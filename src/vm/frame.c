#include "frame.h"
#include <string.h>
#include "lib/random.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/swap.h"
#include "vm/mmap.h"

static void evict_frame_without_swap (struct frame *frame_ptr);
static void evict_frame_to_swap (struct frame *frame_ptr);
static void evict_frame_mmap (struct frame *frame_ptr);
static struct frame *next_evicted_random (void) UNUSED;
static struct frame *next_evicted (void);

/* Obtaining an unused frame. */
struct frame *
falloc_get_frame (bool zero)
{
  struct frame *frame_ptr;

  /* Initialise the page pointer in the frame, if ZERO is true,
     fill the page with zeros. */
  lock_acquire (&frametable_lock);
  void *kernel_page_addr = zero ? palloc_get_page (PAL_ZERO | PAL_USER) :
                           palloc_get_page (PAL_USER);

  if (kernel_page_addr == NULL)
    {
      /* Find next frame to evict, since we have run out of new user-pages.
         Make sure to remove the page directory entry for the previous owner
         as soon as possible to prevent them from accessing/modifying
         that page. The next_evicted function can be swapped out for other
         valid eviction algorithms, like next_evicted_random ().*/
      frame_ptr = next_evicted ();
      ASSERT (frame_ptr != NULL)

      lock_acquire (&frame_ptr->frame_lock);
      struct page_entry *entry = get_entry (frame_ptr);
      pagedir_clear_page (entry->owner_thread->pagedir,
                          entry->user_page_addr);

      /* We should never be able to evict a swap slot frame, because the
         page should have been removed from the frame as part of the eviction
         process. */
      ASSERT (entry->curr_state != SWAP_SLOT)
      switch (entry->curr_state)
        {
          case MMAP_FILE:
            evict_frame_mmap (frame_ptr);
          break;
          case FILE_SYSTEM:
          case All_ZERO:
          case STACK:
            if (!pagedir_is_dirty (entry->owner_thread->pagedir,
                                   entry->user_page_addr))
              {
                evict_frame_without_swap (frame_ptr);
              }
            else
              {
                evict_frame_to_swap (frame_ptr);
              }
          break;
          default:
            PANIC ("Invalid state of next frame to evict. ");
        }
      lock_release (&frame_ptr->frame_lock);
    }
  else
    {
      /* There is an available user page, so we create a new frame to hold
         this page. We should always be able to malloc this, unless we have
         severe memory leaks in the kernel space. */
      frame_ptr = malloc (sizeof (struct frame));
      ASSERT (frame_ptr != NULL)
      frame_ptr->kernel_page_addr = kernel_page_addr;
      lock_init (&frame_ptr->frame_lock);
      list_push_back (&all_frames, &frame_ptr->all_frame_list_elem);
    }

  /* Regardless whether this is a fresh frame or a reused frame, we always
     want to make it available to be evicted and remove previous owners in
     the page list. */
  frame_ptr->pinned = false;
  list_init (&frame_ptr->page_list);
  lock_release (&frametable_lock);

  return frame_ptr;
}

/* Delete given frame in frame table, free the page in this frame. */
void falloc_free_frame (struct frame *frame_ptr)
{
  ASSERT (list_size (&frame_ptr->page_list) == 1)
  ASSERT (lock_held_by_current_thread (&frame_ptr->frame_lock))
  ASSERT (lock_held_by_current_thread (&frametable_lock))

  list_remove (&frame_ptr->all_frame_list_elem);
  palloc_free_page (frame_ptr->kernel_page_addr);
  free (frame_ptr);
}

/* Change a frame's pinned status as necessary, to prevent eviction. */
void frame_change_pinned (void *user_page_addr, bool pinned)
{
  ASSERT (is_user_vaddr (user_page_addr))

  struct frame *frame_ptr = sup_pagetable_entry_lookup (pg_round_down (user_page_addr))
      ->frame_ptr;
  ASSERT (frame_ptr != NULL)

  lock_acquire (&frame_ptr->frame_lock);
  frame_ptr->pinned = pinned;
  lock_release (&frame_ptr->frame_lock);
}

/* Returns a frame if a corresponding frame with a read-only page is found.
   Rely on the fact that every executable will load its code segment at the same
   user address, so we just need to compare user addresses and files to find
   a read-only page. */
struct frame *read_only_frame_lookup (struct file *file, void *user_page_addr)
{
  struct list *frame_list = &all_frames;
  struct list_elem *e;
  struct frame *f;
  struct page_entry *entry;
  lock_acquire (&frametable_lock);

  for (e = list_begin (frame_list);
       e != list_end (frame_list);
       e = list_next (e))
    {
      /* Once we find a frame, immediately lock it before checking its data.
         Same file is used atomically so there is no need to acquire
         the filesys lock here. */
      f = list_entry (e, struct frame, all_frame_list_elem);
      lock_acquire (&f->frame_lock);
      entry = get_entry (f);
      if (!entry->writable &&
          entry->user_page_addr == user_page_addr &&
          same_file (entry->file, file))
        {
          lock_release (&f->frame_lock);
          lock_release (&frametable_lock);
          return f;
        }
      lock_release (&f->frame_lock);
    }
  lock_release (&frametable_lock);

  return NULL;
}

/* Given a frame pointer, returns the first element on the head of the
   page_list. This is the frame's "owner". */
struct page_entry *get_entry (struct frame *f)
{
  return list_entry (list_front (&f->page_list), struct page_entry, frame_elem);
}

/* ------------------------ EVICTION FUNCTIONS ------------------------ */

/* Handles eviction of a previous page stored in the frame. The frametable
   lock and the specific frame's lock MUST be held before entering this
   function. */
static void evict_frame_to_swap (struct frame *frame_ptr)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock))
  ASSERT (lock_held_by_current_thread (&frame_ptr->frame_lock))

  /* Attempt to write to swap. This function is internally synchronized. */
  int swap_index = insert_swap (frame_ptr->kernel_page_addr);
  if (swap_index == BITMAP_ERROR)
    {
      lock_release (&frame_ptr->frame_lock);
      lock_release (&frametable_lock);
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
    }

  /* Modify the original owner thread's page entry to store the relevant
     information, so that is loaded properly on the next page fault. */
  struct page_entry *entry = get_entry (frame_ptr);
  ASSERT (entry->swap_index == -1)
  entry->prev_state = entry->curr_state;
  entry->curr_state = SWAP_SLOT;
  entry->swap_index = swap_index;
  entry->is_dirty = pagedir_is_dirty (entry->owner_thread->pagedir,
                                      entry->user_page_addr);
  entry->frame_ptr = NULL;
  list_remove (&entry->frame_elem);
}

/* Used to evict a frame, without writing to swap. */
static void
evict_frame_without_swap (struct frame *frame_ptr)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock))
  ASSERT (lock_held_by_current_thread (&frame_ptr->frame_lock))

  struct page_entry *entry = get_entry (frame_ptr);
  ASSERT (entry->curr_state != STACK)
  ASSERT (entry->curr_state != MMAP_FILE)
  ASSERT (!pagedir_is_dirty (entry->owner_thread->pagedir,
                             entry->user_page_addr));
  entry->frame_ptr = NULL;
  list_remove (&entry->frame_elem);
}

/* Eviction for mmap that writes back to original mmap-ed file. Separate from
   the other functions because we need to keep the information about mmap
   relevant. */
static void evict_frame_mmap (struct frame *frame_ptr)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock))
  ASSERT (lock_held_by_current_thread (&frame_ptr->frame_lock))

  struct page_entry *entry = get_entry (frame_ptr);
  ASSERT (entry->curr_state == MMAP_FILE)
  if (pagedir_is_dirty (entry->owner_thread->pagedir, entry->user_page_addr))
    {
      write_page_back_to_file (entry->mmap_fd, entry->ofs,
                               entry->user_page_addr, entry->read_bytes);
    }
  /* If the page is not dirty, there is no need to write to file, and we
     can fault the page back in from the mmap file later on. */
}

/* Least recently used algorithm to find the next frame to evict. */
static struct frame *next_evicted (void)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock));
  struct list_elem *e;
  struct list_elem *temp;
  struct frame *frame_ptr;
  struct page_entry *entry;
  uint32_t *curr_pagedir;
  e = list_head (&all_frames);

  while ((e = list_next (e)) != list_end (&all_frames))
    {
      frame_ptr = list_entry (e, struct frame, all_frame_list_elem);
      lock_acquire (&frame_ptr->frame_lock);
      entry = get_entry (frame_ptr);
      curr_pagedir = entry->owner_thread->pagedir;
      if (!pagedir_is_accessed (curr_pagedir, entry->user_page_addr)
          && !frame_ptr->pinned)
        {
          /* Found eviction candidate, remove from list and return */
          list_remove (e);
          list_push_back (&all_frames, e);
          lock_release (&frame_ptr->frame_lock);
          return frame_ptr;
        }
      else
        {
          /* Not eviction candidate, change access bit and move to back of list */
          pagedir_set_accessed (curr_pagedir, entry->user_page_addr, false);
          temp = e;
          list_remove (temp);
          e = list_head (&all_frames);
          list_push_back (&all_frames, temp);
          lock_release (&frame_ptr->frame_lock);
        }
    }
  NOT_REACHED()
}

/* Eviction algorithm that choose a random frame from the all_frames list. */
static struct frame *next_evicted_random (void)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock));
  uint32_t rand = random_ulong () % (list_size (&all_frames) - 1) + 1;

  struct list_elem *e;
  struct frame *rand_frame;
  uint32_t i = 0;

  for (e = list_begin (&all_frames);
       e != list_end (&all_frames) && i < rand;
       e = list_next (e))
    {
      rand_frame = list_entry (e, struct frame, all_frame_list_elem);
      i++;
    }

  return rand_frame;
}
