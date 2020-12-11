#include "frame.h"
#include <stdio.h>
#include <string.h>
#include "lib/random.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/filesys_wrapper.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/swap.h"
#include "vm/mmap.h"

static void evict_frame_without_swap (struct frame *frame_ptr);
static void evict_frame_to_swap (struct frame *frame_ptr);
static void evict_frame_mmap (struct frame *frame_ptr);
static struct frame *next_evicted_random (void);
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
      /* Find next frame to evict, making sure to remove the page directory
         entry for the previous owner as soon as possible to prevent them from
         accessing/modifying that page. */
      frame_ptr = next_evicted ();
      ASSERT (frame_ptr != NULL)

      lock_acquire (&frame_ptr->frame_lock);
      struct page_entry *entry = get_entry (frame_ptr);
      pagedir_clear_page (entry->owner_thread->pagedir,
                          entry->user_page_addr);

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
         this page. */
      frame_ptr = malloc (sizeof (struct frame));
      frame_ptr->kernel_page_addr = kernel_page_addr;
      lock_init (&frame_ptr->frame_lock);
      list_init (&frame_ptr->page_list);

      list_push_back (&all_frames, &frame_ptr->all_frame_list_elem);
    }

  frame_ptr->pinned = false;
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
  for (e = list_begin (frame_list); e != list_end (frame_list);)
    {
      f = list_entry (e, struct frame, all_frame_list_elem);
      entry = get_entry (f);
      e = list_next (e);
      lock_acquire (&filesys_lock);
      if (!entry->writable &&
          entry->user_page_addr == user_page_addr &&
          same_file (entry->file, file))
        {
          lock_release (&filesys_lock);
          lock_release (&frametable_lock);
          return f;
        }
    }

  lock_release (&filesys_lock);
  lock_release (&frametable_lock);
  return NULL;
}
struct page_entry *get_entry (struct frame *f)
{
  return list_entry (list_front (&f->page_list), struct page_entry, frame_elem);
}

/* ------------------------ EVICTION FUNCTIONS ------------------------ */

static void evict_frame_to_swap (struct frame *frame_ptr)
{
  ASSERT (lock_held_by_current_thread (&frametable_lock))
  ASSERT (lock_held_by_current_thread (&frame_ptr->frame_lock))
  int swap_index = insert_swap (frame_ptr->kernel_page_addr);
  if (swap_index == BITMAP_ERROR)
    {
      lock_release (&frame_ptr->frame_lock);
      lock_release (&frametable_lock);
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
    }

  /* Modify other thread's page entry. */
  struct page_entry *entry = get_entry (frame_ptr);
  ASSERT (entry->swap_index == -1)
  entry->frame_ptr = NULL;
  entry->prev_state = entry->curr_state;
  entry->curr_state = SWAP_SLOT;
  entry->swap_index = swap_index;
  entry->is_dirty = pagedir_is_dirty (entry->owner_thread->pagedir,
                                      entry->user_page_addr);
  list_remove (&entry->frame_elem);
}

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
}

static struct frame *next_evicted (void)
{
  struct list_elem *e;
  struct list_elem *temp;
  struct frame *evicted;
  struct page_entry *entry;
  uint32_t *curr_pagedir;
//  lock_acquire (&frametable_lock);
  e = list_head (&all_frames);

  while ((e = list_next (e)) != list_end (&all_frames))
    {
      evicted = list_entry (e, struct frame, all_frame_list_elem);
      lock_acquire (&evicted->frame_lock);
      entry = list_entry (list_front (&evicted->page_list), struct page_entry, frame_elem);
      curr_pagedir = entry->owner_thread->pagedir;
      if (!pagedir_is_accessed (curr_pagedir, entry->user_page_addr)
          && !evicted->pinned)
        {
          //found eviction candidate, remove from list and return
          list_remove (e);
          list_push_back (&all_frames, e);
          lock_release (&evicted->frame_lock);
//          lock_release (&frametable_lock);
          return evicted;
        }
      else
        {
          //not eviction candidate, change access bit and move to back of list
          pagedir_set_accessed (curr_pagedir, entry->user_page_addr, false);
          temp = e;
          list_remove (temp);
          e = list_head (&all_frames);
          list_push_back (&all_frames, temp);
          lock_release (&evicted->frame_lock);
        }
    }
  NOT_REACHED()
}

static struct frame *next_evicted_random (void)
{
  uint32_t rand = random_ulong () % (list_size (&all_frames) - 1) + 1;

//  lock_acquire (&frametable_lock);
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
//  lock_release (&frametable_lock);
  return rand_frame;
}
