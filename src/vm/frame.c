#include "frame.h"
#include <stdio.h>
#include <string.h>
#include "lib/random.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/filesys_wrapper.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"

static bool
evict_frame_without_swap (struct frame *frame_ptr, enum page_state old_state);
static bool evict_frame_to_swap (struct frame *frame_ptr, bool new_writable);
static struct frame *next_evicted_random (void);
static struct frame *next_evicted (void);

struct frame *frame_lookup (void *page_ptr)
{
  struct frame f;
  struct hash_elem *e;
  f.kernel_page_addr = page_ptr;
  lock_acquire (&frametable_lock);
  e = hash_find (&frametable, &f.hash_elem);
  lock_release (&frametable_lock);
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

/* Obtaining an unused frame. */
struct frame *
falloc_get_frame (bool zero, enum page_state state,
                  void *user_page_addr, struct file *exec_file,
                  bool writable, off_t ofs, uint32_t read_bytes)
{
  ASSERT (is_user_vaddr (user_page_addr));
  struct frame *frame_ptr = malloc (sizeof (struct frame));
  ASSERT (frame_ptr != NULL)

  /* Initialise the page pointer in the frame, if ZERO is true, fill the page with zeros. */
  frame_ptr->kernel_page_addr = zero ? palloc_get_page (PAL_ZERO | PAL_USER) :
                                palloc_get_page (PAL_USER);

  if (frame_ptr->kernel_page_addr == NULL)
    {
      free (frame_ptr);
      do
        {
          frame_ptr = next_evicted ();
        }
      while (frame_ptr->pinned);

      ASSERT (frame_ptr != NULL)
      lock_acquire (&frame_ptr->frame_lock);
//      printf ("evicted state: %d, evicted: %p, new: %p\n", frame_ptr->state, frame_ptr->user_page_addr, user_page_addr);

      switch (frame_ptr->state)
        {
          case FILE_SYSTEM:
            if (frame_ptr->writable == false)
              {
                evict_frame_without_swap (frame_ptr, frame_ptr->state);
                break;
              }
          case All_ZERO:
          case STACK:
                evict_frame_to_swap (frame_ptr, writable);
          break;
          case SWAP_SLOT:
            PANIC ("should not have swap slot page as next frame");
          case MMAP_FILE:
            // write to file system
            // remove from user frame table
            // add to sup page table
            PANIC ("mmap file");
        }
      lock_release (&frame_ptr->frame_lock);
    }
  else
    {
      lock_init (&frame_ptr->frame_lock);

      lock_acquire (&frametable_lock);
      hash_insert (&frametable, &frame_ptr->hash_elem);
      lock_release (&frametable_lock);

      lock_acquire (&all_frames_lock);
      list_push_back (&all_frames, &frame_ptr->all_frame_list_elem);
      lock_release (&all_frames_lock);
    }

  frame_ptr->owner = thread_current ();
  frame_ptr->state = state;
  frame_ptr->user_page_addr = user_page_addr;
  frame_ptr->file = exec_file;
  frame_ptr->writable = writable;
  frame_ptr->counter = 0;
  frame_ptr->ofs = ofs;
  frame_ptr->read_bytes = read_bytes;
  frame_ptr->pinned = false;
  list_init(&frame_ptr->threads_users);

  list_push_back (&thread_current ()->frame_list, &frame_ptr->thread_frame_list_elem);

  return frame_ptr;
}

/* Delete given frame in frame table, free the page in this frame. */
void falloc_free_frame (struct frame *frame_ptr)
{
  ASSERT (frame_ptr->counter == 0);

  lock_acquire (&frametable_lock);
  hash_delete (&frametable, &frame_ptr->hash_elem);
  lock_release (&frametable_lock);
  lock_acquire (&all_frames_lock);
  list_remove (&frame_ptr->all_frame_list_elem);
  lock_release (&all_frames_lock);
  free (frame_ptr);
}

/* Returns a frame if a corresponding frame with a read-only page is found.
   Rely on the fact that every executable will load its code segment at the same
   user address, so we just need to compare user addresses and files to find
   a read-only page.
   TODO: fix potential deadlock situation, improve efficiency. */
struct frame *read_only_frame_lookup (struct file *file, void *user_page_addr)
{
  lock_acquire (&frametable_lock);
  struct hash_iterator i;
  hash_first (&i, &frametable);
  while (hash_next (&i))
    {
      struct frame *frame = hash_entry (hash_cur (&i), struct frame, hash_elem);

      lock_acquire (&filesys_lock);
      if (frame->file != NULL &&
          !frame->writable &&
          frame->user_page_addr == user_page_addr &&
          same_file (frame->file, file))
        {
          lock_release (&frametable_lock);
          lock_release (&filesys_lock);
          return frame;
        }
      lock_release (&filesys_lock);
    }
  lock_release (&frametable_lock);
  return NULL;
}

/* EVICTION FUNCTIONS. */

static bool evict_frame_to_swap (struct frame *frame_ptr, bool new_writable)
{
  pagedir_clear_page (frame_ptr->owner->pagedir,
                      frame_ptr->user_page_addr);
  if (!insert_swap_table (frame_ptr))
    {
      process_exit_with_code (-1);
    }
  list_remove (&frame_ptr->thread_frame_list_elem);
  sup_pagetable_add_swap (frame_ptr->user_page_addr, new_writable);
}

static bool
evict_frame_without_swap (struct frame *frame_ptr, enum page_state old_state)
{
  ASSERT (!pagedir_is_dirty (frame_ptr->owner->pagedir, frame_ptr->user_page_addr))

  pagedir_clear_page (frame_ptr->owner->pagedir,
                      frame_ptr->user_page_addr);
  list_remove (&frame_ptr->thread_frame_list_elem);

  switch (old_state)
    {
      case FILE_SYSTEM:
        sup_pagetable_add_file (thread_current (), FILE_SYSTEM, frame_ptr->user_page_addr, frame_ptr->file,
                                frame_ptr->ofs, frame_ptr->read_bytes,
                                PGSIZE - frame_ptr->read_bytes,
                                frame_ptr->writable);
      break;
      case All_ZERO:
      case STACK:
        if (frame_ptr->writable == false && old_state == All_ZERO)
          {
            printf ("something's up!\n");
          }
      sup_pagetable_add_all_zero (frame_ptr->user_page_addr, frame_ptr->writable, frame_ptr->file);
      break;
    }


//  struct list_elem *e;
//  struct thread *t;
//  struct list threads_using_frame_list = frame_ptr->threads_using_frame_list;
//  list_remove (&frame_ptr->thread_frame_list_elem);
//
//  for (e = list_begin (&threads_using_frame_list);
//       e != list_end (&threads_using_frame_list);
//       e = list_next (e))
//    {
//      t = list_entry (e, struct thread, frame_elem);
//      pagedir_clear_page (t->pagedir, frame_ptr->user_page_addr);
//      sup_pagetable_add_file (t, FILE_SYSTEM,
//                              frame_ptr->user_page_addr, frame_ptr->file,
//                              frame_ptr->ofs, frame_ptr->read_bytes,
//                              PGSIZE - frame_ptr->read_bytes,
//                              frame_ptr->writable);
//    }
//  return true;
}

static struct frame *next_evicted (void)
{
  struct list_elem *e;
  struct list_elem *temp;
  struct frame *evicted;
  uint32_t *curr_pagedir;
  lock_acquire (&all_frames_lock);
  e = list_head (&all_frames);

  while ((e = list_next (e)) != list_end (&all_frames))
    {
      evicted = list_entry (e, struct frame, all_frame_list_elem);
      curr_pagedir = evicted->owner->pagedir;
      if (!pagedir_is_accessed (curr_pagedir, evicted->user_page_addr))
        {
          //found eviction candidate, remove from list and return
          list_remove (e);
          list_push_back (&all_frames, e);
          lock_release (&all_frames_lock);
          return evicted;
        }
      else
        {
          //not eviction candidate, change access bit and move to back of list
          pagedir_set_accessed (curr_pagedir, evicted->user_page_addr, false);
          temp = e;
          list_remove (temp);
          e = list_head (&all_frames);
          list_push_back (&all_frames, temp);
        }
    }
  NOT_REACHED()
}

static struct frame *next_evicted_random (void)
{
  uint32_t rand = random_ulong () % (list_size (&all_frames) - 1) + 1;

  lock_acquire (&all_frames_lock);
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
  lock_release (&all_frames_lock);
  return rand_frame;
}
