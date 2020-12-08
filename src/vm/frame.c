#include <filesys/file.h>
#include "frame.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Find a frame in the frame table, given a page pointer. */
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
falloc_get_frame (bool zero, enum page_state state, void *user_page_addr,
                  struct file *exec_file, bool writable)
{
  struct frame *frame_ptr = malloc (sizeof (struct frame));

  /* Initialise the page pointer in the frame, if ZERO is true, fill the page with zeros. */
  frame_ptr->kernel_page_addr = zero ? palloc_get_page (PAL_ZERO | PAL_USER) :
                                palloc_get_page (PAL_USER);

  if (frame_ptr->kernel_page_addr == NULL)
    {
      free (frame_ptr);
      PANIC ("No more frames available.");
    }

  lock_init (&frame_ptr->frame_lock);
  frame_ptr->state = state;
  frame_ptr->user_page_addr = user_page_addr;
  frame_ptr->file = exec_file;
  frame_ptr->writable = writable;
  frame_ptr->counter = 0;

  lock_acquire (&frametable_lock);
  hash_insert (&frametable, &frame_ptr->hash_elem);
  lock_release (&frametable_lock);

  list_push_front(&thread_current()->frame_list,&frame_ptr->list_elem);

  return frame_ptr;
}

/* Delete given frame in frame table, free the page in this frame. */
void falloc_free_frame (struct frame *frame_ptr)
{
  lock_acquire (&frametable_lock);
  hash_delete (&frametable, &frame_ptr->hash_elem);
  lock_release (&frametable_lock);

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