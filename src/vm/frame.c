#include "frame.h"

#include "threads/palloc.h"
#include "threads/malloc.h"

struct frame *frame_lookup (void *page_ptr) {
  struct frame f;
  struct hash_elem *e;
  f.page_ptr = page_ptr;
  lock_acquire (&frametable_lock);
  e = hash_find (&frametable, &f.hash_elem);
  lock_release (&frametable_lock);
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

struct frame *falloc_get_frame (bool zero)
{
  struct frame *frame_ptr = malloc (sizeof (struct frame));

  frame_ptr->page_ptr = zero ? palloc_get_page (PAL_ZERO | PAL_USER) :
              palloc_get_page (PAL_USER);

  if (frame_ptr->page_ptr == NULL)
    {
      free (frame_ptr);
      PANIC ("No more frames available.");
    }

  lock_acquire (&frametable_lock);
  hash_insert (&frametable, &frame_ptr->hash_elem);
  lock_release (&frametable_lock);

  return frame_ptr;
}
void falloc_free_frame (struct frame *frame_ptr)
{
  lock_acquire (&frametable_lock);
  hash_delete (&frametable, &frame_ptr->hash_elem);
  lock_release (&frametable_lock);

  palloc_free_page (frame_ptr->page_ptr);
  free (frame_ptr);
}