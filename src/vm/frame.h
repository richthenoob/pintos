#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <lib/kernel/hash.h>
#include <threads/synch.h>

struct frame {
  struct hash_elem hash_elem;
  void *page_ptr;
};

struct hash frametable;               /* Hashtable to store frames. */
struct lock frametable_lock;          /* Lock used for the frame. */

struct frame *falloc_get_frame (bool zero);
void falloc_free_frame (struct frame *frame_ptr);
struct frame *frame_lookup (void *page_ptr);

#endif /* vm/frame.h */
