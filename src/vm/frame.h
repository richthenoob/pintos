#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <lib/kernel/hash.h>
#include <lib/kernel/bitmap.h>
#include <lib/kernel/list.h>
#include "threads/synch.h"
#include "vm/page.h"

struct frame {
  struct lock frame_lock;                /* Lock for individual frame. */
  struct list_elem all_frame_list_elem;  /* List elem to add to all_frames */

  bool pinned;                           /* Pin frame to prevent eviction. */
  void *kernel_page_addr;                /* Pointer to palloc-ed user page. */
  struct list page_list;                 /* List of page_entries currently
                                             using this frame, for sharing. */
};

struct lock frametable_lock;             /* Global lock on list of all_frames. */
struct list all_frames;                  /* List to hold every frame. */

struct frame *falloc_get_frame (bool zero);
void falloc_free_frame (struct frame *frame_ptr);
struct frame *read_only_frame_lookup (struct file *file, void *user_page_addr);
void frame_change_pinned (void *user_page_ptr, bool pinned);
struct page_entry *get_entry (struct frame *f);

#endif /* vm/frame.h */
