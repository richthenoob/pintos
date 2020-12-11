#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <lib/kernel/hash.h>
#include <threads/synch.h>
#include <lib/kernel/bitmap.h>
#include <lib/kernel/list.h>
#include "vm/page.h"

struct frame {
  struct lock frame_lock;
  struct list_elem all_frame_list_elem;

  bool pinned;
  void *kernel_page_addr;
  struct list page_list;
};

struct lock frametable_lock;
struct list all_frames;

struct frame *falloc_get_frame(bool zero);
void falloc_free_frame(struct frame *frame_ptr);
struct frame *read_only_frame_lookup(struct file *file, void *user_page_addr);
void frame_change_pinned(void *user_page_ptr, bool pinned);
struct page_entry *get_entry(struct frame *f);

#endif /* vm/frame.h */
