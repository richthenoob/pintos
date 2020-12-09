#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <lib/kernel/hash.h>
#include <threads/synch.h>
#include <lib/kernel/bitmap.h>
#include <lib/kernel/list.h>
#include "vm/page.h"

struct frame {
  struct lock frame_lock;
  struct hash_elem hash_elem;
  struct list_elem thread_frame_list_elem;
  struct list_elem all_frame_list_elem;

  struct thread *owner;
  bool pinned;
  enum page_state state;
  void *kernel_page_addr;
  void *user_page_addr;
  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
  int counter;
  struct list threads_users;
  bool writable;
};

struct hash frametable;               /* Hashtable to store frames. */
struct lock frametable_lock;          /* Lock used for the frame. */

struct frame *
falloc_get_frame (bool zero, enum page_state state, void *user_page_addr, struct file *exec_file, bool writable, off_t ofs, uint32_t read_bytes);
void falloc_free_frame (struct frame *frame_ptr);
struct frame *frame_lookup (void *page_ptr);
struct frame *read_only_frame_lookup (struct file *file, void *user_page_addr);

struct list all_frames;
struct lock all_frames_lock;
#endif /* vm/frame.h */
