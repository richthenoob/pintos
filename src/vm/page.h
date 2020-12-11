#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdint.h>
#include <stdbool.h>
#include <hash.h>
#include <debug.h>
#include "filesys/off_t.h"
#include "threads/thread.h"
#include "vm/mmap.h"

/* Keeps track of a page's state. */
enum page_state {
  All_ZERO,
  FILE_SYSTEM,
  SWAP_SLOT,
  MMAP_FILE,
  STACK,
  ERROR_STATE
};

/* Supplemental page table entry. */
struct page_entry {
  struct hash_elem spt_elem;
  struct list_elem frame_elem;
  struct list_elem mmap_elem; // maybe don't need?

  void *user_page_addr;
  struct frame *frame_ptr;
  struct thread *owner_thread;
  enum page_state curr_state;
  enum page_state prev_state;

  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;
  int swap_index;
  bool is_dirty;
  int mmap_fd;
};

/* Adding to supplemental page table. */
struct page_entry *
add_to_sup_pagetable (void *user_page_addr, enum page_state state,
                      struct file *file, off_t ofs,
                      uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Functions to properly load the pages after a page fault occurs. */
bool sup_pagetable_load_entry (struct page_entry *entry);
bool grow_stack (void *user_addr_rounded);

/* Helper functions. */
struct page_entry *sup_pagetable_entry_lookup (void *user_page_addr);
unsigned sup_page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool sup_page_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
                   void *aux UNUSED);
void free_sup_page_entry (struct hash_elem *element, void *aux UNUSED);

#endif /* vm/page.h */
