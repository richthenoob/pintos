#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdint.h>
#include <stdbool.h>
#include <hash.h>
#include <debug.h>
#include <filesys/off_t.h>

enum page_state {
  All_ZERO,
  FILE_SYSTEM,
  SWAP_SLOT,
  MMAP_FILE
};

/* Supplementary page table entry. */
struct sup_pagetable_entry {
  struct hash_elem spt_elem;
  struct list_elem mmap_elem;

  void *upage;
  enum page_state state;
  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;
};

/* Adding to supplemental pagetable. */
struct sup_pagetable_entry *
sup_pagetable_add_all_zero (void *upage, bool writable);
struct sup_pagetable_entry *
sup_pagetable_add_file (enum page_state state, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Functions to properly load the pages after a page fault occurs. */
bool
sup_pagetable_load_all_zero (struct sup_pagetable_entry *entry);

bool
sup_pagetable_load_file (struct sup_pagetable_entry *entry);

/* Helper functions. */
struct sup_pagetable_entry*
sup_pagetable_entry_lookup(void * page);
unsigned
sup_page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
sup_page_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
              void *aux UNUSED);
void free_sup_page_entry (struct hash_elem *element, void *aux UNUSED);

#endif /* vm/page.h */
