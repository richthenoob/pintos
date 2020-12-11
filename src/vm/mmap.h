#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "filesys/off_t.h"
#include "lib/user/syscall.h"
#include "lib/kernel/hash.h"

#define MMAP_ERROR (-1)

struct mmap_node {
  struct hash_elem hash_elem;       /* Hash element for storing in a thread's mmap_hash_table */
  mapid_t mapid;                    /* Unique map id. */
  int fd;                           /* Record the fd of the file that's mapped. */
  struct list list_pages_open;      /* List of page tables to record the pages opened. */
};

mapid_t memory_map (int fd, void *user_page_addr);
bool memory_unmap (mapid_t mapping);
struct mmap_node *mmap_node_lookup (mapid_t id);
bool write_page_back_to_file (int fd, off_t ofs,
                              void *user_page_addr, uint32_t write_bytes);

/* Helper functions. */
mapid_t next_mapid_value (void);
unsigned mmap_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
mmap_cmp (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

#endif /* vm/mmap.h */
