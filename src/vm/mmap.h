#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <lib/user/syscall.h>
#include <lib/kernel/hash.h>

struct mmap_node {
  struct hash_elem hash_elem;
  mapid_t mapid;                    /* map id. */
  int fd;                           /* Record the fd of the file that's mapped. */
  struct list list_pages_open;      /* List of page tables to record the pages opened. */
};

mapid_t
next_mapid_value (void);

struct
mmap_node *mmap_node_lookup (mapid_t id);

/* Helper functions. */
unsigned
mmap_hash (const struct hash_elem *p_, void *aux UNUSED);

bool
mmap_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
          void *aux UNUSED);

#endif /* vm/mmap.h */
