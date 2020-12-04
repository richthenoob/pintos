#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <lib/user/syscall.h>
#include <lib/kernel/hash.h>

struct mmap_node {
    mapid_t mapid;
    int fd;
    struct hash_elem hash_elem;
    struct list list_pages_open;
};

unsigned
mmap_hash (const struct hash_elem *p_, void *aux UNUSED);

bool
mmap_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
          void *aux UNUSED);

mapid_t
next_mapid_value (void);
struct
    mmap_node *mmap_node_lookup (mapid_t id);

#endif /* vm/mmap.h */
