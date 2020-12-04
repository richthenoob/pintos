#include "mmap.h"
#include "userprog/syscall.h"
#include "threads/thread.h"

/* Helper functions. */
unsigned
mmap_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct mmap_node *p = hash_entry(p_, struct mmap_node, hash_elem);
  return hash_bytes (&p->mapid, sizeof p->mapid);
}

bool
mmap_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
          void *aux UNUSED)
{
  const struct mmap_node *a = hash_entry (a_, struct mmap_node, hash_elem);
  const struct mmap_node *b = hash_entry (b_, struct mmap_node, hash_elem);
  return a->mapid < b->mapid;
}

/* Find a memory mapped node of the current thread's mmap_hash_table given a
   mmap id. No synchronization needed since a thread only
   accesses its own hash table. */
struct mmap_node *
mmap_node_lookup (mapid_t id)
{
  struct mmap_node node;
  struct hash_elem *e;
  node.mapid = id;
  e = hash_find (&thread_current ()->mmap_hash_table, &node.hash_elem);
  return e != NULL ? hash_entry (e, struct mmap_node, hash_elem) : NULL;
}

/* Returns next memory map id value for a specific thread. No synchronization
   needed since a thread only accesses its own hash table. */
mapid_t
next_mapid_value (void)
{
  return hash_size (&thread_current ()->mmap_hash_table);
}