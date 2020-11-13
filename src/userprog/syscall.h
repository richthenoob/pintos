#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <lib/kernel/hash.h>
#include <debug.h>

void syscall_init (void);

struct file_node {
  struct hash_elem hash_elem;
  int fd;
  struct file *file;
};

unsigned
file_node_hash(const struct hash_elem *p_, void *aux UNUSED);
bool
file_node_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

#endif /* userprog/syscall.h */
