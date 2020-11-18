#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <lib/kernel/hash.h>
#include <debug.h>

#define DEFAULT_ERR_EXIT_CODE -1
void syscall_init (void);

struct file_node {
  struct hash_elem hash_elem;
  int fd;
  struct file *file;
};

int add_to_hash_table_of_file_nodes (struct file *opened_file);
void free_file_node (struct hash_elem *element, void *aux);

#endif /* userprog/syscall.h */
