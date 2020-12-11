#ifndef FILESYS_WRAPPER_H
#define FILESYS_WRAPPER_H

#include <debug.h>
#include "lib/kernel/hash.h"
#include "userprog/filesys_wrapper.h"

struct file_node {
  struct hash_elem hash_elem;       /* hash_elem to store in a thread's hash_table_of_file_nodes. */
  int fd;                           /* File descriptor. */
  int mmap_count;                   /* Record the number of mapping. */
  struct file *file;                /* File pointer to internal struct file.*/
};

struct lock filesys_lock;           /* Lock used over the entire filesystem. */

unsigned file_node_hash (const struct hash_elem *p_, void *aux UNUSED);
bool file_node_less (const struct hash_elem *a_,
                const struct hash_elem *b_,
                void *aux UNUSED);

struct file_node *file_node_lookup (int fd);
void free_file_node (struct hash_elem *element, void *aux UNUSED);
int add_to_hash_table_of_file_nodes (struct file *opened_file);

#endif /* vm/filesys_wrapper.h */