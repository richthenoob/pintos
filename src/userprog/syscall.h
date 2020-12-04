#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <lib/kernel/hash.h>
#include <debug.h>

#define DEFAULT_ERR_EXIT_CODE (-1)
#define MAX_STACK_SPACE_IN_BYTES (2000 * PGSIZE) /* 8MB of space*/
#define MAX_OFFSET_FROM_STACK_PTR_IN_BYTES (32) /* Page faults can occur up to
                                                   32 bytes from esp because of
                                                   how PUSHA works. */
void syscall_init (void);

struct file_node {
  struct hash_elem hash_elem;
  int fd;
  int mmap_count;
  struct file *file;
};

int add_to_hash_table_of_file_nodes (struct file *opened_file);
void free_file_node (struct hash_elem *element, void *aux);
bool is_writable_segment (const uint8_t *fault_addr);

#endif /* userprog/syscall.h */
