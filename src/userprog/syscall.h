#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include "lib/kernel/hash.h"

#define DEFAULT_ERR_EXIT_CODE (-1)
#define MAX_STACK_SPACE_IN_BYTES (2000 * PGSIZE) /* 8MB of space*/
#define MAX_OFFSET_FROM_STACK_PTR_IN_BYTES (32) /* Page faults can occur up to
                                                   32 bytes from esp because of
                                                   how PUSHA works. */
void syscall_init (void);
bool is_writable_segment (const uint8_t *fault_addr);

/* Syscall functions that are needed by other kernel code. */
int syscall_write (int fd, const void *buffer, unsigned length);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);

#endif /* userprog/syscall.h */
