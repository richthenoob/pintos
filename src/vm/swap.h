#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>

#define SWAP_ERROR (-1)

/* Initialization function. Called in init.c. */
void swap_init (void);

/* insert and read functions. */
int insert_swap (void *kernel_pg_addr);
bool read_swap (int index, void *kernel_pg_addr);

#endif /* vm/swap.h */