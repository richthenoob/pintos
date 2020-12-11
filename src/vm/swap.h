#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>

void swap_init (void);
int insert_swap (void *kernel_pg_addr);
bool read_swap (int index, void *kernel_pg_addr);

#endif /* vm/swap.h */