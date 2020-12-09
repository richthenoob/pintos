#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <lib/user/syscall.h>
#include <lib/kernel/hash.h>
#include <lib/kernel/bitmap.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/frame.h"

struct swap_slot {
    struct hash_elem hash_elem;
    int index;
    tid_t tid;
    void *user_page_addr;
    enum page_state prev_state;
    struct file *file;
    bool writable;
};

void swap_init (void);
bool insert_swap_table (const struct frame *frame_ptr);
bool read_swap_table (pid_t pid, void *user_pg_addr, struct frame *dest_frame);

struct hash swap_table;
struct lock swap_table_lock;
struct bitmap *swap_bit_map;

#endif /* vm/swap.h */