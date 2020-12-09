#include "swap.h"
#include <stdio.h>
#include "devices/timer.h"
#include "threads/malloc.h"

static const int SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;
struct block *block_device;

static unsigned swap_hash (const struct hash_elem *f_, void *aux UNUSED);
static bool swap_less (const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED);
static struct swap_slot *swap_lookup (void *user_pg_addr, tid_t tid);

/* Initialize data structures required for swapping. */
void swap_init ()
{
  block_device = block_get_role (BLOCK_SWAP);
  int max_swap_slots = block_size (block_device) / SECTORS_PER_PAGE;
  swap_bit_map = bitmap_create (max_swap_slots);
  if (!swap_bit_map)
    {
      PANIC("No more memory");
    }
  if (block_device == NULL)
    {
      PANIC("No block device assigned");
    }
  hash_init (&swap_table, swap_hash, swap_less, NULL);
  lock_init (&swap_table_lock);
}

/* Takes a frame and copies the data into a swap_entry,
   then writes to swap space. Note that this function does NOT handle removing
   a page entry from the process's pagedir, so be sure to do that. */
bool
insert_swap_table (const struct frame *frame_ptr)
{
  ASSERT (is_user_vaddr(frame_ptr->user_page_addr));
  struct swap_slot *swap_entry = malloc (sizeof (struct swap_slot));

  // TODO: consider frame synchronization
  /* Set up swap_entry so we can recover from it later. */
  swap_entry->user_page_addr = frame_ptr->user_page_addr;
  swap_entry->tid = frame_ptr->owner->tid;
  swap_entry->prev_state = frame_ptr->state;
  swap_entry->file = frame_ptr->file;
  swap_entry->writable = frame_ptr->writable;

  /* Find next available sector. */
  lock_acquire (&swap_table_lock);
  swap_entry->index = bitmap_scan_and_flip (swap_bit_map, 0, 1, false);
  if (swap_entry->index == BITMAP_ERROR)
    {
      return false;
    }
  hash_insert (&swap_table, &swap_entry->hash_elem);
  lock_release (&swap_table_lock);

  /* Actually write to swap space. Block write is internally synchronized,
     so no synchronization methods needed here. */
  for (int sector_count = 0; sector_count < SECTORS_PER_PAGE; ++sector_count)
    {
      block_write (block_device,
                   sector_count + swap_entry->index * SECTORS_PER_PAGE,
                   frame_ptr->kernel_page_addr + sector_count * BLOCK_SECTOR_SIZE);
    }
  return true;
}

/* Writes to a given frame the entry we stored earlier, and restores the
   frame data as well. This function only modifies the frame and the
   kernel address it points to, so remember to update information about the
   frame somewhere else (e.g. adding to a thread's frame list, installing
   the page.) */
bool read_swap_table (tid_t tid, void *user_pg_addr, struct frame *dest_frame)
{
  /* Ensure that other processes don't try to access a wrong frame. */
  ASSERT (dest_frame->owner == thread_current ());

  /* Retrieve back the frame table information. */
  struct swap_slot *swap_entry = swap_lookup (user_pg_addr, tid);
  if (swap_entry == NULL)
    {
      return false;
    }

  ASSERT (is_user_vaddr(dest_frame->user_page_addr));
  /* Restore frame attributes. */
  dest_frame->state = swap_entry->prev_state;
  dest_frame->user_page_addr = swap_entry->user_page_addr;
  dest_frame->file = swap_entry->file;
  dest_frame->counter = 0;
  dest_frame->pinned = false;
  dest_frame->writable = dest_frame->writable;
  ASSERT (is_user_vaddr(swap_entry->user_page_addr));

  /* Write data from swap to provided frame. */
  for (int sector_count = 0; sector_count < SECTORS_PER_PAGE; ++sector_count)
    {
      block_read (block_device,
                  sector_count + swap_entry->index * SECTORS_PER_PAGE,
                  dest_frame->kernel_page_addr + sector_count * BLOCK_SECTOR_SIZE);
    }

  /* Clear entry in swap table. */
  lock_acquire (&swap_table_lock);
  hash_delete (&swap_table, &swap_entry->hash_elem);
  bitmap_set_multiple (swap_bit_map, swap_entry->index, 1, false);
  lock_release (&swap_table_lock);

  free (swap_entry);

  return true;
}

static unsigned swap_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  struct swap_slot *s = hash_entry (f_, struct swap_slot, hash_elem);
  return hash_bytes (&s->tid, sizeof (s->user_page_addr) + sizeof (s->tid));
}

static struct swap_slot *swap_lookup (void *user_pg_addr, tid_t tid)
{
  struct swap_slot swap_slot;
  struct hash_elem *e;
  swap_slot.tid = tid;
  swap_slot.user_page_addr = user_pg_addr;
  lock_acquire (&swap_table_lock);
  e = hash_find (&swap_table, &swap_slot.hash_elem);
  lock_release (&swap_table_lock);
  return e != NULL ? hash_entry (e, struct swap_slot, hash_elem) : NULL;
}

static bool
swap_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  struct swap_slot *a = hash_entry (a_, struct swap_slot, hash_elem);
  struct swap_slot *b = hash_entry (b_, struct swap_slot, hash_elem);
  if (a->user_page_addr == b->user_page_addr)
    {
      return a->tid < b->tid;
    }
  else
    {
      return a->user_page_addr < b->user_page_addr;
    }
}







