#include "swap.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static const int SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;
static struct lock swap_lock;
static struct bitmap *swap_bit_map;
struct block *block_device;

/* Initialize data structures required for swapping. */
void swap_init ()
{
  block_device = block_get_role (BLOCK_SWAP);
  uint32_t max_swap_slots = block_size (block_device) / SECTORS_PER_PAGE;
  swap_bit_map = bitmap_create (max_swap_slots);

  if (!swap_bit_map)
    {
      PANIC("No more memory");
    }

  if (block_device == NULL)
    {
      PANIC("No block device assigned");
    }

  lock_init (&swap_lock);
}

/* Takes a frame and copies the data into a swap_entry,
   then writes to swap space. Note that this function does NOT handle removing
   a page entry from the process's pagedir, so be sure to do that. */
int insert_swap (void *kernel_pg_addr)
{
  ASSERT (is_kernel_vaddr (kernel_pg_addr))

  /* Find next available sector. */
  lock_acquire (&swap_lock);
  int index = bitmap_scan_and_flip (swap_bit_map, 0, 1, false);
  if (index == BITMAP_ERROR)
    {
      return BITMAP_ERROR;
    }
  lock_release (&swap_lock);

  /* Actually write to swap space. Block write is internally synchronized,
     so no synchronization methods needed here. */
  for (int sector_count = 0; sector_count < SECTORS_PER_PAGE; ++sector_count)
    {
      block_write (block_device,
                   sector_count + index * SECTORS_PER_PAGE,
                   kernel_pg_addr + sector_count * BLOCK_SECTOR_SIZE);
    }
  return index;
}

/* Writes to a given frame the entry we stored earlier, and restores the
   frame data as well. This function only modifies the frame and the
   kernel address it points to, so remember to update information about the
   frame somewhere else (e.g. adding to a thread's frame list, installing
   the page.) */
bool read_swap (int index, void *kernel_pg_addr)
{
  ASSERT (is_kernel_vaddr (kernel_pg_addr))
  /* Ensure that other processes don't try to access a wrong frame. */

  /* Retrieve back the frame table information. */
  lock_acquire (&swap_lock);
  if (bitmap_test (swap_bit_map, index) == 0)
    {
      return false;
    }
  lock_release (&swap_lock);

  /* Write data from swap to provided frame. */
  for (int sector_count = 0; sector_count < SECTORS_PER_PAGE; ++sector_count)
    {
      block_read (block_device,
                  sector_count + index * SECTORS_PER_PAGE,
                  kernel_pg_addr + sector_count * BLOCK_SECTOR_SIZE);
    }

  /* Clear entry in swap table. */
  lock_acquire (&swap_lock);
  bitmap_set_multiple (swap_bit_map, index, 1, false);
  lock_release (&swap_lock);

  return true;
}