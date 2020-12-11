#include "page.h"
#include <string.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/filesys_wrapper.h"
#include "vm/frame.h"
#include "vm/swap.h"

static bool sup_pagetable_load_from_swap (struct page_entry *entry);

/* Add an entry to the supplemental page table with information of a file. */
struct page_entry *
add_to_sup_pagetable (void *user_page_addr, enum page_state state,
                      struct file *file, off_t ofs,
                      uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  /* Record file information in a page. */
  struct page_entry *entry = malloc (sizeof (struct page_entry));
  entry->user_page_addr = user_page_addr;
  entry->frame_ptr = NULL;
  entry->owner_thread = thread_current ();
  entry->curr_state = state;
  entry->file = file;
  entry->ofs = ofs;
  entry->read_bytes = read_bytes;
  entry->zero_bytes = zero_bytes;
  entry->writable = writable;
  entry->prev_state = ERROR_STATE;
  entry->swap_index = SWAP_ERROR;
  entry->is_dirty = false;
  entry->mmap_fd = MMAP_ERROR;
  lock_init (&entry->page_lock);

  /* Add the page to the supplemental page table. */
  hash_insert (&thread_current ()->sup_pagetable, &entry->spt_elem);

  return entry;
}

/* Loading of a page_entry. This function is called whenever a page fault
   is detected and a supplemental page table entry is found. */
bool
sup_pagetable_load_entry (struct page_entry *entry)
{
  ASSERT (is_user_vaddr (entry->user_page_addr))
  ASSERT (sup_pagetable_entry_lookup (entry->user_page_addr) != NULL)
  ASSERT (entry->owner_thread == thread_current ())
  ASSERT (entry->curr_state != STACK)
  ASSERT (entry->curr_state != ERROR_STATE)
  ASSERT (pagedir_get_page (thread_current ()->pagedir, entry->user_page_addr)
          == NULL)

  /* Special function to load in swap entries from the swap space. */
  if (entry->curr_state == SWAP_SLOT)
    {
      return sup_pagetable_load_from_swap (entry);
    }

  struct frame *frame_ptr;

//  /* Attempt sharing if page is read-only. */
//  if (!entry->writable && entry->curr_state == FILE_SYSTEM)
//    {
//      frame_ptr = read_only_frame_lookup (entry->file, entry->user_page_addr);
//      if (frame_ptr)
//        {
//          lock_acquire (&frame_ptr->frame_lock);
//          list_push_back (&frame_ptr->page_list, &entry->frame_elem);
//          frame_ptr->pinned = true;
//          lock_release (&frame_ptr->frame_lock);
//          install_page (entry->user_page_addr, frame_ptr->kernel_page_addr, entry
//              ->writable);
//          return true;
//        }
//    }

  /* Get a new frame. */
  frame_ptr = falloc_get_frame (false);
  if (frame_ptr == NULL)
    {
      return false;
    }

  lock_acquire (&filesys_lock);
  lock_acquire (&frame_ptr->frame_lock);
  lock_acquire (&entry->page_lock);
  /* Add the page to the process's address space. */
  if (!install_page (entry->user_page_addr, frame_ptr->kernel_page_addr, entry
      ->writable))
    {
      PANIC ("Install page failed");
    }

  /* Frame obtained successfully. We pin the frame here since we are about to
     interface with the pintos filesystem, which should never page fault
     while the code is running. */
  frame_ptr->pinned = true;
  entry->frame_ptr = frame_ptr;
  list_push_back (&frame_ptr->page_list, &entry->frame_elem);

  /* Load data into the page. */
  if (entry->curr_state == FILE_SYSTEM || entry->curr_state == MMAP_FILE)
    {
      file_seek (entry->file, entry->ofs);
      if (file_read (entry->file, frame_ptr->kernel_page_addr, entry->read_bytes)
          != (int) entry->read_bytes)
        {
          lock_release (&filesys_lock);
          falloc_free_frame (frame_ptr);
          return false;
        }

      memset (frame_ptr->kernel_page_addr
              + entry->read_bytes, 0, entry->zero_bytes);
    }

  /* Ensure zero of pages if it is required. */
  if (entry->curr_state == All_ZERO)
    {
      memset (frame_ptr->kernel_page_addr, 0, PGSIZE);
    }

  /* Unpin frame so other frames can evict it, since we are now done with
     reading from the filesystem. */
  frame_ptr->pinned = false;
  lock_release (&entry->page_lock);
  lock_release (&frame_ptr->frame_lock);
  lock_release (&filesys_lock);

  return true;
}

/* Load from swap space. */
static bool sup_pagetable_load_from_swap (struct page_entry *entry)
{
  ASSERT (entry->curr_state == SWAP_SLOT)
  ASSERT (entry->swap_index != SWAP_ERROR)

  /* Acquire a free frame to store page in. */
  struct frame *frame_ptr = falloc_get_frame (false);
  lock_acquire (&frame_ptr->frame_lock);
  lock_acquire (&entry->page_lock);

  /* Copy data from swap space. */
  bool success = read_swap (entry->swap_index, frame_ptr->kernel_page_addr);
  if (!install_page (entry->user_page_addr, frame_ptr->kernel_page_addr, thread_current ()
      ->pagedir))
    {
      PANIC ("Install page failed.");
    }

  /* Restore old values of the page before it was evicted. We also reset the
     page's is_dirty field and swap_index to their defautl values. */
  list_push_back (&frame_ptr->page_list, &entry->frame_elem);
  entry->curr_state = entry->prev_state;
  entry->prev_state = ERROR_STATE;
  entry->frame_ptr = frame_ptr;
  pagedir_set_dirty (entry->owner_thread->pagedir, entry->user_page_addr, entry
      ->is_dirty);
  entry->is_dirty = false;
  entry->swap_index = SWAP_ERROR;

  lock_release (&entry->page_lock);
  lock_release (&frame_ptr->frame_lock);
  return success;
}

/* Finds the page that faulted in the supplemental page table. */
struct page_entry *
sup_pagetable_entry_lookup (void *page)
{
  struct page_entry entry;
  struct hash_elem *e;
  entry.user_page_addr = page;
  e = hash_find (&thread_current ()->sup_pagetable, &entry.spt_elem);
  return e != NULL
         ? hash_entry (e, struct page_entry, spt_elem)
         : NULL;
}

/* Helper functions. */
unsigned
sup_page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page_entry *p = hash_entry(p_, struct page_entry, spt_elem);
  return hash_bytes (&p->user_page_addr, sizeof p->user_page_addr);
}

bool
sup_page_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
              void *aux UNUSED)
{
  const struct page_entry *a = hash_entry (a_, struct page_entry, spt_elem);
  const struct page_entry *b = hash_entry (b_, struct page_entry, spt_elem);
  return a->user_page_addr < b->user_page_addr;
}

void free_sup_page_entry (struct hash_elem *element, void *aux UNUSED)
{
  struct page_entry *entry = hash_entry (element,
                                         struct page_entry,
                                         spt_elem);
  hash_delete (&thread_current ()->sup_pagetable, element);
  free (entry);
}

/* Attempt to grow stack. */
bool
grow_stack (void *user_addr_rounded)
{
  ASSERT (is_user_vaddr (user_addr_rounded))
  struct frame *frame_ptr = falloc_get_frame (true);

  if (frame_ptr == NULL)
    {
      return false;
    }

  lock_acquire (&frame_ptr->frame_lock);
  if (!install_page (user_addr_rounded, frame_ptr->kernel_page_addr, true))
    {
      PANIC ("Install page failed.");
    }

  /* Frame obtained successfully. Add this information to the supplemental
     page table and add the page to the frame's page_list. */
  struct page_entry *entry = add_to_sup_pagetable (user_addr_rounded, STACK,
                                                   NULL, -1, -1, -1, true);
  lock_acquire (&entry->page_lock);
  entry->frame_ptr = frame_ptr;
  list_push_back (&frame_ptr->page_list, &entry->frame_elem);

  lock_release (&entry->page_lock);
  lock_release (&frame_ptr->frame_lock);
  return true;
}