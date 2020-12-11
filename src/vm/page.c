#include "page.h"
#include <string.h>
#include <stdio.h>
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
  entry->swap_index = -1;
  entry->is_dirty = false;
  entry->mmap_fd = MMAP_ERROR;

  /* Add the page to the supplemental page table. */
  hash_insert (&thread_current ()->sup_pagetable, &entry->spt_elem);

  return entry;
}

/* Actual loading a file. */
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

  if (entry->curr_state == SWAP_SLOT)
    {
      return sup_pagetable_load_from_swap (entry);
    }

  struct frame *frame_ptr;

//      /* Attempt sharing if page is read-only. */
//      if (!entry->writable && entry->state == FILE_SYSTEM)
//        {
//          kframe = read_only_frame_lookup (entry->file, entry->upage);
//          if (kframe)
//            {
//              lock_acquire (&kframe->frame_lock);
//              kframe->counter++;
//              list_push_back(&kframe->page_list,&thread_current()->frame_elem);
//              kframe->pinned = true;
//              lock_release (&kframe->frame_lock);
//              install_page (entry->upage, kframe->kernel_page_addr, entry->writable);
//              return true;
//            }
//        }

  /* Get a new page of memory. */
  frame_ptr = falloc_get_frame (false);
  if (frame_ptr == NULL)
    {
      return false;
    }

  lock_acquire (&frame_ptr->frame_lock);
  /* Add the page to the process's address space. */
  if (!install_page (entry->user_page_addr, frame_ptr->kernel_page_addr, entry
      ->writable))
    {
      PANIC ("install page failed");
      falloc_free_frame (frame_ptr);
      return false;
    }

  /* Frame obtained successfully. */
  frame_ptr->pinned = true;
  entry->frame_ptr = frame_ptr;
  list_push_back (&frame_ptr->page_list, &entry->frame_elem);

  /* Load data into the page. */
  if (entry->curr_state == FILE_SYSTEM || entry->curr_state == MMAP_FILE)
    {
      lock_acquire (&filesys_lock);
      file_seek (entry->file, entry->ofs);
      if (file_read (entry->file, frame_ptr->kernel_page_addr, entry->read_bytes)
          != (int) entry->read_bytes)
        {
          lock_release (&filesys_lock);
          falloc_free_frame (frame_ptr);
          return false;
        }
      lock_release (&filesys_lock);

      memset (frame_ptr->kernel_page_addr
              + entry->read_bytes, 0, entry->zero_bytes);
    }

  frame_ptr->pinned = false;
  lock_release (&frame_ptr->frame_lock);

  return true;
}

static bool sup_pagetable_load_from_swap (struct page_entry *entry)
{
  ASSERT (entry->curr_state == SWAP_SLOT)
  ASSERT (entry->swap_index != -1)

  struct frame *frame_ptr = falloc_get_frame (false);
  lock_acquire (&frame_ptr->frame_lock);

  bool success = read_swap (entry->swap_index, frame_ptr->kernel_page_addr);
  install_page (entry->user_page_addr, frame_ptr->kernel_page_addr, thread_current ()
      ->pagedir);

  list_push_back (&frame_ptr->page_list, &entry->frame_elem);
  entry->curr_state = entry->prev_state;
  entry->prev_state = ERROR_STATE;
  entry->frame_ptr = frame_ptr;
  pagedir_set_dirty (entry->owner_thread->pagedir, entry->user_page_addr, entry
      ->is_dirty);
  entry->is_dirty = false;
  entry->swap_index = -1;

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
      falloc_free_frame (frame_ptr);
      return false;
    }

  /* Frame obtained successfully. */
  struct page_entry *entry = add_to_sup_pagetable (user_addr_rounded, STACK,
                                                   NULL, -1, -1, -1, true);
  entry->frame_ptr = frame_ptr;
  list_push_back (&frame_ptr->page_list, &entry->frame_elem);

  ASSERT (sup_pagetable_entry_lookup (user_addr_rounded) != NULL)
  lock_release (&frame_ptr->frame_lock);
  return true;
}