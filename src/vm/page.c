#include "page.h"
#include <string.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/filesys_wrapper.h"
#include "vm/frame.h"
#include "vm/swap.h"

struct sup_pagetable_entry *
sup_pagetable_add_swap (void *upage, bool writable) {
  return sup_pagetable_add_file (thread_current(), SWAP_SLOT, upage, 0, 0, 0, 0, writable);
}

/* Add an entry to the supplemental page table in all-zero situation. */
struct sup_pagetable_entry *
sup_pagetable_add_all_zero (void *upage, bool writable, struct file *file)
{
  return sup_pagetable_add_file (thread_current(), All_ZERO, upage, file, 0, 0, 0, writable);
}

/* Add an entry to the supplemental page table with information of a file. */
struct sup_pagetable_entry *
sup_pagetable_add_file (struct thread *thread, enum page_state state, void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  /* Record file information in a page. */
  struct sup_pagetable_entry *entry = malloc (sizeof (struct sup_pagetable_entry));
  entry->state = state;
  entry->upage = upage;
  entry->file = file;
  entry->ofs = ofs;
  entry->read_bytes = read_bytes;
  entry->zero_bytes = zero_bytes;
  entry->writable = writable;

  /* Add the page to the supplemental page table. */
  hash_insert (&thread->sup_pagetable, &entry->spt_elem);

  return entry;
}

/* Actual loading in all-zero situation. */
bool
sup_pagetable_load_all_zero (struct sup_pagetable_entry *entry)
{
  ASSERT (is_user_vaddr(entry->upage));

  /* Check if virtual page already allocated */
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->upage);

  if (kpage == NULL)
    {

      /* Get a new frame of memory. */
      struct frame *kframe = falloc_get_frame (true, All_ZERO, entry->upage, NULL, entry
          ->writable, 0, 0);
      if (kframe == NULL)
        {
          return false;
        }

      /* Add the page to the process's address space. */
      if (!install_page (entry->upage, kframe->kernel_page_addr, entry->writable))
        {
          falloc_free_frame (kframe);
          return false;
        }
    }

  /* Supplemental pagetable entry is not needed anymore since we have
   successfully loaded into memory. Do not free if state is MMAP_FILE since
   the mmap entry still requires this struct. */
  if (entry->state == All_ZERO || entry->state == FILE_SYSTEM)
    {
      free_sup_page_entry (&entry->spt_elem, NULL);
    }
  return true;
}

/* Actual loading a file. */
bool
sup_pagetable_load_file (struct sup_pagetable_entry *entry)
{
  ASSERT (is_user_vaddr(entry->upage));

  lock_acquire (&filesys_lock);
  file_seek (entry->file, entry->ofs);
  lock_release (&filesys_lock);

  /* Check if virtual page already allocated. */
  struct frame *kframe;
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->upage);

  if (kpage == NULL)
    {

      /* Attempt sharing if page is read-only. */
      if (!entry->writable && entry->state == FILE_SYSTEM)
        {
          kframe = read_only_frame_lookup (entry->file, entry->upage);
          if (kframe)
            {
              lock_acquire (&kframe->frame_lock);
              kframe->counter++;
              list_push_back(&kframe->threads_users,&thread_current()->frame_elem);
              kframe->pinned = true;
              lock_release (&kframe->frame_lock);
              install_page (entry->upage, kframe->kernel_page_addr, entry->writable);
              return true;
            }
        }

      /* Get a new page of memory. */
      kframe = falloc_get_frame (false, FILE_SYSTEM,
                                 entry->upage, entry->file, entry->writable, entry->ofs, entry->read_bytes);
      if (kframe == NULL)
        {
          return false;
        }

      /* Add the page to the process's address space. */
      if (!install_page (entry->upage, kframe->kernel_page_addr, entry->writable))
        {
          falloc_free_frame (kframe);
          return false;
        }

      /* Page obtained successfully. */
      kpage = kframe->kernel_page_addr;
    }

  /* Load data into the page. */
  lock_acquire (&filesys_lock);
  if (file_read (entry->file, kpage, entry->read_bytes)
      != (int) entry->read_bytes)
    {
      lock_release (&filesys_lock);
      falloc_free_frame (kframe);
      return false;
    }
  lock_release (&filesys_lock);

  memset (kpage + entry->read_bytes, 0, entry->zero_bytes);

  /* Supplemental page table entry is not needed anymore since we have
     successfully loaded into memory. */
  if (entry->state == All_ZERO || entry->state == FILE_SYSTEM)
    {
      free_sup_page_entry (&entry->spt_elem, NULL);
    }
  return true;
}

bool sup_pagetable_load_from_swap (struct sup_pagetable_entry *entry) {
  ASSERT (is_user_vaddr(entry->upage));
  struct frame *f = falloc_get_frame (true, SWAP_SLOT, entry->upage, NULL, entry
      ->writable, entry->ofs, entry->read_bytes);
  bool success = read_swap_table (thread_current()->tid, entry->upage, f);

  install_page (f->user_page_addr, f->kernel_page_addr, thread_current()->pagedir);
  free_sup_page_entry (&entry->spt_elem, NULL);
  return success;
}

/* Finds the page that faulted in the supplemental page table. */
struct sup_pagetable_entry *
sup_pagetable_entry_lookup (void *page)
{
  struct sup_pagetable_entry entry;
  struct hash_elem *e;
  entry.upage = page;
  e = hash_find (&thread_current ()->sup_pagetable, &entry.spt_elem);
  return e != NULL
         ? hash_entry (e, struct sup_pagetable_entry, spt_elem)
         : NULL;
}

/* Helper functions. */
unsigned
sup_page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct sup_pagetable_entry *p = hash_entry(p_, struct sup_pagetable_entry, spt_elem);
  return hash_bytes (&p->upage, sizeof p->upage);
}

bool
sup_page_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
              void *aux UNUSED)
{
  const struct sup_pagetable_entry *a = hash_entry (a_, struct sup_pagetable_entry, spt_elem);
  const struct sup_pagetable_entry *b = hash_entry (b_, struct sup_pagetable_entry, spt_elem);
  return a->upage < b->upage;
}

void free_sup_page_entry (struct hash_elem *element, void *aux UNUSED)
{
  struct sup_pagetable_entry *entry = hash_entry (element,
                                                  struct sup_pagetable_entry,
                                                  spt_elem);
  hash_delete (&thread_current ()->sup_pagetable, element);
  free (entry);
}