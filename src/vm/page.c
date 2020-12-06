#include "page.h"
#include <string.h>
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "vm/frame.h"

/* Add an entry to the supplemental page table in all-zero situation. */
struct sup_pagetable_entry *
sup_pagetable_add_all_zero (void *upage, bool writable)
{
  return sup_pagetable_add_file (All_ZERO, upage, NULL, 0, 0, 0, writable);
}

/* Add an entry to the supplemental page table with information of a file. */
struct sup_pagetable_entry *
sup_pagetable_add_file (enum page_state state, void *upage,
                        struct file *file, off_t ofs, uint32_t read_bytes,
                        uint32_t zero_bytes, bool writable)
{
  /* Record file information in a page. */
  struct sup_pagetable_entry *entry
      = (struct sup_pagetable_entry *) malloc (sizeof (struct sup_pagetable_entry));
  entry->state = state;
  entry->upage = upage;
  entry->file = file;
  entry->ofs = ofs;
  entry->read_bytes = read_bytes;
  entry->zero_bytes = zero_bytes;
  entry->writable = writable;

  /* Add the page to the supplemental page table. */
  hash_insert (&thread_current ()->sup_pagetable, &entry->spt_elem);

  return entry;
}

/* Actual loading in all-zero situation. */
bool
sup_pagetable_load_all_zero (struct sup_pagetable_entry *entry)
{
  /* Check if virtual page already allocated */
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->upage);

  if (kpage == NULL)
    {

      /* Get a new frame of memory. */
      struct frame *kframe = falloc_get_frame (true);
      if (kframe == NULL)
        {
          return false;
        }

      /* Add the page to the process's address space. */
      if (!install_page (entry->upage, kframe->page_ptr, entry->writable))
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
  file_seek (entry->file, entry->ofs);

  /* Check if virtual page already allocated. */
  struct frame *kframe;
  struct thread *t = thread_current ();
  uint8_t *kpage = pagedir_get_page (t->pagedir, entry->upage);

  if (kpage == NULL)
    {

      /* Get a new page of memory. */
      kframe = falloc_get_frame (true);
      if (kframe == NULL)
        {
          return false;
        }

      /* Add the page to the process's address space. */
      if (!install_page (entry->upage, kframe->page_ptr, entry->writable))
        {
          falloc_free_frame (kframe);
          return false;
        }
      kpage = kframe->page_ptr;
    }

  /* Load data into the page. */
  if (file_read (entry->file, kpage, entry->read_bytes)
      != (int) entry->read_bytes)
    {
      falloc_free_frame (kframe);
      return false;
    }

  memset (kpage + entry->read_bytes, 0, entry->zero_bytes);

  /* Supplemental page table entry is not needed anymore since we have
     successfully loaded into memory. */
  if (entry->state == All_ZERO || entry->state == FILE_SYSTEM)
    {
      free_sup_page_entry (&entry->spt_elem, NULL);
    }
  return true;
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