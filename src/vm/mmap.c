#include "mmap.h"
#include <stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/filesys_wrapper.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

/* Maps a file to given user address. */
mapid_t
memory_map (int fd, void *user_page_addr)
{
  /* Check if the input of fd and user_page_addr are valid. */
  if (user_page_addr == 0 ||
      fd <= STDOUT_FILENO ||
      (uint32_t) user_page_addr % PGSIZE != 0)
    {
      return MMAP_ERROR;
    }

  /* Find the file_node in the process's hash_table_of_file_nodes. */
  struct file_node *file_node = file_node_lookup (fd);
  if (!file_node || !file_node->file)
    {
      return MMAP_ERROR;
    }

  /* Open file and check file length. */
  lock_acquire (&filesys_lock);
  struct file *file = file_reopen (file_node->file);
  lock_release (&filesys_lock);
  if (file == NULL)
    {
      return MMAP_ERROR;
    }

  lock_acquire (&filesys_lock);
  off_t length = file_length (file);
  lock_release (&filesys_lock);

  /* Fail if the file opened has a length of zero bytes. */
  if (length == 0)
    {
      return MMAP_ERROR;
    }

  /* Assign a mmapid and push mmap_node into the hash table. Increment mmap_count
     by one so that any calls to filesys_close will not actually close the file
     before this function finishes. */
  struct mmap_node *mmap_node = (struct mmap_node *) malloc (sizeof (struct mmap_node));
  mmap_node->mapid = next_mapid_value ();
  mmap_node->fd = fd;
  list_init (&mmap_node->list_pages_open);
  hash_insert (&thread_current ()->mmap_hash_table, &mmap_node->hash_elem);
  file_node->mmap_count += 1;

  /* Determine zero_bytes and read_bytes so we know how many pagetable entries
     we should add. Note that we are loading the file in lazily here. */
  uint32_t read_bytes = length;
  uint32_t zero_bytes = -1;
  int n = 0;
  while (n * PGSIZE < length)
    {
      ++n;
    }
  zero_bytes = n * PGSIZE - length;

  /* Map into pages. */
  off_t ofs = 0;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Page exists in the thread's page directory, so we are potentially
         overwriting some data. */
      if (pagedir_get_page (thread_current ()->pagedir, user_page_addr) != NULL)
        {
          return MMAP_ERROR;
        }
      /* Avoid overwriting another supplemental page table entry, since that
         indicates something else should be there. */
      if (sup_pagetable_entry_lookup (user_page_addr) != NULL)
        {
          memory_unmap (mmap_node->mapid);
          return MMAP_ERROR;
        }

      /* Calculate the number of bytes to read/zero in this page. */
      struct page_entry *entry;
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      entry = add_to_sup_pagetable (user_page_addr, MMAP_FILE, file,
                                    ofs, page_read_bytes, page_zero_bytes, true);

      /* Adjust the number of bytes we have to continue reading from the file. */
      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      user_page_addr += PGSIZE;

      /* Add entry to this mmap node so that we can remove it accordingly
       when the thread is terminated or when munmap is called. */
      list_push_back (&mmap_node->list_pages_open, &entry->mmap_elem);
    }

  return mmap_node->mapid;
}

/* Removes a memory mapping, writing to disk if necessary. */
bool memory_unmap (mapid_t mapping)
{
  /* Check if the node is mapped. */
  struct mmap_node *mmap_node = mmap_node_lookup (mapping);
  if (mmap_node == NULL)
    {
      return false;
    }

  struct list_elem *e;
  struct page_entry *entry;
  struct list *list_pages_open = &mmap_node->list_pages_open;

  /* Iterate through the node's list of open pages.  */
  for (e = list_begin (list_pages_open); e != list_end (list_pages_open);)
    {
      entry = list_entry (e, struct page_entry, mmap_elem);
      e = list_next (e);

      /* Write back to disk if page has been written to. */
      if (pagedir_is_dirty (thread_current ()->pagedir, entry->user_page_addr))
        {
          write_page_back_to_file (mmap_node->fd, entry->ofs,
                                   entry->user_page_addr, entry->read_bytes);
        }

      /* Remove mapping from page directory and free the appropriate memory. */
      pagedir_clear_page (thread_current ()->pagedir, entry->user_page_addr);
      free_sup_page_entry (&entry->spt_elem, NULL);
    }

  /* Remove this mmap_node's link to its corresponding file_node. */
  file_node_lookup (mmap_node->fd)->mmap_count -= 1;
  hash_delete (&thread_current ()->mmap_hash_table, &mmap_node->hash_elem);
  free (mmap_node);

  return true;
}

/* Copy write_bytes bytes of data from user_page_addr to file indicated by fd
   at declared offset. */
bool
write_page_back_to_file (int fd, off_t ofs,
                         void *user_page_addr, uint32_t write_bytes)
{
  ASSERT (ofs % PGSIZE == 0)

  /* Store where the file pointer is before we write to it, so that we can
   restore this information later on. */
  unsigned initial_file_pos = syscall_tell (fd);

  /* Write to specific offset within file. */
  syscall_seek (fd, ofs);
  int bytes_written = syscall_write (fd, &user_page_addr, write_bytes);
  ASSERT (bytes_written > 0)
  ASSERT ((uint32_t) bytes_written == write_bytes)

  /* Restore file pointer. */
  syscall_seek (fd, initial_file_pos);
  return true;
}

/* Find a memory mapped node of the current thread's mmap_hash_table given a
   mmap id. No synchronization needed since a thread only
   accesses its own hash table. */
struct mmap_node *
mmap_node_lookup (mapid_t id)
{
  struct mmap_node node;
  struct hash_elem *e;
  node.mapid = id;
  e = hash_find (&thread_current ()->mmap_hash_table, &node.hash_elem);
  return e != NULL ? hash_entry (e, struct mmap_node, hash_elem) : NULL;
}

/* Returns next memory map id value for a specific thread. No synchronization
   needed since a thread only accesses its own hash table. */
mapid_t
next_mapid_value (void)
{
  return hash_size (&thread_current ()->mmap_hash_table);
}

/* Helper functions. */
unsigned
mmap_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct mmap_node *p = hash_entry(p_, struct mmap_node, hash_elem);
  return hash_bytes (&p->mapid, sizeof p->mapid);
}

bool
mmap_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
          void *aux UNUSED)
{
  const struct mmap_node *a = hash_entry (a_, struct mmap_node, hash_elem);
  const struct mmap_node *b = hash_entry (b_, struct mmap_node, hash_elem);
  return a->mapid < b->mapid;
}