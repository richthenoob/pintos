#include "filesys_wrapper.h"
#include <stdlib.h>
#include <stdio.h>
#include <debug.h>
#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

static int next_fd_value (void);

int add_to_hash_table_of_file_nodes (struct file *opened_file);

/* Find a file node of the current thread's hash_table_of_file_nodes given a
   file descriptor, fd. No synchronization needed since a thread only
   accesses its own hash table. */
struct file_node *
file_node_lookup (int fd)
{
  struct file_node fn;
  struct hash_elem *e;
  fn.fd = fd;
  e = hash_find (&thread_current ()->hash_table_of_file_nodes, &fn.hash_elem);
  return e != NULL ? hash_entry (e, struct file_node, hash_elem) : NULL;
}

/* Add to current thread's hash_table_of_file_nodes. No synchronization needed. */
int add_to_hash_table_of_file_nodes (struct file *opened_file)
{
  struct file_node *node = malloc (sizeof (*node));
  if (node == NULL)
    {
      return DEFAULT_ERR_EXIT_CODE;
    }
  node->file = opened_file;
  node->fd = next_fd_value ();
  hash_insert (&(thread_current ()->hash_table_of_file_nodes), &node->hash_elem);
  return node->fd;
}

/* Close file opened by this file_node and frees the malloc-ed struct. */
void free_file_node (struct hash_elem *element, void *aux UNUSED)
{
  ASSERT (lock_held_by_current_thread (&filesys_lock));
  struct file_node *fn = hash_entry (element,
                                     struct file_node,
                                     hash_elem);
  file_close (fn->file);
  hash_delete (&thread_current ()->hash_table_of_file_nodes, element);
  free (fn);
}

/* Returns next file descriptor value for a specific thread. No synchronization
   needed since a thread only accesses its own hash table. */
static int
next_fd_value (void)
{
  return hash_size (&thread_current ()->hash_table_of_file_nodes)
         + STDOUT_FILENO + 1;
}

/* A few functions used to initialize a thread's hash_table_of_file_nodes. */
unsigned
file_node_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct file_node *p = hash_entry (p_, struct file_node, hash_elem);
  return hash_int (p->fd);
}

bool
file_node_less (const struct hash_elem *a_,
                const struct hash_elem *b_,
                void *aux UNUSED)
{
  const struct file_node *a = hash_entry (a_, struct file_node, hash_elem);
  const struct file_node *b = hash_entry (b_, struct file_node, hash_elem);
  return a->fd < b->fd;
}