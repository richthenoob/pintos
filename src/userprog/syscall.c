#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <threads/synch.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "lib/string.h"
#include "filesys/directory.h"

#define SINGLE_ARG_SYSCALL_CUTOFF 8
#define DOUBLE_ARG_SYSCALL_CUTOFF 10
#define TRIPLE_ARG_SYSCALL_CUTOFF 12

static void syscall_handler (struct intr_frame *);
static int single_arg_syscall (int syscall_no, void *arg1);
static int double_arg_syscall (int syscall_no, void *arg1, void *arg2);
static int triple_arg_syscall (int syscall_no, void *arg1,
                               void *arg2, void *arg3);

static void syscall_exit (int exit_code) NO_RETURN;
static pid_t syscall_exec (const char *file);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_write (int fd, const void *buffer, unsigned length);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);

static bool user_memory_access_is_valid (void *user_ptr);
static bool
user_memory_access_buffer_is_valid (void *user_ptr, unsigned length);
static bool user_memory_access_string_is_valid (void *user_ptr);

static int next_fd_value (void);
static struct file_node *file_node_lookup (int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* ---------------- SYSCALL HANDLERS ---------------- */
static void
syscall_handler (struct intr_frame *f)
{
  /* Check that caller arguments are in user virtual memory space. Since
     the maximum number of args is 3, we just need to check that the 3rd
     argument is within user space. */
  if (!user_memory_access_is_valid (f->esp + 3 * sizeof (void *)))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }

  int syscall_no = *(int *) f->esp;
  void *arg1 = f->esp + 1 * sizeof (void *);
  void *arg2 = f->esp + 2 * sizeof (void *);
  void *arg3 = f->esp + 3 * sizeof (void *);
  int return_value;
  if (syscall_no == 0)
    {
      shutdown_power_off ();
    }
  else if (syscall_no <= SINGLE_ARG_SYSCALL_CUTOFF)
    {
      return_value = single_arg_syscall (syscall_no, arg1);
    }
  else if (syscall_no <= DOUBLE_ARG_SYSCALL_CUTOFF)
    {
      return_value = double_arg_syscall (syscall_no, arg1, arg2);
    }
  else if (syscall_no <= TRIPLE_ARG_SYSCALL_CUTOFF)
    {
      return_value = triple_arg_syscall (syscall_no, arg1, arg2, arg3);
    }
  else
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }

  f->eax = return_value;
}

static int single_arg_syscall (int syscall_no, void *arg1)
{
  switch (syscall_no)
    {
      case SYS_EXIT:
        syscall_exit (*(int *) arg1);
      NOT_REACHED()
      case SYS_EXEC:
        return syscall_exec (arg1);
      case SYS_WAIT:
        return syscall_wait (*(pid_t *) arg1);
      case SYS_REMOVE:
        return syscall_remove ((const char *) arg1);
      case SYS_OPEN:
        return syscall_open ((const char *) arg1);
      case SYS_FILESIZE:
        return syscall_filesize (*(int *) arg1);
      case SYS_TELL:
        return syscall_tell (*(int *) arg1);
      case SYS_CLOSE:
        syscall_close (*(int *) arg1);
      return 0;
      default:
        syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
}

static int double_arg_syscall (int syscall_no, void *arg1, void *arg2)
{
  switch (syscall_no)
    {
      case SYS_CREATE:
        return syscall_create ((const char *) arg1, *(unsigned *) arg2);
      case SYS_SEEK:
        syscall_seek (*(int *) arg1, *(unsigned *) arg2);
      return 0;
      default:
        syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
}

static int triple_arg_syscall (int syscall_no, void *arg1,
                               void *arg2, void *arg3)
{
  switch (syscall_no)
    {
      case SYS_READ:
        return syscall_read (*(int *) arg1, arg2, *(unsigned *) arg3);
      case SYS_WRITE:
        return syscall_write (*(int *) arg1, arg2, *(unsigned *) arg3);
      default:
        syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
}

/* ---------------- SYSCALL FUNCTIONS ---------------- */
static void syscall_exit (int exit_code)
{
  process_exit_with_code (exit_code);
  NOT_REACHED()
}

static pid_t syscall_exec (const char *file)
{
  char *file_ptr = *(char **) file;

  if (user_memory_access_is_valid (file_ptr)
      && user_memory_access_string_is_valid (file_ptr))
    {
      return process_execute (file_ptr);
    }
  else
    {
      return TID_ERROR;
    }
}

static int syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool syscall_create (const char *file, unsigned initial_size)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_is_valid (file_ptr) || strcmp (file_ptr, "") == 0
      || !user_memory_access_buffer_is_valid (file_ptr, NAME_MAX))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
  if (strlen (file_ptr) > NAME_MAX)
    {
      return false;
    }
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file_ptr, initial_size);
  lock_release (&filesys_lock);
  return success;
}

static bool syscall_remove (const char *file)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_is_valid (file_ptr)
      || !user_memory_access_buffer_is_valid (file_ptr, NAME_MAX))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file_ptr);
  lock_release (&filesys_lock);
  return success;
}

static int syscall_open (const char *file)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_is_valid (file_ptr)
      || !user_memory_access_buffer_is_valid (file_ptr, NAME_MAX))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
  lock_acquire (&filesys_lock);
  struct file *opened_file = filesys_open (file_ptr);
  lock_release (&filesys_lock);
  if (!opened_file)
    {
      return DEFAULT_ERR_EXIT_CODE;
    }

  return add_to_hash_table_of_file_nodes (opened_file);
}

static int syscall_filesize (int fd)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      return DEFAULT_ERR_EXIT_CODE;
    }
  lock_acquire (&filesys_lock);
  int length = file_length (file_node->file);
  lock_release (&filesys_lock);
  return length;
}

static int syscall_read (int fd, void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **) (buffer);
  struct file_node *file_node = file_node_lookup (fd);
  if (!user_memory_access_is_valid (buffer_ptr) || file_node == NULL
      || !user_memory_access_buffer_is_valid (buffer_ptr, length))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
  int read_length;
  switch (fd)
    {
      case STDIN_FILENO:
        read_length = input_getc ();
      break;
      case STDOUT_FILENO:
        process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
      NOT_REACHED()
      default:
        lock_acquire (&filesys_lock);
      read_length = file_read (file_node->file, buffer_ptr, length);
      lock_release (&filesys_lock);
    }

  return read_length;
}

static int syscall_write (int fd, const void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **) (buffer);
  if (!user_memory_access_is_valid (buffer_ptr)
      || !user_memory_access_buffer_is_valid (buffer_ptr, length))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }

  lock_acquire (&filesys_lock);
  int bytes_written;
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer_ptr, length);
      bytes_written = length;
    }
  else if (fd > STDOUT_FILENO
           && file_node_lookup (fd) != NULL)
    {
      bytes_written = file_write (file_node_lookup (fd)->file, buffer_ptr, length);
    }
  else
    {
      bytes_written = 0;
    }
  lock_release (&filesys_lock);
  return bytes_written;
}

static void syscall_seek (int fd, unsigned position)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
    }
  lock_acquire (&filesys_lock);
  file_seek (file_node->file, position);
  lock_release (&filesys_lock);
}

static unsigned syscall_tell (int fd)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
      NOT_REACHED()
    }
  lock_acquire (&filesys_lock);
  unsigned next_byte_pos = file_tell (file_node->file);
  lock_release (&filesys_lock);
  return next_byte_pos;
}

static void syscall_close (int fd)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node != NULL)
    {
      lock_acquire (&filesys_lock);
      free_file_node (&file_node->hash_elem, NULL);
      lock_release (&filesys_lock);
    }
}

/* ---------------- HELPER FUNCTIONS ---------------- */

/* Check that user pointer is not a kernal addr. and not null. If
   the pointer points to an unmapped page, we handle it in exception.c */
static bool
user_memory_access_is_valid (void *user_ptr)
{
  return !(user_ptr == NULL ||
           !is_user_vaddr (user_ptr));
}

static bool
user_memory_access_buffer_is_valid (void *user_ptr, unsigned length)
{
  bool success = user_memory_access_is_valid (user_ptr + length);
  while (success && length > PGSIZE)
    {
      length -= PGSIZE;
      success = pagedir_get_page (thread_current ()->pagedir, user_ptr) != NULL;
    }
  return success;
}

/* Check string to ensure that it is of length smaller than or equals
   to PGSIZE. */
static bool
user_memory_access_string_is_valid (void *user_ptr)
{
  return strnlen (user_ptr, PGSIZE) < PGSIZE + 1;
}

/* Returns next file descriptor value for a specific thread. No synchronization
   needed since a thread only accesses its own hash table. */
static int
next_fd_value (void)
{
  return hash_size (&thread_current ()->hash_table_of_file_nodes)
         + STDOUT_FILENO + 1;
}

/* Find a file node of the current thread's hash_table_of_file_nodes given a
   file descriptor, fd. No synchronization needed since a thread only
   accesses its own hash table. */
static struct file_node *
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
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
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