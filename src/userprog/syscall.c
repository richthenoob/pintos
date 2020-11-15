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
static bool user_memory_access_buffer (void *user_ptr, unsigned length);
static bool user_memory_access_string (void *user_ptr);

static int next_fd_value (void);
static struct file_node *file_node_lookup (int fd, struct thread *t);
static void free_file_node (struct file_node *file_node);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* ---------------- SYSCALL HANDLERS ---------------- */
static void
syscall_handler (struct intr_frame *f)
{
  /* Check that caller arguments are in user virtual memory space. */
  if (!user_memory_access_is_valid (f->esp + 12))
    {
      syscall_exit (-1);
    }

  int syscall_no = *(int *) f->esp;
  void *arg1 = f->esp + 4;
  void *arg2 = f->esp + 8;
  void *arg3 = f->esp + 12;
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
      syscall_exit (-1);
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
      break;
      default:
        syscall_exit (-1);
    }
  return 0;
}

static int double_arg_syscall (int syscall_no, void *arg1, void *arg2)
{
  switch (syscall_no)
    {
      case SYS_CREATE:
        return syscall_create ((const char *) arg1, *(unsigned *) arg2);
      case SYS_SEEK:
        syscall_seek (*(int *) arg1, *(unsigned *) arg2);
      break;
    }
  return 0;
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
        syscall_exit (-1);
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
      && user_memory_access_string (file_ptr))
    {
      char *exec[strlen (file_ptr) + 1];
      strlcpy ((char *) exec, file_ptr, strlen (file_ptr) + 1);
      char *token, *save_ptr;
      token = strtok_r ((char *) exec, " ", &save_ptr);
// TODO: fix issue with testing file exists - refer to tests syn-read vs exec-missing
//      lock_acquire (&filesys_lock);
//      struct file *test_open = filesys_open (token);
//      if (!test_open)
//        {
//          lock_release (&filesys_lock);
//          return TID_ERROR;
//        }
//      file_close (test_open);
//      lock_release (&filesys_lock);
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
  if (!user_memory_access_is_valid (file_ptr) || strcmp (file_ptr, "") == 0)
    {
      syscall_exit (-1);
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
  //todo: consider the case when removing a open file.
  char *file_ptr = *(char **) file;
  if (!user_memory_access_is_valid (file_ptr))
    {
      syscall_exit (-1);
    }
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

static int syscall_open (const char *file)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_is_valid (file_ptr))
    {
      syscall_exit (-1);
    }
  lock_acquire (&filesys_lock);
  struct file *opened_file = filesys_open (file_ptr);
  lock_release (&filesys_lock);
  if (!opened_file)
    {
      return -1;
    }
  struct file_node *node = malloc (sizeof (*node));
  node->file = opened_file;

  struct thread *current_thread = thread_current ();
  node->fd = next_fd_value ();
  hash_insert (&current_thread->hash_table_of_file_nodes, &node->hash_elem);
  return node->fd;
}

static int syscall_filesize (int fd)
{
  struct thread *current_thread = thread_current ();
  lock_acquire (&filesys_lock);
  struct file_node *file_node = file_node_lookup (fd, current_thread);
  if (file_node == NULL)
    {
      lock_release (&filesys_lock);
      return -1;
    }

  int length = file_length (file_node->file);
  lock_release (&filesys_lock);
  return length;
}

static int syscall_read (int fd, void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **) (buffer);
  lock_acquire (&filesys_lock);
  struct file_node *file_node = file_node_lookup (fd, thread_current ());
  if (!user_memory_access_is_valid (buffer_ptr) || file_node == NULL
      || !user_memory_access_buffer (buffer_ptr, length))
    {
      lock_release (&filesys_lock);
      syscall_exit (-1);
    }
  if (fd == STDOUT_FILENO)
    {
      input_getc ();
      lock_release (&filesys_lock);
      return 1;
    }

  int read_length = file_read (file_node->file, buffer_ptr, length);
  lock_release (&filesys_lock);
  return read_length;
}

static int syscall_write (int fd, const void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **) (buffer);
  if (!user_memory_access_is_valid (buffer_ptr)
      || !user_memory_access_buffer (buffer_ptr, length))
    {
      syscall_exit (-1);
    }

//      void *user_ptr = pagedir_get_page (thread_current ()->pagedir, buffer_ptr);

  lock_acquire (&filesys_lock);
  int bytes_written;
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer_ptr, length);
      bytes_written = length;
    }
  else if (fd > STDOUT_FILENO && file_node_lookup (fd, thread_current ()) != NULL)
    {
      bytes_written = file_write (file_node_lookup (fd, thread_current ())->file, buffer_ptr, length);
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
  struct thread *current_thread = thread_current ();
  lock_acquire(&filesys_lock);
  struct file_node *file_node = file_node_lookup (fd, current_thread);
  if (file_node == NULL)
    {
      return;
    }
  file_seek (file_node->file, position);
  lock_release (&filesys_lock);
}

static unsigned syscall_tell (int fd)
{
  struct thread *current_thread = thread_current ();
  lock_acquire(&filesys_lock);
  struct file_node *file_node = file_node_lookup (fd, current_thread);
  if (file_node == NULL)
    {
      lock_release(&filesys_lock);
      return -1;
    }
  unsigned next_byte_pos = file_tell (file_node->file);
  lock_release(&filesys_lock);
  return next_byte_pos;
}

static void syscall_close (int fd)
{
  struct thread *current_thread = thread_current ();
  lock_acquire(&filesys_lock);
  struct file_node *file_node = file_node_lookup (fd, current_thread);
  if (file_node == NULL)
    {
      lock_release(&filesys_lock);
      return;
    }
  hash_delete (&current_thread->hash_table_of_file_nodes, &file_node->hash_elem);
  free_file_node (file_node);
  lock_release(&filesys_lock);
}

/* ---------------- HELPER FUNCTIONS ---------------- */

static bool
user_memory_access_is_valid (void *user_ptr)
{
  return !(user_ptr == NULL ||
           !is_user_vaddr (user_ptr) ||
           pagedir_get_page (thread_current ()->pagedir, user_ptr) == NULL);
}

static bool
user_memory_access_buffer (void *user_ptr, unsigned length)
{
  return is_user_vaddr (user_ptr + length);
}

static bool
user_memory_access_string (void *user_ptr)
{
  unsigned difference = PHYS_BASE - user_ptr + 1;
  return strnlen (user_ptr, difference) < difference;
}

static int
next_fd_value (void)
{
  static tid_t next_fd = 2;
  tid_t tid;

//    lock_acquire (&fd_lock);
  tid = next_fd++;
//    lock_release (&fd_lock);

  return tid;
}

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

static struct file_node *
file_node_lookup (int fd, struct thread *t)
{
  struct file_node file_node;
  struct hash_elem *e;
  file_node.fd = fd;
  e = hash_find (&t->hash_table_of_file_nodes, &file_node.hash_elem);
  return e != NULL ? hash_entry (e, struct file_node, hash_elem) : NULL;
}

static void
free_file_node (struct file_node *file_node)
{
  free (file_node);
}
