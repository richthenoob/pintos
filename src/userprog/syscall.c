#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <threads/synch.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "lib/string.h"

#define SINGLE_ARG_SYSCALL_CUTOFF 8
#define DOUBLE_ARG_SYSCALL_CUTOFF 10
#define TRIPLE_ARG_SYSCALL_CUTOFF 12

static void syscall_handler (struct intr_frame *);
static int single_arg_syscall(int syscall_no, void *arg1);
static int double_arg_syscall(int syscall_no, void *arg1, void *arg2);
static int triple_arg_syscall(int syscall_no, void *arg1, void *arg2, void *arg3);
static int syscall_write (int fd, const void *buffer, unsigned length);
static void syscall_exit (int exit_code) NO_RETURN;
static int syscall_wait (pid_t pid);
static bool syscall_create(const char *file, unsigned initial_size);
static int syscall_open(struct intr_frame *);
static pid_t syscall_exec (const char *file);
static bool user_memory_access_is_valid (void *user_ptr);
static int next_fd_value(void);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  /* Check that caller arguments are in user virtual memory space. */
  if (!user_memory_access_is_valid (f->esp + 12)) {
    syscall_exit(-1);
  }

  int syscall_no = *(int *) f->esp;
  void *arg1 = f->esp + 4;
  void *arg2 = f->esp + 8;
  void *arg3 = f->esp + 12;
  int return_value;
  if (syscall_no <= SINGLE_ARG_SYSCALL_CUTOFF) {
    return_value = single_arg_syscall(syscall_no, arg1);
  } else if (syscall_no <= DOUBLE_ARG_SYSCALL_CUTOFF) {
    return_value = double_arg_syscall(syscall_no, arg1, arg2);
  } else if (syscall_no <= TRIPLE_ARG_SYSCALL_CUTOFF) {
    return_value = triple_arg_syscall(syscall_no, arg1, arg2, arg3);
  } else {
      syscall_exit(-1);
  }

  f->eax = return_value;
}

static bool syscall_create(const char *file, unsigned initial_size) {
  //TODO: check to see if valid file pointer; Synchronization.
  return filesys_create(file, initial_size);
}

static int syscall_open(struct intr_frame *f) {
  //hashtable version
  if (!user_memory_access_is_valid(f->esp + 4)) {
    thread_exit();
  }
  struct file *file1 = filesys_open(*(const char **) (f->esp + 4));
  if (!file1) {
    return -1;
  }
  struct file_node * node = malloc(sizeof(*node));
  node->file = file1;

  struct thread *current_thread = thread_current();
  node->fd = next_fd_value();
  hash_insert(&current_thread->hash_table_of_file_nodes, &node->hash_elem);
  return node->fd;
}

static int next_fd_value(void) {
  static tid_t next_fd = 2;
    tid_t tid;

//    lock_acquire (&fd_lock);
    tid = next_fd++;
//    lock_release (&fd_lock);

    return tid;
}

//static int syscall_filesize(struct intr_frame *f) {
//    int target_fd_value = *((int *)(f->esp + 4));
//    struct thread* current_thread = thread_current();
//    struct list_elem *e;
//    for (e = list_begin (&current_thread->fd_elems);
//         e != list_end (&current_thread->fd_elems);
//         e = list_next (e))
//    {
//        struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
//        if (fd->value == target_fd_value) {
//            return file_length(fd->file);
//        }
//    }
//}


  unsigned
  file_node_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct file_node *p = hash_entry (p_, struct file_node, hash_elem);
    return hash_bytes(&p->file, sizeof p->file);
  }
  bool
  file_node_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct file_node *a = hash_entry (a_, struct file_node, hash_elem);
    const struct file_node *b = hash_entry (b_, struct file_node, hash_elem);
    return a->fd < b->fd;
  }

static int single_arg_syscall(int syscall_no, void *arg1) {
  switch (syscall_no)
    {
      case SYS_EXIT:
        syscall_exit (*(int *)arg1);
        NOT_REACHED()
      case SYS_EXEC:
        return syscall_exec (arg1);
      case SYS_WAIT:
        return syscall_wait (*(pid_t *) arg1);
      default:
        syscall_exit (-1);
    }
}

static int double_arg_syscall(int syscall_no, void *arg1, void *arg2) {
  return 0;
}

static int triple_arg_syscall(int syscall_no, void *arg1, void *arg2, void *arg3) {
  switch (syscall_no)
    {
      case SYS_WRITE:
        return syscall_write(*(int *) arg1, arg2, *(unsigned *) arg3);
      default:
        syscall_exit (-1);
    }
}

static int syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

static pid_t syscall_exec (const char *file)
{
  char *file_ptr = *(char **)file;
  if (user_memory_access_is_valid (file_ptr))
    {
     return process_execute (file_ptr);
    }
  else
    {
      syscall_exit(-1);
    }
}

static int syscall_write (int fd, const void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **)(buffer);
  if (user_memory_access_is_valid (buffer_ptr))
    {
//      void *user_ptr = pagedir_get_page (thread_current ()->pagedir, buffer_ptr);
      if (fd == STDOUT_FILENO)
        {
          putbuf (buffer_ptr, length);
        }
    }
  else
    {
      syscall_exit(-1);
    }
}

static void syscall_exit (int exit_code)
{
  process_exit_with_code (exit_code);
}

static bool
user_memory_access_is_valid (void *user_ptr)
{
  return !(user_ptr == NULL ||
           !is_user_vaddr (user_ptr) ||
           pagedir_get_page (thread_current ()->pagedir, user_ptr) == NULL);
}