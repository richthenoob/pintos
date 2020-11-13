#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
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
static pid_t syscall_exec (const char *file);
static bool user_memory_access_is_valid (void *user_ptr);

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
