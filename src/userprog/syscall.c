#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void print_process_termination_msg (int exit_code);
static void check_user_memory_access (struct intr_frame *f, void *user_ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  // TODO: check user memory access
//  hex_dump(0, f->esp, 32, true);
  switch (*(int *) f->esp) {
    case SYS_WRITE:
      syscall_write(f);
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
  }
}

static void syscall_write(struct intr_frame *f) {
  printf("write syscall called!\n");
}

static void syscall_exit(struct intr_frame *f) {
  printf("exit syscall called!\n");
  // need to change to access from argument of exit
  print_process_termination_msg(0);
}

static void print_process_termination_msg (int exit_code) {
 // TODO: somehow find process name as passed in to process_execute
}

static void
check_user_memory_access (struct intr_frame *f, void *user_ptr) {
  if (!is_user_vaddr(user_ptr)) {
    printf("user_addr below PHYBASE\n");
    return;
  }
  if (pagedir_get_page(thread_current()->pagedir, user_ptr) == NULL) {
    printf("wrong page dir\n");
    return;
  };
}