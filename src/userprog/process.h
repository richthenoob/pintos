#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "lib/user/syscall.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_exit_with_code(int exit_code);

struct lock process_lock;
struct process *process_lookup (const int pid);
struct process {
  struct semaphore process_sema;
  struct hash_elem hash_elem;
  struct list_elem list_elem;
  struct file *exec_file;
  tid_t parent_tid;
  bool waited_on;
  pid_t pid;
  int exit_code;
};
#endif /* userprog/process.h */
