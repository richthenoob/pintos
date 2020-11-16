#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "lib/user/syscall.h"
#include "threads/synch.h"

#define DEFAULT_ERROR_CODE (-10)
#define DEFAULT_PARENT_TID (-20)

struct process {
  struct semaphore exec_sema;
  struct semaphore wait_sema;
  struct hash_elem hash_elem;
  struct list_elem list_elem;
  struct file *exec_file;
  tid_t parent_tid;
  bool waited_on;
  pid_t pid;
  int exit_code;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_exit_with_code(int exit_code);

struct lock process_lock;
struct process *process_lookup (const int pid);
unsigned process_hash (const struct hash_elem *p_, void *aux UNUSED);
bool process_less(const struct hash_elem *a_, const struct hash_elem *b_,
                  void *aux UNUSED);
#endif /* userprog/process.h */
