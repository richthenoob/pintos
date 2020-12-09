#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/kernel/hash.h"
#include "lib/user/syscall.h"
#include "threads/thread.h"
#include "threads/synch.h"

#define EXIT_CODE_FAILED_LOAD (-11)
#define DEFAULT_EXIT_CODE (-10)
#define DEFAULT_PARENT_TID (-20)
#define MAX_NUMBER_OF_ARGS (64)

struct hash process_hashtable;          /* Hashtable to store process structs. */
struct lock process_lock;               /* Lock used before accessing process_hashtable.*/

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
void process_exit_with_code (int exit_code);
bool install_page (void *upage, void *kpage, bool writable);

struct process *process_lookup (const int pid);
#endif /* userprog/process.h */
