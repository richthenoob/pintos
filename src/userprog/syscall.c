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
#include <vm/page.h>
#include <vm/mmap.h>

#define SINGLE_ARG_SYSCALL_CUTOFF 9
#define DOUBLE_ARG_SYSCALL_CUTOFF 12
#define TRIPLE_ARG_SYSCALL_CUTOFF 14

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
user_memory_access_buffer_is_valid (void *user_ptr, int32_t length);
static bool user_memory_access_string_is_valid (void *user_ptr);
static int get_user (const uint8_t *uaddr);

static int next_fd_value (void);
static struct file_node *file_node_lookup (int fd);
static void mmap_unmap (const struct hash_elem *p_, void *aux UNUSED);

static mapid_t syscall_mmap (int fd, void *p_void);
static void syscall_munmap (mapid_t fd);

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

  thread_current ()->user_esp = f->esp;
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

  thread_current ()->user_esp = (uint32_t *) -1;
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
      case SYS_MUNMAP:
        syscall_munmap (*(int *) arg1);
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
      break;
      case SYS_MMAP:
        return syscall_mmap (*(int *) arg1, *(int *) arg2);
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
  hash_apply (&(thread_current ()->mmap_hash_table), (void (*) (struct hash_elem *, void *)) mmap_unmap);
  process_exit_with_code (exit_code);
  NOT_REACHED()
}

static pid_t syscall_exec (const char *file)
{
  char *file_ptr = *(char **) file;

  if (user_memory_access_string_is_valid (file_ptr))
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
  if (!user_memory_access_string_is_valid (file_ptr) ||
      strcmp (file_ptr, "") == 0)
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
  if (!user_memory_access_string_is_valid (file_ptr))
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
  if (!user_memory_access_string_is_valid (file_ptr))
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
  if (!user_memory_access_is_valid (buffer_ptr)
      || file_node == NULL
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
      || !user_memory_access_is_valid (buffer_ptr + length))
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
  if (file_node != NULL && file_node->mmap_count == 0)
    {
      lock_acquire (&filesys_lock);
      free_file_node (&file_node->hash_elem, NULL);
      lock_release (&filesys_lock);
    }
}

static mapid_t syscall_mmap (int fd, void *addr)
{

  /* Check if the input of fd and addr are valid. */
  if (addr == 0 || fd < 2 || (uint32_t) addr % PGSIZE != 0)
    {
      return -1;
    }

  /* Open the file. */
  struct file_node *file_node = file_node_lookup (fd);
  if (!file_node || !file_node->file)
    {
      return -1;
    }
  struct file *file = file_reopen (file_node->file);
  if (file == NULL)
    {
      return -1;
    }

  off_t length = file_length (file);

  /* Fail if the file opened has a length of zero bytes. */
  if (length == 0)
    {
      return -1;
    }

  /* Assign a mmapid and push mmap_node into the hash table. */
  struct mmap_node *mmap_node = (struct mmap_node *) malloc (sizeof (struct mmap_node));
  mmap_node->mapid = next_mapid_value ();
  mmap_node->fd = fd;
  list_init (&mmap_node->list_pages_open);
  hash_insert (&thread_current ()->mmap_hash_table, &mmap_node->hash_elem);
  file_node->mmap_count += 1;

  /* Determine the zero_bytes and the read_bytes. */
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
      if (pagedir_get_page (thread_current ()->pagedir, addr) != 0)
        {
          return -1;
        }
      if (sup_pagetable_entry_lookup (addr) != NULL)
        {
          // TODO free previously allocated sup. page table entries
          return -1;
        }

      /* Lazy loading. */
      struct sup_pagetable_entry *entry;
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (page_zero_bytes == PGSIZE)
        {
          entry = sup_pagetable_add_all_zero (addr, true);
        }
      else
        {
          entry = sup_pagetable_add_file (MMAP_FILE, addr, file, ofs, read_bytes, zero_bytes, true);
        }

      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      addr += PGSIZE;

      /* Add entry to this mmap node so that we can remove it accordingly
         when the thread is terminated or when munmap is called. */
      list_push_back (&mmap_node->list_pages_open, &entry->mmap_elem);
    }

  return mmap_node->mapid;
}

static void syscall_munmap (mapid_t mapping)
{
  /* Check if the node is mapped. */
  struct mmap_node *mmap_node = mmap_node_lookup (mapping);
  if (mmap_node == NULL)
    {
      return;
    }

  /* Store where the file pointer is before we write to it, so that we can
     restore this information later on. */
  unsigned initial_file_pos = syscall_tell (mmap_node->fd);

  struct list_elem *e;
  struct sup_pagetable_entry *spe;
  struct list *list_pages_open = &mmap_node->list_pages_open;

  for (e = list_begin (list_pages_open); e != list_end (list_pages_open);)
    {
      spe = list_entry (e, struct sup_pagetable_entry, mmap_elem);
      e = list_next (e);

      /* Write back to disk if page has been written to. */
      if (pagedir_is_dirty (thread_current ()->pagedir, spe->upage))
        {
          syscall_write (mmap_node->fd, &spe->upage, spe->read_bytes);
        }

      /* Remove mapping from page directory and free the appropriate memory. */
      pagedir_clear_page (thread_current ()->pagedir, spe->upage);
      free_sup_page_entry (&spe->spt_elem, NULL);
    }

  /* Restore file pointer. */
  syscall_seek (mmap_node->fd, initial_file_pos);

  /* Remove this mmap_node's link to its corresponding file_node. */
  file_node_lookup (mmap_node->fd)->mmap_count -= 1;

  hash_delete (&thread_current ()->mmap_hash_table, &mmap_node->hash_elem);
  free (mmap_node);
}

/* ---------------- MEMORY CHECK FUNCTIONS ---------------- */

/* Check that user pointer is not a kernel addr. and not null. */
static bool
user_memory_access_is_valid (void *user_ptr)
{
  return user_ptr != NULL &&
         is_user_vaddr (user_ptr) &&
         get_user ((uint8_t *) user_ptr) != -1;
}

/* Check that buffer can be written to and is a valid user address. */
static bool
user_memory_access_buffer_is_valid (void *user_ptr, int32_t length)
{
  bool success = user_memory_access_is_valid (user_ptr + length);

  do
    {
      success = success &&
                is_writable_segment (user_ptr + length) &&
                get_user ((uint8_t *) user_ptr + length) != -1;
      length -= PGSIZE;
    }
  while (success && length > PGSIZE);

  return success;
}

/* Check string to ensure that it is of length smaller than or equals
   to PGSIZE. */
static bool
user_memory_access_string_is_valid (void *user_ptr)
{
  long string_length = strnlen (user_ptr, PGSIZE);
  return string_length < PGSIZE + 1
         && user_memory_access_is_valid (user_ptr)
         && user_memory_access_is_valid (user_ptr + string_length);
}

/* ---------------- FILESYSTEM FUNCTIONS ---------------- */

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

static void mmap_unmap (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct mmap_node *p = hash_entry(p_, struct mmap_node, hash_elem);
  syscall_munmap (p->mapid);
}
bool
is_writable_segment (const uint8_t *fault_addr)
{
  bool within_user_stack_space =
      (PHYS_BASE - MAX_STACK_SPACE_IN_BYTES < fault_addr)
      && (fault_addr < PHYS_BASE);
  bool within_data_segment =
      fault_addr >= thread_current ()->start_writable_segment_addr
      && fault_addr < thread_current ()->end_writable_segment_addr;
  return within_user_stack_space || within_data_segment;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;

}