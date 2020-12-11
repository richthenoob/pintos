#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/string.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/filesys_wrapper.h"
#include "vm/mmap.h"
#include "vm/frame.h"

#define SINGLE_ARG_SYSCALL_CUTOFF 9
#define DOUBLE_ARG_SYSCALL_CUTOFF 12
#define TRIPLE_ARG_SYSCALL_CUTOFF 14

/* Syscall handler/dispatcher. */
static void syscall_handler (struct intr_frame *);
static int single_arg_syscall (int syscall_no, void *arg1);
static int double_arg_syscall (int syscall_no, void *arg1, void *arg2);
static int triple_arg_syscall (int syscall_no, void *arg1,
                               void *arg2, void *arg3);

/* Syscall functions. */
static void syscall_exit (int exit_code) NO_RETURN;
static pid_t syscall_exec (const char *file);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
int syscall_write (int fd, const void *buffer, unsigned length);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static mapid_t syscall_mmap (int fd, void *addr);
void syscall_munmap (mapid_t mapping);

/* Memory validation function.s */
static bool user_memory_access_is_valid (void *user_ptr);
static bool
user_memory_access_buffer_is_valid (void *user_ptr,
                                    int32_t length,
                                    bool read_only);
static bool user_memory_access_string_is_valid (void *user_ptr);
static int get_user (const uint8_t *uaddr);

/* Pinning functions, used in VM. */
static void user_memory_string_unpin (void *user_ptr);
static void user_memory_buffer_unpin (void *user_ptr, int32_t length);

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

  /* Save the user esp in struct frame, in case we page fault in the
     syscall handler and need to find the original esp. */
  thread_current ()->user_esp = f->esp;
  int return_value;

  /* Dispatch to different functions based on the number of arguments. This
     cutoff is based on the enum order in <syscall-nr.h>. */
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

  /* Resets the user_esp stored on thread. */
  thread_current ()->user_esp = (uint32_t *) DEFAULT_ERR_EXIT_CODE;
  f->eax = return_value;
}

/* Syscall dispatch for single argument syscalls. The de-referencing of stack
   pointers to find the actual arguments is done here. */
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
  NOT_REACHED();
}

/* Syscall dispatch for double argument syscalls. */
static int double_arg_syscall (int syscall_no, void *arg1, void *arg2)
{
  switch (syscall_no)
    {
      case SYS_CREATE:
        return syscall_create ((const char *) arg1, *(unsigned *) arg2);
      case SYS_SEEK:
        syscall_seek (*(int *) arg1, *(unsigned *) arg2);
      return 0;
      case SYS_MMAP:
        return syscall_mmap (*(int *) arg1, (void *) *(int32_t *) arg2);
      default:
        syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }
  NOT_REACHED();
}

/* Syscall dispatch for triple argument syscalls. */
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
  NOT_REACHED();
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
  tid_t child_tid;

  /* Verifies the file_ptr by attempting to fault in the page the file name
     name is stored on. This check also pins the page. Refer to the actual
     function for more information. */
  if (user_memory_access_string_is_valid (file_ptr))
    {
      child_tid = process_execute (file_ptr);
    }
  else
    {
      child_tid = TID_ERROR;
    }

  /* Remember to unpin the page after we are done with it. */
  user_memory_string_unpin (file_ptr);
  return child_tid;
}

static int syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool syscall_create (const char *file, unsigned initial_size)
{
  /* Ensures that a valid file name is passed in. */
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

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
     is not thread safe. */
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file_ptr, initial_size);
  lock_release (&filesys_lock);

  /* Remember to unpin the page after we are done with it. */
  user_memory_string_unpin (file_ptr);
  return success;
}

static bool syscall_remove (const char *file)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_string_is_valid (file_ptr))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
     is not thread safe. */
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file_ptr);
  lock_release (&filesys_lock);

  /* Remember to unpin the page after we are done with it. */
  user_memory_string_unpin (file_ptr);
  return success;
}

static int syscall_open (const char *file)
{
  char *file_ptr = *(char **) file;
  if (!user_memory_access_string_is_valid (file_ptr))
    {
      syscall_exit (DEFAULT_ERR_EXIT_CODE);
    }

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
   is not thread safe. */
  lock_acquire (&filesys_lock);
  struct file *opened_file = filesys_open (file_ptr);
  lock_release (&filesys_lock);

  /* Attempt to add to the thread's hashtable of file_nodes. */
  int fd = opened_file
           ? add_to_hash_table_of_file_nodes (opened_file)
           : DEFAULT_ERR_EXIT_CODE;

  /* Remember to unpin the page after we are done with it. */
  user_memory_string_unpin (file_ptr);
  return fd;
}

static int syscall_filesize (int fd)
{
  /* File_node_lookup only checks a thread's own hashtable, so there is no
     need to synchronize here.*/
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      return DEFAULT_ERR_EXIT_CODE;
    }

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
     is not thread safe. */
  lock_acquire (&filesys_lock);
  int length = file_length (file_node->file);
  lock_release (&filesys_lock);

  return length;
}

static int syscall_read (int fd, void *buffer, unsigned length)
{
  if (length == 0) {
      return 0;
    }

  char *buffer_ptr = *(char **) (buffer);
  struct file_node *file_node = file_node_lookup (fd);

  /* Attempts to pre-load the whole buffer into memory and pins the frame
     it holds. This is done in user_memory_access_buffer_is_valid, so that
     when we enter the Pintos filesystem, no other threads can try to evict
     the page we are writing to, causing a page fault while we still have the
     file system lock. */
  if (!user_memory_access_is_valid (buffer_ptr)
      || file_node == NULL
      || !user_memory_access_buffer_is_valid (buffer_ptr, length, false))
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

  /* Remember to unpin ALL the pages/frames we have pinned earlier. */
  user_memory_buffer_unpin (buffer_ptr, length);
  return read_length;
}

int syscall_write (int fd, const void *buffer, unsigned length)
{
  char *buffer_ptr = *(char **) (buffer);

  if (length == 0) {
    return 0;
  }

  /* Similar to syscall_read, we want to pre-load the pages in the buffer
     and pin the frames they are on, so that no other processes can evict the
     frame we are reading from, while we are in the pintos filesystem.*/
  if (!user_memory_access_is_valid (buffer_ptr)
      || !user_memory_access_buffer_is_valid (buffer_ptr, length, true))
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

  /* Remember to unpin ALL the pages/frames we have pinned earlier. */
  user_memory_buffer_unpin (buffer_ptr, length);
  return bytes_written;
}

void syscall_seek (int fd, unsigned position)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
    }

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
     is not thread safe. */
  lock_acquire (&filesys_lock);
  file_seek (file_node->file, position);
  lock_release (&filesys_lock);
}

unsigned syscall_tell (int fd)
{
  struct file_node *file_node = file_node_lookup (fd);
  if (file_node == NULL)
    {
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
      NOT_REACHED()
    }

  /* Ensure exclusive access to the filesystem, since the pintos filesystem
     is not thread safe. */
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
  /* If a file_node is still being used by a memory map, we don't
     free the file node just yet. */
}

static mapid_t syscall_mmap (int fd, void *addr)
{
  return memory_map (fd, addr);
}

void syscall_munmap (mapid_t mapping)
{
  if (!memory_unmap (mapping))
    {
      process_exit_with_code (DEFAULT_ERR_EXIT_CODE);
    }
}

/* ---------------- MEMORY CHECK FUNCTIONS ---------------- */

/* Check that user pointer is not a kernel addr. and not null. */
static bool
user_memory_access_is_valid (void *user_ptr)
{
  bool success = user_ptr != NULL && is_user_vaddr (user_ptr);

  /* Attempt to pin page after faulting in the page. */
  if (success && get_user ((uint8_t *) user_ptr) != -1)
    {
      frame_change_pinned (user_ptr, true);
    }
  return success;
}

/* Go through the whole buffer, and pre-load the pages by faulting them in one
   by one. This ensures that whenever a syscall is attempt to use the buffer,
   the pages it uses will not be evicted, which could cause issues since we
   are still holding the filesys lock. */
static bool
user_memory_access_buffer_is_valid (void *user_ptr,
                                    int32_t length,
                                    bool read_only)
{
  bool success = user_memory_access_is_valid (pg_round_down (user_ptr) + length - 1);

  do
    {
      /* Attempt to pin each frame after get_user faults in the page */
      success = success &&
                (read_only || is_writable_segment (user_ptr + length)) &&
                get_user ((uint8_t *) user_ptr + length - 1) != -1;
      frame_change_pinned (user_ptr + length - 1, true);
      length -= PGSIZE;
    }
  while (success && length > 0);

  return success;
}

/* Check string to ensure that it is of length smaller than or equals
   to PGSIZE. Since this function calls user_memory_access_is_valid, it
   also pre-loads the page the file name is on and pins the frame. Ensure
   that user_memory_string_unpin is called at the end of the syscall. */
static bool
user_memory_access_string_is_valid (void *user_ptr)
{
  long string_length = strnlen (user_ptr, PGSIZE);
  return string_length < PGSIZE + 1
         && user_memory_access_is_valid (user_ptr)
         && user_memory_access_is_valid (user_ptr + string_length);
}

/* Check that the user pointer is either in the valid swap space (up to 8MB)
   or in the data segment. */
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

/* ---------------- Pinning functions, used in VM ----------------*/

/* Goes through all the pages the buffer resides on, unpinning them. */
static void
user_memory_buffer_unpin (void *user_ptr, int32_t length)
{
  ASSERT (user_ptr != NULL)

  do
    {
      ASSERT (pagedir_get_page (thread_current ()->pagedir, user_ptr) != NULL)
      frame_change_pinned (user_ptr + length - 1, false);
      length -= PGSIZE;
    }
  while (length > PGSIZE);
}

/* Unpins the page(s) a user string is stored on. Ensures that we are unpinning
   all the pages the string uses. */
static void
user_memory_string_unpin (void *user_ptr)
{
  long string_length = strnlen (user_ptr, PGSIZE);
  ASSERT (string_length < PGSIZE + 1)

  user_memory_buffer_unpin (user_ptr, string_length);
}