#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#ifdef USERPROG
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "userprog/filesys_wrapper.h"
#include "vm/frame.h"
#include "vm/page.h"
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void free_frame (struct hash_elem *element, void *aux UNUSED);

/* Locates a process in process_hashtable given a pid. Must hold process_lock
  before calling this function. */
struct process *process_lookup (const int pid)
{
  ASSERT (lock_held_by_current_thread (&process_lock))
  struct process p;
  struct hash_elem *e;
  p.pid = pid;
  e = hash_find (&process_hashtable, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct process, hash_elem) : NULL;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    {
      return TID_ERROR;
    }

  struct process *p = malloc (sizeof (struct process));
  if (p == NULL)
    {
      return TID_ERROR;
    }

  sema_init (&p->exec_sema, 0);
  sema_init (&p->wait_sema, 0);
  p->pid = (pid_t) TID_ERROR; /* Use a 1-1 mapping of TID to PID. */
  p->exit_code = DEFAULT_EXIT_CODE;
  p->exec_file = NULL;
  p->parent_tid = DEFAULT_PARENT_TID;
  p->waited_on = false;

  lock_acquire (&process_lock);
  hash_insert (&process_hashtable, &p->hash_elem);
  lock_release (&process_lock);

  /* We need to pass the pointer to the process struct from the current thread
     (parent thread) to the child thread. So reserve a space of 4 bytes at the
     top of the page "fn_copy" to store this information. Copy the rest of
     the file name and its arguments to the rest of the page. */
  memcpy (fn_copy, &p, sizeof (struct process **));
  strlcpy (
      fn_copy + sizeof (struct process **), file_name,
      PGSIZE - sizeof (struct process **));

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  /* Allocation of memory failed in thread_create. */
  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      lock_acquire (&process_lock);
      hash_delete (&process_hashtable, &p->hash_elem);
      free (p);
      lock_release (&process_lock);
      return TID_ERROR;
    }

  sema_down (&p->exec_sema);

  /* Process failed to load executable in load. */
  if (p->exit_code == EXIT_CODE_FAILED_LOAD)
    {
      palloc_free_page (fn_copy);
      lock_acquire (&process_lock);
      hash_delete (&process_hashtable, &p->hash_elem);
      free (p);
      lock_release (&process_lock);
      return TID_ERROR;
    }

  /* Executable successfully loaded. */
  list_push_back (&thread_current ()->child_processes_list, &p->list_elem);
  p->parent_tid = thread_current ()->tid;
  return tid;

}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *argv[MAX_NUMBER_OF_ARGS];
  void *argv_addr[MAX_NUMBER_OF_ARGS];
  /* Since file_name_ is a pointer to a page we passed in from the parent
     process, we need to decipher a pointer to the process passed in and the
     file name + arguments properly. Refer to process_execute for more info. */
  char *file_name = file_name_ + sizeof (struct process **);
  struct process *p = *(struct process **) file_name_;
  struct intr_frame if_;
  bool success;

/* Set pid of this process's to its tid. */
  lock_acquire (&process_lock);
  hash_delete (&process_hashtable, &p->hash_elem);
  p->pid = thread_current ()->tid;
  hash_insert (&process_hashtable, &p->hash_elem);
  lock_release (&process_lock);

  /*  Tokenize file_name and place into array argv */
  char *token, *save_ptr;
  int argc = 0;
  for (token = strtok_r (file_name, " ", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      argv[argc] = token;
      argc++;
    }

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  if (!success)
    {
      process_exit_with_code (TID_ERROR);
      NOT_REACHED()
    }

  /* Determine the longest possible string size we can accommodate into our
     stack based on how many arguments have been tokenized already, and
     how much more space we need to store the rest of the stack. Since this
     is floor division, we can be sure that arg_max will never overflow the
     stack. */
  long arg_max =
      (PGSIZE - (4
                 * sizeof (void *))    /* Reserve space for return address, argc, argv and null pointer sentinel */
       - (argc * sizeof (void *)) /* Reserve space for pointers to arguments. */
      ) / argc;

  /* Push arguments in reverse order, storing each address into argv_addr. */
  for (int i = argc - 1; i >= 0; --i)
    {
      if_.esp -= strlen (argv[i]) + 1;
      strlcpy (if_.esp, argv[i], arg_max);
      argv_addr[i] = if_.esp;
    }

  /* Push null pointer sentinel. */
  if_.esp -= sizeof (void *);
  memset (if_.esp, 0, sizeof (void *));

  /* Push pointers to arguments. */
  for (int j = argc - 1; j >= 0; --j)
    {
      if_.esp -= sizeof (void *);
      memcpy (if_.esp, &argv_addr[j], sizeof (void *));
    }

  /* Set up argv */
  void *old_esp = if_.esp;
  if_.esp -= sizeof (void *);
  memcpy (if_.esp, &old_esp, sizeof (void *));

  /* Set up argc */
  if_.esp -= sizeof (int);
  memcpy (if_.esp, &argc, sizeof (int));

  /* Fake return address */
  if_.esp -= sizeof (void *);
  memset (if_.esp, 0, sizeof (void *));

  palloc_free_page (file_name_);
  sema_up (&p->exec_sema);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  lock_acquire (&process_lock);
  struct process *p = process_lookup (child_tid);
  lock_release (&process_lock);
  if (p == NULL || p->parent_tid != thread_current ()->tid || p->waited_on)
    {
      return -1;
    }

  /* Child process exists in process_hashtable, so wait on it. */
  p->waited_on = true;

  /* Wait for child if it hasn't yet exited. */
  if (p->exit_code == DEFAULT_EXIT_CODE)
    {
      sema_down (&p->wait_sema);
    }
  int exit_code = p->exit_code;

  /* Child has successfully exited, so remove from process hashtable and
     child_processes_list then free memory. */
  lock_acquire (&process_lock);
  struct hash_elem *returned_hash = hash_delete (&process_hashtable, &p->hash_elem);
  ASSERT (returned_hash != NULL);
  list_remove (&p->list_elem);
  free (p);
  lock_release (&process_lock);

  return exit_code;
}

/* Release memory associated with child processes it has created. Must hold
   process_lock before calling this function. */
static void free_all_children_process (void)
{
  ASSERT (lock_held_by_current_thread (&process_lock));
  struct list_elem *e;
  struct process *p;
  struct hash_elem *returned_hash;
  struct list *child_list = &thread_current ()->child_processes_list;
  for (e = list_begin (child_list); e != list_end (child_list);)
    {
      p = list_entry (e, struct process, list_elem);
      returned_hash = hash_delete (&process_hashtable, &p->hash_elem);
      ASSERT (returned_hash != NULL);
      e = list_next (e);
      free (p);
    }
}

/* Free all its children processes, close all open files, destroy its hashtable
   of open files, and set its exit_code before calling thread_exit. */
void
process_exit_with_code (int exit_code)
{
  /* Print exit message. */
  char *name = thread_name ();
  char *token, *save_ptr;
  token = strtok_r (name, " ", &save_ptr);
  printf ("%s: exit(%d)\n", token, exit_code);

  /* Free all of its children processes in process hashtable. */
  lock_acquire (&process_lock);
  free_all_children_process ();

  /* Signal to parent process that this thread is done, provided that
     parent process has not already terminated and deleted this struct's
     entry in process_hashtable. */
  struct process *p = process_lookup (thread_current ()->tid);
  if (p != NULL)
    {
      p->exit_code = exit_code;

      if (p->exec_file == NULL)
        {
          /* Load failed. Signal to parent this has happened. */
          p->exit_code = EXIT_CODE_FAILED_LOAD;
        }
      /* Ensure that any processes waiting on this process is unblocked. */
      sema_up (&p->wait_sema);
      sema_up (&p->exec_sema);
    }
  lock_release (&process_lock);

  /* Close all files opened by this process and free hashtable memory. */
  lock_acquire (&filesys_lock);
  hash_destroy (&thread_current ()->hash_table_of_file_nodes, free_file_node);
  lock_release (&filesys_lock);

  /* Free all the frames used by this process. */
  lock_acquire (&frametable_lock);
  hash_destroy (&thread_current()->sup_pagetable, free_frame);
  lock_release (&frametable_lock);

  /* Ensure that no locks are still held by this process. */
  ASSERT (!lock_held_by_current_thread (&process_lock))
  ASSERT (!lock_held_by_current_thread (&filesys_lock))
  ASSERT (!lock_held_by_current_thread (&frametable_lock))
  thread_exit ();
}

static void free_frame (struct hash_elem *element, void *aux UNUSED)
{
  struct page_entry *entry = hash_entry (element,
                                         struct page_entry,
                                         spt_elem);
  if (entry->frame_ptr != NULL) {
    lock_acquire (&entry->frame_ptr->frame_lock);
    falloc_free_frame (entry->frame_ptr);
  }
  hash_delete (&thread_current()->sup_pagetable, element);
  free (entry);
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);


/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  lock_release (&filesys_lock);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  lock_acquire (&filesys_lock);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      lock_release (&filesys_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }
  lock_release (&filesys_lock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&filesys_lock);
      if (file_ofs < 0 || file_ofs > file_length (file))
        {
          lock_release (&filesys_lock);
          goto done;
        }

      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          lock_release (&filesys_lock);
          goto done;
        }
      lock_release (&filesys_lock);
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* Successfully loaded, so deny-write to its executable and add it to
     the current thread's hashtable of file nodes so that we can close
     the executable when the process finishes. */
  success = true;
  add_to_hash_table_of_file_nodes (file);
  lock_acquire (&filesys_lock);
  file_deny_write (file);
  lock_release (&filesys_lock);

  lock_acquire (&process_lock);
  struct process *p = process_lookup (thread_current ()->tid);
  lock_release (&process_lock);
  p->exec_file = file;

  done:
  /* We arrive here whether the load is successful or not.*/

  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  lock_acquire (&filesys_lock);
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    {
      lock_release (&filesys_lock);
      return false;
    }
  lock_release (&filesys_lock);

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  if (writable && thread_current ()->start_writable_segment_addr == 0)
    {
      thread_current ()->start_writable_segment_addr = upage;
      thread_current ()->end_writable_segment_addr =
          upage + read_bytes + zero_bytes;
    }

  /* Create an entry for every page we try to read, remembering to increment
     ofs so that we know where in the file we should read from. */
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (page_zero_bytes == PGSIZE)
        {
          add_to_sup_pagetable (upage, All_ZERO, file, ofs,
                                read_bytes, zero_bytes, writable);
        }
      else
        {
          struct page_entry *entry = sup_pagetable_entry_lookup (upage);
          if (entry != NULL)
            {
              /* Loading of segments onto same page, so update entry and
                 re-insert into supplemental page table. */
              ASSERT (entry->user_page_addr == upage)
              ASSERT (entry->file == file)
              ofs = MIN (ofs, entry->ofs);
              page_read_bytes = MAX(page_read_bytes, entry->read_bytes);
              page_zero_bytes = MIN(page_zero_bytes, entry->zero_bytes);
              writable = writable || entry->writable;
              free_sup_page_entry (&entry->spt_elem, NULL);
            }

          add_to_sup_pagetable (upage, FILE_SYSTEM, file, ofs,
                                page_read_bytes, page_zero_bytes, writable);
        }

      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  bool success = grow_stack (((uint8_t *) PHYS_BASE) - PGSIZE);

  if (success)
    {
      *esp = PHYS_BASE;
    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
