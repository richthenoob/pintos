#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* System call numbers. */
enum 
  {
    /* Tasks 2 and later. */
    /* One argument syscalls */
    SYS_HALT,                   /* Halt the operating system. */
    SYS_EXIT,                   /* Terminate this process. */
    SYS_EXEC,                   /* Start another process. */
    SYS_WAIT,                   /* Wait for a child process to die. */
    SYS_REMOVE,                 /* Delete a file. */
    SYS_OPEN,                   /* Open a file. */
    SYS_FILESIZE,               /* Obtain a file's size. */
    SYS_TELL,                   /* Report current position in a file. */
    SYS_CLOSE,                  /* Close a file. */
    SYS_MUNMAP,                 /* Remove a memory mapping. */

  /* Two argument syscalls */
    SYS_CREATE,                 /* Create a file. */
    SYS_SEEK,                   /* Change position in a file. */
    SYS_MMAP,                   /* Map a file into memory. */

  /* Three argument syscalls */
    SYS_READ,                   /* Read from a file. */
    SYS_WRITE,                  /* Write to a file. */

    /* Task 4 only. */
    SYS_CHDIR,                  /* Change the current directory. */
    SYS_MKDIR,                  /* Create a directory. */
    SYS_READDIR,                /* Reads a directory entry. */
    SYS_ISDIR,                  /* Tests if a fd represents a directory. */
    SYS_INUMBER                 /* Returns the inode number for a fd. */
  };

#endif /* lib/syscall-nr.h */
