#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

// Method declarations
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct thread *get_child_thread (struct list *cur_children_list,
                                        tid_t child_tid);
static void free_children_list (struct list *children_list);

// File system global lock
extern struct lock filesys_lock;

// Carson drove here
/* Starts a new thread running a user program loaded from
   FILENAME. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created.
   Also adds the new thread to the children list. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *fn_copy2;
  char *save_ptr;
  tid_t new_child_thread_tid;
  struct thread *new_child_thread;

  // Make a copy of FILE_NAME.
  // Otherwise there's a race between the caller and load()
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  fn_copy2 = palloc_get_page (0);
  if (fn_copy2 == NULL)
    return TID_ERROR;
  strlcpy (fn_copy2, file_name, PGSIZE);

  // Get the first token of the command (executable name)
  char *exec_name = strtok_r (fn_copy2, " ", &save_ptr);

  // Check if the file exists or not
  lock_acquire (&filesys_lock);
  struct file *exec_file = filesys_open (exec_name);
  lock_release (&filesys_lock);
  if (exec_file == NULL)
    return TID_ERROR;
  
  // Create a new thread to execute FILE_NAME
  new_child_thread_tid = thread_create (exec_name, PRI_DEFAULT,
                                        start_process, fn_copy);
  sema_up (&thread_current ()->load_sema);

  // Free pages if invalid tid
  if (new_child_thread_tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      palloc_free_page (fn_copy2);
      return TID_ERROR;
    }
  else
    {
      enum intr_level old_level = intr_disable ();

      new_child_thread = get_thread (new_child_thread_tid);
      if (new_child_thread == NULL)
        return TID_ERROR;
        
      // Add the new child thread to the children list
      list_push_front (&thread_current ()->children_list,
                        &new_child_thread->child_elem);

      intr_set_level (old_level);
    }
    
  return new_child_thread_tid;
}
// End of Carson driving

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  // Store the load status and unblock the parent
  thread_current ()->load_status = success;
  sema_up (&thread_current ()->load_sema);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

// Carson drove here
/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct list *cur_children_list = &thread_current ()->children_list;
  struct thread *child_thread;
  int exit_status;

  // Get the child thread from the children list using its tid
  child_thread = get_child_thread (cur_children_list, child_tid);
  // If the tid was not found in the list or if it was not a child of the
  // calling process, return -1
  if (child_thread == NULL)
    return -1;
  
  child_thread->is_waited_on = true;
  // The child will be killed soon, so we can remove it from the children list
  list_remove (&child_thread->child_elem);

  // Parent thread must wait for the child
  sema_down (&child_thread->child_sema);

  // Save exit status before child unblocks and frees
  exit_status = child_thread->exit_status;
  sema_up (&child_thread->exit_sema);
  return exit_status;
}
// End of Carson driving

// Carson drove here
/* Iterates through the children list, searching for the corresponding thread
   of child_tid and returning a pointer to it.
   Returns NULL if not found. */
static struct thread *
get_child_thread (struct list *children_list, tid_t child_tid)
{
  struct list_elem *temp;

  if (list_empty (children_list))
    return NULL;

  for (temp = list_begin (children_list);
      temp != list_end (children_list); temp = list_next (temp))
    {
      struct thread *t = list_entry (temp, struct thread, child_elem);
      // If the tid of the thread we're on matches child_tid, return it
      if (t->tid == child_tid)
        return t;
    }
  return NULL;
}
// End of Carson driving

// Carson and Charles drove here
/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int i;

  if (cur->executable_file != NULL)
    {
      lock_acquire (&filesys_lock);
      file_close (cur->executable_file);
      lock_release (&filesys_lock);
    }
  
  for (i = 2; i < 128; i++)
    {
      if (cur->fd_table[i] != NULL)
        {
          struct file *fd_file = cur->fd_table[i];
          lock_acquire(&filesys_lock);
          file_close (fd_file);
          lock_release(&filesys_lock);
        }
    }

  // Signal parent thread to stop waiting since the child thread is killed
  sema_up (&cur->child_sema);
  // If the current thread needs to be waited on, block before freeing so
  // the parent can still get its exit status
  if (&cur->is_waited_on)
    sema_down (&cur->exit_sema);

  free_children_list (&cur->children_list);
  page_table_deallocate (cur);

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
// End of Carson and Charles driving

// Carson drove here
/* Iterates through the children list, freeing each thread struct */
static void
free_children_list (struct list *children_list)
{
  struct list_elem *temp;

  if (list_empty (children_list))
    return;

  for (temp = list_begin (children_list);
      temp != list_end (children_list); temp = list_next (temp))
    {
      struct thread *t = list_entry (temp, struct thread, child_elem);
      // Remove this child from its children list
      list_remove (&t->child_elem);
      // Free the thread struct
      palloc_free_page (t);
    }
}
// End of Carson driving

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
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
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

static bool setup_stack (void **esp, int argc, char *argv[]);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static int parse_command (const char *cmd_line, char *argv[]);

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
  int argc;
  char **argv;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  hash_init (&t->page_table, &page_hash, &page_less, NULL);

  // Carson drove here
  // Parse the string copy of FILE_NAME to get the tokens
  // Limit the arguments to those that will fit in a single page (4 kB)
  argv = palloc_get_page (0);
  if (argv == NULL)
    return TID_ERROR;
  argc = parse_command (file_name, argv);
  // End of Carson driving

  lock_acquire (&filesys_lock);
  /* Open executable file. */
  file = filesys_open (argv[0]);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", argv[0]);
      goto done; 
    }
  lock_release(&filesys_lock);
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", argv[0]);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
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
    /* Set up stack. */
  if (!setup_stack(esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  if (success)
    {
      // Prevent writes to an open file
      thread_current ()->executable_file = file;
      file_deny_write (file);
    }
  else
    file_close (file);
  return success;
}

// Carson drove here
/* Uses the system call strtok_r() to parse file_name and store the
   tokens in the string array argv.
   Returns argc, the total number of tokens in file_name */
static int
parse_command (const char *file_name, char *argv[])
{
  char *cmd_line;
  char *save_ptr;
  const char *delimiter = " ";
  int argc = 0;
  // Make a copy of file_name
  cmd_line = palloc_get_page (0);
  if (cmd_line == NULL)
    return TID_ERROR;
  strlcpy (cmd_line, file_name, PGSIZE);
  // Get the first token of the command
  char *token = strtok_r (cmd_line, delimiter, &save_ptr);
  // Get and store the arguments of the command if any
  while (token)
    {
      argv[argc] = token;
      token = strtok_r (NULL, delimiter, &save_ptr);
      argc++;
    }
  return argc;
}
// End of Carson driving

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
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

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

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // Get a page of memory
      struct page_table_entry *page = page_allocate (upage, writable);
      if (page == NULL)
        return false;
      // Update page fields
      page->location = DISK;
      page->owner = thread_current();
      page->f_ptr = file;
      page->f_offset = ofs;
      page->read_bytes = page_read_bytes;
      // Advance bytes and offset
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, int argc, char *argv[]) 
{
  uint8_t *kpage;

  // Get a new page
  struct page_table_entry *page =
      page_allocate (((uint8_t *) PHYS_BASE) - PGSIZE, true);
  if (page == NULL)
    return false;
  struct frame_table_entry *free_frame = frame_allocate (page);
  kpage = page->kernel_addr;

  if (kpage != NULL) 
    {
      if (free_frame != NULL) 
        {
          // Carson drove here
          char *esp_copy;
          char *argv_addresses[argc];
          char **argv_start_address;
          int i;
          int data_size;

          // Stack starts at defined constant, create a copy for ease
          *esp = PHYS_BASE;
          esp_copy = (char *)(*esp);

          // Write each argument to the stack in reverse order
          for (i = argc - 1; i >= 0; i--)
            {
              data_size = sizeof (char) * (strlen (argv[i]) + 1);
              esp_copy -= data_size;
              memcpy (esp_copy, argv[i], data_size);
              argv_addresses[i] = esp_copy;
            }

          // Word-aligned accesses are faster than unaligned accesses, so
          // round the stack pointer down to a multiple of 4
          data_size = (uint8_t)(esp_copy) % 4;
          esp_copy -= data_size;

          // Push null pointer sentinel
          data_size = sizeof (char *);
          esp_copy -= data_size;
          // Write each address of argv to the stack in reverse order
          for (i = argc - 1; i >= 0; i--)
            {
              esp_copy -= data_size;
              memcpy (esp_copy, &argv_addresses[i], data_size);
            }

          // Push address of argv (argv[0])
          argv_start_address = (char **)(esp_copy);
          data_size = sizeof (char **);
          esp_copy -= data_size;
          memcpy (esp_copy, &argv_start_address, data_size);
          // Push argc
          data_size = sizeof (int);
          esp_copy -= data_size;
          *esp_copy = argc;
          // Push fake return address
          data_size = sizeof (void *);
          esp_copy -= data_size;

          // Reset stack pointer to our copy and free argv
          *esp = esp_copy;
          // End of Carson driving
        }
      else
        palloc_free_page (kpage);
    }
  palloc_free_page (argv);
  return true;
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
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
