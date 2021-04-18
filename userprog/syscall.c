#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "vm/page.h"
#include <stdio.h>
#include <syscall-nr.h>

// Process identifier
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

// Buffer and stack constants
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define MAX_BUFFER 300
#define PUSHA 32
#define MAX_ADDR 0x800000

// Method declarations
static void syscall_handler (struct intr_frame *);
static bool check_arguments (struct intr_frame *f, int num_args);
static void syscall_halt (void);
static pid_t syscall_exec (const char *cmd_line);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size, 
                         struct intr_frame *f);
static int syscall_write (int fd, const void *buffer, unsigned size);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static int syscall_write_helper (const void *buffer, unsigned size);
static struct file *syscall_index_helper (int fd);
static bool check_argument_pointer (void *ptr, void *esp); 
static void check_buffer (void *buffer, unsigned size);

// File system global lock
struct lock filesys_lock;

/* Initializes syscalls. */
void
syscall_init (void) 
{
  lock_init (&filesys_lock); 
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Carson drove here
/* Calls the corresponding system call depending on the syscode given.
   Checks the given pointers and stores the paramters using pointer arithmetic.
   Returns the results of the sytem call to the frame's eax register. Also 
   checks for valid pointers and if its correctly mapped.*/
static void
syscall_handler (struct intr_frame *f) 
{
  if (f == NULL)
    return;

  uint32_t *sys_code = (uint32_t *) (f->esp);
  check_argument_pointer (sys_code, f->esp);

  // Switch to handle which system call we are using
  switch (*sys_code) 
    {
      case SYS_HALT:
        {
          syscall_halt (); 
          break;
        }
      case SYS_EXIT:
        {
          check_arguments (f, 1);
          int status = *((int *)(f->esp) + 1);
          syscall_exit (status);
          break;
        }
      case SYS_EXEC:
        {
          check_arguments (f,1);
          const char *cmd_line = (const char *)(*((int *)(f->esp) + 1));
          check_argument_pointer (cmd_line, f->esp);
          f->eax = syscall_exec (cmd_line);
          break;
        }
      case SYS_WAIT:
        {
          check_arguments (f, 1);
          pid_t pid = *((pid_t *)(f->esp) + 1);
          f->eax = syscall_wait (pid);
          break;
        }
      case SYS_CREATE:
        {
          check_arguments (f, 2);
          const char *file = (const char *)(*((int *)(f->esp) + 1));
          unsigned initial_size = *((unsigned *)(f->esp) + 2);
          check_argument_pointer (file, f->esp);
          f->eax = syscall_create (file, initial_size);
          break;
        } 
      case SYS_REMOVE:
        {
          check_arguments (f, 1);
          const char *file = (const char *)(*((int *)(f->esp) + 1));
          check_argument_pointer (file, f->esp);
          f->eax = syscall_remove (file);
          break;
        } 
      case SYS_OPEN:
        {
          check_arguments (f, 1);
          const char *file = (const char *)(*((int *)(f->esp) + 1));
          check_argument_pointer (file, f->esp);
          f->eax = syscall_open (file);
          break;
        }
      case SYS_FILESIZE:
        {
          check_arguments (f, 1);
          int fd = *((int *)(f->esp) + 1);
          f->eax = syscall_filesize (fd);
          break;
        }
      case SYS_READ:
        {
          check_arguments (f, 3);
          int fd = *((int *)(f->esp) + 1);
          void *buffer = (void *)(*((int *)(f->esp) + 2));
          unsigned size = *((unsigned *)(f->esp) + 3);
          f->eax = syscall_read (fd, buffer, size, f);
          break;
        } 
      case SYS_WRITE:
        {
          check_arguments (f, 3);
          int fd = *((int *)(f->esp) + 1);
          const void *buffer = (const void *)(*((int *)(f->esp) + 2));
          unsigned size = *((unsigned *)(f->esp) + 3);
          check_argument_pointer (buffer, f->esp);
          f->eax = syscall_write (fd, buffer, size); 
          break;
        }
      case SYS_SEEK:
        {
          check_arguments (f, 2);
          int fd = *((int *)(f->esp) + 1);
          unsigned position = *((unsigned *)(f->esp) + 2);
          syscall_seek (fd, position);
          break;
        }
      case SYS_TELL:
        {
          check_arguments (f, 1);
          int fd = *((int *)(f->esp) + 1);
          f->eax = syscall_tell (fd); 
          break;
        }
      case SYS_CLOSE:
        {
          check_arguments (f, 1);
          int fd = *((int *)(f->esp) + 1);
          syscall_close (fd);
          break;
        }
      default:
        {
          // No corresponding syscall code
          syscall_exit(-1);
        }
    }
}
// End of Carson driving

// Carson drove here
/* Checks the validity of each argument pointer up to the 
   specified number of arguments. */
static bool 
check_arguments (struct intr_frame *f, int num_args) 
{
  int i;
  int *ptr;
  for (i = 0; i < num_args; i++)
   {
     // Pointer arithmetic to get the next pointer
     ptr = (int *)(f->esp) + (i + 1);
     // Check the validity of the pointer
     if (ptr == NULL || is_kernel_vaddr (ptr) ||
        pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
        syscall_exit (-1);
   }
}
// End of Carson driving

// Charles drove here
/* Checks if the ptr is a valid pointer. Ends the process if the pt
   is null, unmapped to virtual addr, or points to a physical space.
   Exits immediately in the event of an error. */
static bool
check_argument_pointer (void *ptr, void *esp) 
{
  // Check if ptr is valid or a kernel addr or esp is within bounds
  if (ptr == NULL || !is_user_vaddr (ptr) 
      || esp - ptr > PUSHA || esp > PHYS_BASE)
    syscall_exit (-1);
  
  // Check if it is mapped with curr thread
  void *pd = pagedir_get_page (thread_current ()->pagedir, ptr);
  if (pd == NULL)
    {
      // Check the page
      bool bound = pg_round_down (ptr) + MAX_ADDR >= PHYS_BASE
                    && esp <= ptr + PUSHA
                    && page_lookup (pg_round_down (ptr)) == NULL;
      
      // Get the page entry
      struct page_table_entry * entry = page_lookup (pg_round_down (ptr));

      // Allocate new page if it wasn't found and stack bounds are ok
      if (bound)
        entry = page_allocate (pg_round_down (ptr), true);

      // If the page was allocated successfully, load it into the frame
      if (entry)
        return frame_allocate (entry);
      else
        {
          syscall_exit (-1);
          return false;
        }
    }
  return true;
}
// End of Charles driving

/* Terminates Pintos by shutting it down */
static void
syscall_halt () 
{
  shutdown_power_off ();
}

// Carson drove here
/** Terminates the current running program and returns that status
 *  to the kernel. 
 *  @param: status - exit status of current thread
 *  @return: void
*/
void 
syscall_exit (int status) 
{
  // Store the relayed exit code in the current thread
  thread_current ()->exit_status = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}
// End of Carson driving

// Carson drove here
/** Runs the executable file given.
 *  Parent thread waits until it knows whether the child was loaded
 *  successfuly or not.
 *  @param: cmd_line - name of executable file
 *  @return: the new process's pid or -1 if the child load failed
*/
static pid_t syscall_exec (const char *cmd_line) 
{
  return process_execute (cmd_line);
}
// End of Carson driving

// Carson drove here
/** Parent thread waits for its child process until it finishes.
 *  @param: pid - program id of the child process
 *  @return: the child's exit status or -1 if waiting failed
*/
static int
syscall_wait (pid_t pid) 
{
  return process_wait (pid);
}
// End of Carson driving

// Eric drove here
/** Creates a new file.
 *  @param: file - new file
 *          initial_size - initial file size in bytes
 *  @return: true if successful, false otherwise
*/
static bool
syscall_create (const char *file, unsigned initial_size)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);

  return success;
}
// End of Eric driving

// Charles drove here
/** Deletes the given file.
 *  Removes it regardless of whether it is open or closed.
 *  Removing an open file does not close it.
 *  @param: file - file to be removed
 *  @return: true if successful, false otherwise
*/
static bool
syscall_remove (const char *file)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
          
  return success;
}
// End of Charles driving

// Charles and Eric drove here
/** Opens the given file.
 *  If successful, it adds the file if it is a valid one to a
 *  file descriptor array. Also increments the file descriptor index.
 *  @param: file - file to be opened 
 *  @return: nonnegative integer handle called a file descriptor or -1 if
 *           the file could not be opened
*/
static int
syscall_open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *open_file = filesys_open (file);
  lock_release(&filesys_lock);

  if (open_file == NULL)
    return -1;
  
  // Storing into the file array and incrementing fd for the next store
  thread_current ()->fd_table[thread_current ()->fd_index] = open_file;
  thread_current ()->fd_index++;

  return thread_current ()->fd_index - 1;
}
// End of Charles and Eric driving

// Charles drove here
/** Returns the size of the opened file.
 *  @param: fd - the index of the open file
 *  @return: the size, in bytes, of the open file
*/
static int
syscall_filesize (int fd)
{
  int length = 0;
  struct thread *current = thread_current ();
  struct file *file = syscall_index_helper (fd);

  if (file)
    {
      lock_acquire(&filesys_lock);
      length = file_length (file);
      lock_release(&filesys_lock);
    }
  return length;
}
// End of Charles driving

// Eric drove here
/** Reads a specified number of bytes from an open file into buffer.
 *  @param: fd - the index of the open file
 *          buffer - where it will be read to
 *          size - the number of bytes to be read
 *  @return: the number of bytes actually read (0 at end of file) or -1
 *           if the file could not be read
*/
static int syscall_read (int fd, void *buffer, 
                          unsigned size, struct intr_frame *f)
{
  uint8_t *buff;
  struct file *file;
  int i;
  
  check_buffer (buffer, size);

  int j = 0;
  for (; j < size; j++)
    {
      if(buffer + j == NULL || !is_user_vaddr (buffer + j)){
        return -1;
      }
      check_argument_pointer (buffer + j, f->esp);
    }

  // Reading from keyboard
  if (fd == 0)
    {
      buff = buffer;
      for (i = 0; i < size; i++)
        buff[i] = (char) input_getc ();
      return size;
    }
  else
    {
      // Finds the file and returns it 
      file = syscall_index_helper (fd);
      if (file != NULL)
        return file_read (file, buffer, size);
    }

  return 0;
}
// End of Eric driving

// Eric drove here
// Helper method to check if each page in the buffer is valid
static void
check_buffer (void *buffer, unsigned size)
{
  void *temp;
  // Check is buffer is in kernel
  if (buffer > PHYS_BASE)
    syscall_exit (-1);

  temp = buffer;
  struct page_table_entry *page = page_lookup (pg_round_down (temp));

  if (page && !page->is_writable)
    syscall_exit (-1);

  temp += PGSIZE;
  // Check the buffer pages to ensure they are read only
  while (temp < buffer + size)
    {
      page = page_lookup (pg_round_down (temp));
      // Checks for the existance of each page
      if (page != NULL && !page->is_writable)
        syscall_exit (-1);
      temp += PGSIZE;
    }
}
// End of Eric driving

// Charles drove here
/** Writes a specified number of bytes from an open file into buffer.
 *  @param: fd - the index of the open file
 *          buffer - where it will be written to
 *          size - the number of bytes to be written
 *  @return: the number of bytes actually written, which may be less than size
 *           if some bytes could not be written
*/
static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  int bytes_written = 0;

  if (fd == STDIN_FILENO)
    syscall_exit (-1);

  check_buffer (buffer, size);

  lock_acquire (&filesys_lock);

  // Standard output
  if (fd == STDOUT_FILENO)
    {
      // Checks if size is greater than MAX_BUFFER, if so break it down
      if (size > MAX_BUFFER)
        {
          lock_release (&filesys_lock);
          return syscall_write_helper (buffer,size);
        }
      putbuf (buffer, size);
      bytes_written += size;
      lock_release (&filesys_lock);
      return bytes_written;
    }

  struct file *fd_write = syscall_index_helper (fd);

  if (fd_write != NULL)
    bytes_written += file_write (fd_write, buffer, size);

  lock_release (&filesys_lock);
  return bytes_written;
}
// End of Charles driving

// Charles drove here
/* Helper function that writes to the buffer with size bytes.
   Returns the number of bytes written to the buffer. */
static int
syscall_write_helper (const void *buffer, unsigned size)
{
  int bytes_written = 0;

  // Breaks large sized bytes to max amount to the buffer per call
  while (size > MAX_BUFFER)
    {
      putbuf (buffer, MAX_BUFFER);
      size -= MAX_BUFFER;
      bytes_written += MAX_BUFFER;
    }
  putbuf (buffer, size); 
  bytes_written += size;

  return bytes_written;
}
// End of Charles driving

// Eric drove here
/** Changes the positon of the next byte to be read or written in an open file.
 *  @param: fd - the index of the open file
 *          position - position where the next byte will be read/written
 *  @return: void
*/
static void syscall_seek (int fd, unsigned position) {
  
  lock_acquire (&filesys_lock);
  struct file *fd_file = syscall_index_helper (fd);
  lock_release (&filesys_lock);

  lock_acquire (&filesys_lock);
  if (fd_file != NULL)
    {
      file_seek (fd_file, position);
      lock_release (&filesys_lock);
      return;
    }

  lock_release (&filesys_lock);
  syscall_exit (-1);
}
// End of Eric driving

// Charles drove here
/** Returns the positon of the next byte to be read or written in an open file.
 *  @param: fd - the index of the open file
 *          position - position where the next byte will be read/written
 *  @return: the positon of the next byte to be read or written in an open file
*/
static unsigned syscall_tell (int fd) 
{
  lock_acquire (&filesys_lock);
  struct file *fd_file = syscall_index_helper (fd);
  lock_release (&filesys_lock);

  lock_acquire (&filesys_lock);
  unsigned byte_offset = 0;
  
  if (fd_file != NULL)
    {
      byte_offset = file_tell (fd_file);
      lock_release (&filesys_lock);
      return byte_offset;
    }
  
  lock_release (&filesys_lock);
  return byte_offset;
}
// End of Charles driving

// Charles drove here
/** Closes the given file descriptor.
 *  @param: fd - the index of the file is on
 *  @return: void
*/
static void syscall_close (int fd) 
{
  lock_acquire (&filesys_lock);
  struct file *fd_close = syscall_index_helper (fd);
  if (fd_close != NULL)
    {
      file_close (fd_close);
      thread_current ()->fd_table[fd] = NULL;
    }

  lock_release (&filesys_lock);
}
// End of Charles driving

// Charles drove here
/* Traveres through the file descriptor table and tries to find a matching fd.
   Returns a pointer to that file if it does. */
static struct file *
syscall_index_helper (int fd)
{
  int i;
  struct file *fd_file = NULL;
  for (i = 2; i < 128; i++)
    {
      if (thread_current ()->fd_table[i] != NULL && i == fd)
        fd_file = thread_current ()->fd_table[i];
    }
  return fd_file;
}
// End of Charles driving
