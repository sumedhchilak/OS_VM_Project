#include "frame.h"
#include "page.h"
#include "swap.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/file.h"

// Total available user memory size (number of frames available)
extern int user_mem_size;
// File system global lock
extern struct lock filesys_lock;
// Frame table global lock
struct lock frame_table_lock;
// Frame table global array
struct frame_table_entry *frame_table_array;
// Stores the next frame index for the clock PRA
int clock_index;

// Method declarations
static int load_swap (struct frame_table_entry *new_frame);
static void load_disk (struct page_table_entry *page);

// Sumedh and Carson drove here
/* Initializes the all available physical, user memory frames
   and global variables. */
void
frames_init ()
{
  int i;
  clock_index = 0;

  lock_init (&frame_table_lock);
  lock_acquire (&frame_table_lock);

  // Initialize the frames array using the total user pool size
  frame_table_array = 
      malloc (sizeof (struct frame_table_entry) * user_mem_size);
  if (frame_table_array == NULL)
    syscall_exit (-1);

  // Allocates all the available frames
  for (i = 0; i < user_mem_size; i++)
    {
      frame_table_array[i].kernel_addr = palloc_get_page (PAL_USER);
      frame_table_array[i].page = NULL;
    }
  
  lock_release (&frame_table_lock);
}
// End of Sumedh and Carson driving

// Sumedh and Carson drove here
/* Loads the frame (from swap or disk) and its corresponding page into memory.
   If all the frames are full, it uses a clock PRA to evict a frame. */
struct frame_table_entry *
frame_allocate (struct page_table_entry *page)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *new_frame = NULL;
  // Iterates through the frames array to find the first free frame
  int i = 0;
  while (i < user_mem_size)
    {
      // If there is no page mapped to this frame, we know it is free
      if (frame_table_array[i].page == NULL)
        {
          new_frame = &frame_table_array[i];
          break;
        }
      i++;
    }
  lock_release (&frame_table_lock);

  // If all the frames were in use, use a clock PRA to evict a frame
  if (i == user_mem_size)
    {
      lock_acquire (&frame_table_lock);
      
      bool found = false;
      // For the clock PRA, we loop through the the entire frames array
      // (starting at the clock index) for a maximum of 2 times
      i = 0;
      for (; i < (user_mem_size * 2) && !found; i++)
        {
          // Get the current frame and page table entry
          struct frame_table_entry *f = &frame_table_array[clock_index];
          struct page_table_entry *entry = f->page;
          // Check if the current page has been referenced recently,
          // if so, set it to not referenced
          if (pagedir_is_accessed (entry->owner->pagedir, page->user_addr))
            pagedir_set_accessed (entry->owner->pagedir,
                                  page->user_addr, false);
          // The current page has not been referenced,
          // so we found the frame to evict
          else
            {
              new_frame = &frame_table_array[clock_index];
              found = true;
            }
          // Advance the clock index to the next frame
          if (clock_index == user_mem_size - 1)
            clock_index = 0;
          else
            clock_index++;
        }

      lock_release (&frame_table_lock);
      frame_deallocate (new_frame);
    }

  // Assign the page to the new frame and vice versa
  page->frame = new_frame;
  new_frame->page = page;
  page->kernel_addr = new_frame->kernel_addr;

  bool swapped = false;
  switch (page->location)
    {
      // If the page is on swap, load it back in
      case SWAP:
        {
          if (load_swap (new_frame) == 1)
            swapped = true;
          break;
        }
      // If the page is on disk, load it back in
      case DISK:
        {
          load_disk (page);
          break;
        }
      // We require a zero page in an error
      default:
        {
          memset (page->kernel_addr, 0, PGSIZE);
        }
    }

  // Set the page in main memory
  pagedir_set_page (page->owner->pagedir, page->user_addr,
                    page->kernel_addr, page->is_writable);

  // If the page was in swap, set it as dirty
  if (swapped)
    pagedir_set_dirty (page->owner->pagedir, page->user_addr, true);
  
  return new_frame;
}
// End of Sumedh and Carson driving

// Sumedh and Carson drove here
// Helper method to load a page in from swap and returns true
static int
load_swap (struct frame_table_entry *new_frame)
{
  lock_acquire (&frame_table_lock);
  int success = swap_read (new_frame);
  lock_release (&frame_table_lock);
  return success;
}
// End of Sumedh and Carson driving

// Sumedh and Carson drove here
// Helper method to load a page in from disk
static void
load_disk (struct page_table_entry *page)
{
  lock_acquire (&frame_table_lock);
  lock_acquire (&filesys_lock);
  // Seek and read the page's file using its offset and read bytes
  file_seek (page->f_ptr, page->f_offset);
  file_read (page->f_ptr, page->kernel_addr, page->read_bytes);
  lock_release (&filesys_lock);
  memset (page->kernel_addr + page->read_bytes, 0, PGSIZE - page->read_bytes);
  lock_release (&frame_table_lock);
}
// End of Sumedh and Carson driving

// Sumedh and Carson drove here
/* Evicts the given frame from main memory */
void 
frame_deallocate (struct frame_table_entry *frame)
{
  struct page_table_entry *page = frame->page;

  // If the page is dirty/modified, write it to swap
  if (pagedir_is_dirty (page->owner->pagedir, page->user_addr)) 
    {
      lock_acquire (&frame_table_lock);
      int valid_index = swap_write (frame);

      if (valid_index < 0)
        return;

      lock_release (&frame_table_lock);
    }

  lock_acquire (&frame_table_lock);
  // Clear the page's pagedir
  pagedir_clear_page (page->owner->pagedir, page->user_addr);
  lock_release (&frame_table_lock);
  
  // Set the frame to NULL so we know it's empty
  frame->page = NULL;
}
// End of Sumedh and Carson driving
