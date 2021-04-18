#include "swap.h"
#include "page.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/block.h"

// Swap global lock
struct lock swap_lock;
// Global swap bitmap
struct bitmap *swap_bitmap;

// Method declarations
static void block_io_request (bool io_flag, struct page_table_entry *page);
static void swap_free (struct page_table_entry *page);

// Charles and Sumedh drove here
/* Initializes the swap partition. */
void 
swap_init ()
{
  struct block *swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    return;
  
  // Generate metadata, bitmap, and lock
  size_t num_sectors = block_size (swap_block);
  swap_bitmap = bitmap_create (num_sectors);
  lock_init (&swap_lock);
}
// End of Charles and Sumedh driving

// Eric and Sumedh drove here
/* Takes a page and writes it out to the swap.
   The number of used blocks is determined by the pagesize.
   Finds a contiguous region to write the page data to.
   Updates the page metadata to reflect changes in swap.
   Returns the index of the first bit in the valid region. */
int 
swap_write (struct frame_table_entry *frame)
{ 
  struct block *swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    return -1;

  // Finds a valid and contiguous region to write to
  lock_acquire (&swap_lock);
  size_t valid_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  lock_release (&swap_lock);

  // Accounts for BITMAP_ERROR
  if (valid_index == BITMAP_ERROR)
    {
      ASSERT (1 == 2);
    }

  // Updates to metadata, reflect changes to swap
  struct page_table_entry *page = frame->page;
  page->location = SWAP;
  page->swap_index = valid_index * SIZE_SECTOR;
 
  // Write to swap here
  block_io_request (0, page);

  return valid_index;
}
// End of Eric and Sumedh driving

// Eric and Sumedh drove here
/* Reads blocks from the swap partition back into a free-frame.
   Updates page metadata to reflect that it is in physical memory. */
int
swap_read (struct frame_table_entry *new_frame)
{
  int success = 0;
  struct page_table_entry *page = new_frame->page;
  // Reads a sector, updates bitmap accordingly
  block_io_request (1, page);
  swap_free (page);
  page->location = FRAME;
  success = 1;

  // Updated metadata correctly
  return success;
}
// End of Eric and Sumedh driving

// Sumedh and Carson drove here
/* Frees the blocks of a page read back from swap.
   Updates the bitmap values to reflect metadata changes. */
static void
swap_free (struct page_table_entry *page)
{
  lock_acquire (&swap_lock);
  size_t index = page->swap_index / SIZE_SECTOR;
  bitmap_reset (swap_bitmap, index); 
  lock_release (&swap_lock);
}
// End of Sumedh and Carson driving

// Charles and Sumedh drove here
/* Helper method that reads XOR writes a set amount of blocks. 
   Read/write is determined on the parameter passed into it.
   io_flag determines read/write based on constants defined. */
static void 
block_io_request (bool io_flag, struct page_table_entry *page)
{
  char *ptr = (char *) page->kernel_addr;
  struct block *swap_block;
  int i = 0;

  // Iteration of blocks, single block in each pass
  while (i < SIZE_SECTOR)
  {
    swap_block = block_get_role (BLOCK_SWAP);

    // Reading/writing swap partition
    if (io_flag == WRITE_FLAG)
      block_write (swap_block, page->swap_index + i, ptr);
    if (io_flag == READ_FLAG)
      block_read (swap_block, page->swap_index + i, ptr);

    ptr += BLOCK_SECTOR_SIZE;
    i++;
  }
}
// End of Charles and Sumedh driving
