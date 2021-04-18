#include "page.h"
#include "frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

// Stack constants
#define PUSHA 32
#define MAX_ADDR 0x800000

// Method declarations
static void set_struct_fields (struct page_table_entry *page,
                               const void *user_page, bool writable);
static int page_retrieve_swap (struct page_table_entry *page);
static int page_retrieve_filesys (struct page_table_entry *page);
static int page_growth_handler_helper (struct page_table_entry *page, 
                                       void *user_page, void *fault_addr,
                                       void *esp);

// Sumedh and Carson drove here 
/* Allocates a new page table entry in the page table. */
struct page_table_entry *
page_allocate (const void *user_page, bool writable)
{
  struct hash *page_table;
  struct hash_elem *e;

  struct page_table_entry *page = malloc (sizeof (struct page_table_entry));
  if (page == NULL) 
    return NULL;
  set_struct_fields (page, user_page, writable);
  
  page_table = &page->owner->page_table;
  e = &page->hash_elem;
  // Insert the hash so that it can be used in page_lookup ()
  if (hash_insert (page_table, e) != NULL)
    {
      e = hash_insert (page_table, e);
      free (page);
      page = hash_entry (e, struct page_table_entry, hash_elem);;
    }

  return page;
}
// End of Sumedh and Carson driving

// Helper method for setting a page's metadata
static void
set_struct_fields (struct page_table_entry *page,
                   const void *user_page, bool writable)
{
  // Set page fields
  page->location = FRAME;
  page->user_addr = pg_round_down (user_page);
  page->owner = thread_current ();
  page->is_writable = writable;
  page->kernel_addr = NULL;
  // Set file fields
  page->frame = NULL;
  page->f_ptr = NULL;
  page->read_bytes = 0;
  page->f_offset = 0;
  // Set swap field
  page->swap_index = -1;
}

// Code adapted from Pintos project page
/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p, void *aux UNUSED)
{
  const struct page_table_entry *page = 
      hash_entry (p, struct page_table_entry, hash_elem);

  return hash_bytes (&page->user_addr, sizeof page->user_addr);
}

// Code adapted from Pintos project page
/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a, const struct hash_elem *b, 
          void *aux UNUSED)
{
  const struct  page_table_entry *x = 
      hash_entry (a, struct page_table_entry, hash_elem);

  const struct page_table_entry *y = 
      hash_entry (b, struct page_table_entry, hash_elem);

  return x->user_addr < y->user_addr;
}

// Code adapted from Pintos project page
/* Returns the page containing the given virtual address,
   or NULL if no such page exists. */
struct page_table_entry *
page_lookup (const void *addr)
{
  struct page_table_entry p;
  struct hash_elem *e;

  p.user_addr = (void *) addr;
      e = hash_find (&thread_current ()->page_table, &p.hash_elem);
  
  if (e != NULL)
    return hash_entry (e, struct page_table_entry, hash_elem);
  else
    return NULL;
}

// Sumedh and Carson drove here 
/* Destroys the page table. */
void
page_table_deallocate (struct thread *curr)
{
  hash_destroy (&curr->page_table, &page_deallocate);
}
// End of Sumedh and Carson driving

// Sumedh and Carson drove here
/* Destroys a single page. */
void 
page_deallocate (struct hash_elem *e, void *aux UNUSED)
{
  struct page_table_entry *p =
      hash_entry (e, struct page_table_entry, hash_elem);

  if (p == NULL)
    return;

  // If the page is in memory, evict it
  if (p->frame)
    frame_deallocate (p->frame);

  free ((void *) p);
}
// End of Sumedh and Carson driving

// Eric and Sumedh drove here
/* Helper method for page growth handler, checks bounds before anything else */
static int 
page_growth_handler_helper (struct page_table_entry *page, 
void *user_page, void *fault_addr, void *esp)
{
  int status_flag = 0;

  int esp_overflow = esp > PHYS_BASE;
  int fault_overflow = PUSHA < esp - fault_addr;

  /* Return -1 as the status of the bound check */
  if (esp_overflow || fault_overflow)
    {
      status_flag = -1;
      return status_flag;
    }

  bool growth_overflow = (PHYS_BASE - MAX_ADDR < user_page) 
                          && (esp - fault_addr < PUSHA);
  if  (growth_overflow)
    {
      status_flag = 1;
      return status_flag;
    }
    
  return status_flag;
}
// End of Sumedh and eric driving

// Sumedh and Eric drove here
/* Handles when stack growth happens. It will try to find where the page is
   and handle it accordingly. */
int
page_growth_handler (struct page_table_entry *page,
                     void *user_page, void *fault_addr, void *esp)
{ 
  int status_flag = 
  page_growth_handler_helper(page, user_page, fault_addr, esp);

  /* Return immediately if bounds are not met for growth */
  if (status_flag == -1)
    {
      return status_flag;
    }
  /* Allocate if growth necessary */
  if (status_flag == 1)
    {
      page = page_allocate (user_page, true);
    }
  
  /* If neither conditions are met, DO NOTHING */
  if(status_flag == 0 || status_flag == 1){
    status_flag = -1;
  }

  // Find the page and load it into frame if found in SWAP/DISK/FRAME
  if (page != NULL)
    {
      switch (page->location)
        {
          // If the page is on swap, retrieve it
          case SWAP:
            {
              return page_retrieve_swap (page);
            }
          // If the page is on disk, retrieve it
          case DISK:
            {
              return page_retrieve_filesys (page);
            }
          default:
            {
              struct frame_table_entry *free_frame = frame_allocate (page);
              if (free_frame == NULL)
                return status_flag;
            }
        }
      return 1;
    }
  return 0;
}
// End of Eric and Sumedh driving

// Charles drove here
// Page is found in the SWAP location and now will be loaded into frame
static int
page_retrieve_swap (struct page_table_entry *page)
{
  int status_flag = -1;

  // Frame alloc is able to handle all cases
  struct frame_table_entry *free_frame = frame_allocate (page);
  if (free_frame == NULL)
    return status_flag;

  status_flag = 1;
  return status_flag;
}
// End of Charles driving

// Charles drove here
// Page is found in DISK location and now will be loaded into frame
static int
page_retrieve_filesys (struct page_table_entry *page)
{
  int status_flag = -1;
  
  // Frame alloc is able to handle all cas
  struct frame_table_entry *free_frame = frame_allocate (page);
  if (free_frame == NULL)
    return status_flag;

  status_flag = 1;
  return status_flag;
}
// End of Charles driving
