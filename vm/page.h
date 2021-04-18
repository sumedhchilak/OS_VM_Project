#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdlib.h>
#include <stdbool.h>
#include <hash.h>

// Carson and Eric drove here
enum page_location
  {
    FRAME,
    SWAP,
    DISK
  };
// End of Carson and Eric driving

// Everyone drove here
struct page_table_entry 
  {
    struct hash_elem hash_elem;       /* Page hash element */
    enum page_location location;      /* Location of the page */
    struct frame_table_entry *frame;	/* Corresponding frame of page */
    struct thread *owner;				      /* Corresponding thread of page */
    void *user_addr;							    /* User virtual address */
    void *kernel_addr;						    /* Kernel physical address */
    
    bool is_writable;						      /* Page writable state */
    struct file *f_ptr;					      /* Pointer to file */
    size_t f_offset;						      /* File read offset */
    size_t read_bytes; 					    	/* File num bytes read */
    
    size_t swap_index;                /* Index of page if swapped */
  };


// Method declarations
struct page_table_entry *page_allocate (const void *user_page, bool writable);
unsigned page_hash (const struct hash_elem *p, void *aux);
bool page_less (const struct hash_elem *a,
                const struct hash_elem *b, void *aux);
struct page_table_entry *page_lookup (const void *addr);
void page_table_deallocate (struct thread *curr);
void page_deallocate (struct hash_elem *e, void *aux);
int page_growth_handler(struct page_table_entry *page, void *user_page,
                        void *fault_addr, void *esp);
 // End of everyone driving
#endif
