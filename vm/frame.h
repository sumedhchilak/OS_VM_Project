#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <string.h>
#include <stdbool.h>

// Everyone drove here
struct frame_table_entry
	{
		void *kernel_addr;				  /* Kernel physical address */					
		struct page_table_entry *page;	  /* Corresponding page of frame */
	};
// End of everyone driving

// Method declarations
void frames_init (void);
struct frame_table_entry *frame_allocate (struct page_table_entry *page);
void frame_deallocate (struct frame_table_entry *frame);

#endif
