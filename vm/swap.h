#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "frame.h"
#include <stdbool.h>
#include <bitmap.h>

// Block and read/write constants
#define WRITE_FLAG 0
#define READ_FLAG 1
#define SIZE_SECTOR (PGSIZE / BLOCK_SECTOR_SIZE)

// Method declarations
void swap_init (void);
int swap_write (struct frame_table_entry *frame);
int swap_read (struct frame_table_entry *new_frame);

#endif
