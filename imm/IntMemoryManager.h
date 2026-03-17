/* IntMemoryManager.h
* Copyright © 2026 Aleksandr Silaev.
* This file is part of the Int Memory Manager library.
* The Int Memory Manager library is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*/

#ifndef INT_MEMORY_MANAGER_H
#define INT_MEMORY_MANAGER_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#define BLOCK_SIZE sizeof (IntMemoryRange)
#define ALIGNMENT 16 // Align by 16 bytes for better performance
#define IMM_HEX 0x494D4D52

typedef struct int_memory_range {
    uint32_t hex; // compare a word in hex (IMM_HEX equals IIMR), some 'Tag'
    size_t size; // Size of the memory block
    int free; // Flag to indicate if the block is free (1) or allocated (0)
    struct int_memory_range* next; // Pointer to the next memory block in the linked list
    struct int_memory_range* prev; // Pointer to the previous memory block in the linked list
    void* ptr; // Pointer to the actual memory block allocated for user data
} IntMemoryRange;

void *MemoryAllocate (size_t size);
void cleanbit (void *ptr);
void *MemoryReAllocate (void *ptr, size_t size);

#endif
