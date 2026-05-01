/* IntMemoryManager.c
* Copyright © 2026 Aleksandr Silaev
* This file is part of the Int Memory Manager library.
* The Int Memory Manager library is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*/

#include "IntMemoryManager.h"
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static size_t global_required_size = 100 * 1024 * 1024; // By default 100MB
static IntMemoryRange *base = NULL; // base of the linked list of memory blocks
static pthread_mutex_t imm_lock = PTHREAD_MUTEX_INITIALIZER;

static void *ar_start = NULL;

static IntMemoryPool *_create_pool_structure (size_t size)
{
  void *region = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (!region) return NULL;

  IntMemoryPool *pool = (IntMemoryPool *)malloc (sizeof (IntMemoryPool));
  if (!pool)
  {
    munmap (region, size);
    return NULL;
  }
  pool->base = (IntMemoryRange *)region;

  pool->total_size = size;
  pthread_mutex_init (&pool->lock, NULL);

  pool->base->size = size - BLOCK_SIZE;
  pool->base->free = 1;
  pool->base->hex = IMM_HEX;
  pool->base->next = NULL;
  pool->base->prev = NULL;
  pool->base->ptr = (void *)(pool->base + 1);

  return pool;
}

void MemoryRequire (size_t bytes)
{
  if (base == NULL)
  {
    global_required_size = bytes;
  }
}

void MemoryRequireKB (size_t kilobytes)
{
  MemoryRequire (kilobytes * 1024);
}

IntMemoryPool *MemoryPoolCreate (size_t size)
{
  return _create_pool_structure (size);
}

void MemoryPoolCorrupt (IntMemoryPool *pool)
{
  if (!pool) return;
  pthread_mutex_lock (&pool->lock);
  munmap (pool->base, pool->total_size);
  pthread_mutex_unlock (&pool->lock);
  pthread_mutex_destroy (&pool->lock);
  free (pool);
}

void MemoryPoolAdd (IntMemoryPool *pool, size_t size)
{
  if (!pool) return;

  pthread_mutex_lock (&pool->lock);

  void *region = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region != MAP_FAILED)
  {
    IntMemoryRange *nblock = (IntMemoryRange *)region;
    nblock->size           = size - BLOCK_SIZE;
    nblock->free           = 1;
    nblock->hex            = IMM_HEX;
    nblock->ptr            = (void *)(nblock + 1);
    nblock->prev           = NULL;
    nblock->next           = pool->base;
    if (pool->base) pool->base->prev = nblock;
    pool->base             = nblock;
    pool->total_size       += size;

  }
  pthread_mutex_unlock (&pool->lock);
}

static int imm_init()
{
  if (base != NULL) return 0;

  base  = mmap (NULL, global_required_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) return -1;

  base->size = global_required_size - BLOCK_SIZE;
  base->free = 1;
  base->hex = IMM_HEX;
  base->next = NULL;
  base->prev = NULL;
  base->ptr = (void *)(base + 1);

  return 0;
}

IntMemoryRange *find_free_block_of_memory (IntMemoryRange **last, size_t size)
{
    IntMemoryRange *cur = base;

    while (cur && !(cur->free && cur->size >= size)) {
        if (last) *last = cur;
        cur = cur->next;
    }
    return cur;
}

static void *_internal_MemoryAllocate (size_t size)
{
    if (size <= 0) return NULL;
    if (imm_init() != 0) return NULL;

    size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

    IntMemoryRange *last = NULL;
    IntMemoryRange *block = find_free_block_of_memory (&last, size);

    if (block) {
        if (block->size >= size + BLOCK_SIZE + ALIGNMENT) {
          IntMemoryRange *nblock = (IntMemoryRange *)((char *)block->ptr + size);

          nblock->hex = IMM_HEX;
          nblock->size = block->size - size - BLOCK_SIZE;
          nblock->free = 1;
          nblock->next = block->next;
          nblock->prev = block;
          nblock->ptr = (void*)(nblock + 1);

          if (block->next) block->next->prev = nblock;
          block->next = nblock;
          block->size = size;
        }
        block->free = 0;
        return block->ptr;
    }
  return NULL;
}

void *MemoryAllocate (size_t size) {
    pthread_mutex_lock(&imm_lock);
    void *ptr = _internal_MemoryAllocate(size);
    pthread_mutex_unlock(&imm_lock);
    return ptr;
}

static void _internal_coalesce (IntMemoryRange *block)
{
  if (!block || !block->free || block->hex != IMM_HEX) return;

  if (block->next) {
      if (block->next->hex == IMM_HEX && block->next->free) {
        IntMemoryRange *nblock = block->next;
        block->size += BLOCK_SIZE + nblock->size;
        block->next = nblock->next;
        if (block->next) block->next->prev = block;
      }
  }

  if (block->prev) {
    if (block->prev->hex == IMM_HEX && block->prev->free) {
      IntMemoryRange *pblock = block->prev;
      pblock->size += BLOCK_SIZE + block->size;
      pblock->next = block->next;
      if (block->next) block->next->prev = pblock;
    }
  }
}

void _internal_cleanbit (void *ptr)
{
    if (!ptr) return;

    IntMemoryRange *block = (IntMemoryRange *)ptr - 1;

    if (block->hex != IMM_HEX) {
      return;
    }

    if ((uintptr_t)ptr < (uintptr_t)base + BLOCK_SIZE) return;

    if (block->free) return;

    block->free = 1;

    _internal_coalesce (block);
}

void cleanbit (void *ptr)
{
    if (!ptr) return;
    pthread_mutex_lock(&imm_lock);
    _internal_cleanbit(ptr);
    pthread_mutex_unlock(&imm_lock);
}

void *MemoryReAllocate (void   *ptr, size_t  size)
{
  if (!ptr) return MemoryAllocate (size);

  pthread_mutex_lock (&imm_lock);
  IntMemoryRange *oblock = (IntMemoryRange *)ptr - 1;
  if (oblock->hex != IMM_HEX) {
    pthread_mutex_unlock (&imm_lock);
    return NULL;
  }

  if (oblock->size >= size) {  // no enough memory
    pthread_mutex_unlock (&imm_lock);
    return ptr;
  }

  void *fresh_ptr = _internal_MemoryAllocate (size);
  if (fresh_ptr) {
    memcpy (fresh_ptr, ptr, oblock->size);
    _internal_cleanbit (ptr);
  }

  pthread_mutex_unlock (&imm_lock);
  return fresh_ptr;
}

void *MemoryAllocateAndFillZero (size_t nmemb, size_t size)
{
  if (nmemb == 0 || size == 0) return NULL;
  if (nmemb > SIZE_MAX / size) return NULL;

  size_t total = nmemb * size;

  void *ptr = MemoryAllocate (total);

  if (ptr) memset (ptr, 0, total);
  return ptr;
}