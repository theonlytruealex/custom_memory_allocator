// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <sys/mman.h>
#include <unistd.h>
#define __BRK_SIZE__ 0x1000
#define __MAP_TRESHHOLD__ 0x20000
#define __META_SIZE__ 0x20
#define STATUS_FREE   0
#define STATUS_ALLOC  1
#define STATUS_MAPPED 2

static void *base;
#pragma once

#include <errno.h>
#include <stdio.h>
#include "printf.h"

#define DIE(assertion, call_description)									\
	do {													\
		if (assertion) {										\
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);					\
			perror(call_description);								\
			exit(errno);										\
		}												\
	} while (0)

/* Structure to hold memory block metadata */
typedef struct block_meta {
	size_t size;
	int status;
	char pad[4];
	struct block_meta *prev;
	struct block_meta *next;
} block_meta;


block_meta *best_fit(block_meta *start, size_t size)
{
	int found_space = 0;
	block_meta *best_fit = start;

	while (start != NULL) {
		if (start->size < best_fit->size && start->status == STATUS_FREE && start->size >= size) {
			best_fit = start;
			found_space = 1;
		}
		start = start->next;
	}
	if (found_space)
		return best_fit;
	return NULL;
}

block_meta *alloc_mem(block_meta *last, size_t size)
{
	if (size <= __MAP_TRESHHOLD__) {
		last->next = sbrk(size + __META_SIZE__);
		last->next->prev = last;
		last = last->next;
		last->size = size;
		last->next = NULL;
		last->status = STATUS_ALLOC;
		return last;
	}
	exit(1);
}

void break_block(block_meta *block, size_t size)
{
	if (block->size - size - __META_SIZE__ < 8)
		return;
    block_meta *next = (block_meta *)((void *)block + size + __META_SIZE__);
	next->size = block->size - size - __META_SIZE__;
	next->status = STATUS_FREE;
	next->prev = block;
	next->next = block->next;
	block->size = size;
	block->next = next;
    if (next->next != NULL)
		next->next->prev = next;
}

void merge_block(block_meta *block)
{
	if (block->prev != NULL) {
		if (block->prev->status == STATUS_FREE) {
			block->prev->size = block->prev->size + block->size + __META_SIZE__;
			block->prev->next = block->next;
			if (block->next != NULL)
				block->next->prev = block->prev;
			block = block->prev;
		}
	}
	if (block->next != NULL) {
		if (block->next->status == STATUS_FREE) {
			block->size = block->next->size + block->size + __META_SIZE__;
			if (block->next->next != NULL)
				block->next->next->prev = block;
			block->next = block->next->next;
		}
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	if (size % 8 != 0) {
		size -= size % 8;
		size += 8;
	}
	if (size > __MAP_TRESHHOLD__ - __META_SIZE__) {
		block_meta *blocker = (block_meta *)mmap(NULL, size + __META_SIZE__, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		blocker->next = NULL;
		blocker->prev = NULL;
		blocker->status = STATUS_MAPPED;
		blocker->size = size;
		return blocker + 1;
	}
	if (base == NULL) {
		base = sbrk(__MAP_TRESHHOLD__);
		block_meta *blocker = (block_meta *)base;

		blocker->size = size;
		blocker->status = STATUS_ALLOC;
		blocker->prev = NULL;
		blocker->next = NULL;
		break_block(blocker, size);
		return base + sizeof(block_meta);
	}
	block_meta *blocker = best_fit((block_meta *)base, size);

	if (blocker == NULL) {
		blocker = (block_meta *)base;
		while (blocker->next != NULL)
			blocker = blocker->next;
		blocker = alloc_mem(blocker, size);
	} else {
		break_block(blocker, size);
	}
	blocker->status = STATUS_ALLOC;
	return blocker + 1;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *blocker = (struct block_meta *)(ptr - sizeof(struct block_meta));

	if (blocker->status == STATUS_MAPPED) {
		munmap((void *)blocker, blocker->size + __META_SIZE__);
		return;
	}
	blocker->status = STATUS_FREE;

	merge_block(blocker);
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
