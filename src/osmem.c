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
	block_meta *best_fit = NULL;

	while (start != NULL) {
		if (start->status == STATUS_FREE && start->size >= size) {
			if (best_fit == NULL) {
				best_fit = start;
				found_space = 1;
			} else if (start->size < best_fit->size) {
				best_fit = start;
			}
		}
		if (start->next == NULL)
			break;
		start = start->next;
	}
	if (found_space)
		return best_fit;
	return start;
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
	if (block->size - size < 8 + __META_SIZE__)
		return;
	block_meta *next = (block_meta *)((char *)block + size + __META_SIZE__);

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
	while (block->prev != NULL) {
		if (block->prev->status == STATUS_FREE) {
			block->prev->size = block->prev->size + block->size + __META_SIZE__;
			block->prev->next = block->next;
			if (block->next != NULL)
				block->next->prev = block->prev;
			block = block->prev;
		} else {
			break;
		}
	}
	while (block->next != NULL) {
		if (block->next->status == STATUS_FREE) {
			block->size = block->next->size + block->size + __META_SIZE__;
			if (block->next->next != NULL)
				block->next->next->prev = block;
			block->next = block->next->next;
		} else {
			break;
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
	if (size >= __MAP_TRESHHOLD__ - __META_SIZE__) {
		block_meta *blocker = (block_meta *)mmap(NULL, size + __META_SIZE__, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		blocker->next = NULL;
		blocker->prev = NULL;
		blocker->status = STATUS_MAPPED;
		blocker->size = size;
		return blocker + 1;
	}
	if (base == NULL) {
		base = sbrk(0);
		block_meta *blocker = (block_meta *)sbrk(__MAP_TRESHHOLD__);

		blocker->size = __MAP_TRESHHOLD__ - __META_SIZE__;
		blocker->status = STATUS_ALLOC;
		blocker->prev = NULL;
		blocker->next = NULL;
		break_block(blocker, size);
		return base + sizeof(block_meta);
	}
	block_meta *blocker = best_fit((block_meta *)base, size);

	if (blocker->status == STATUS_ALLOC) {
		blocker = alloc_mem(blocker, size);
	} else if (blocker->size < size) {
		sbrk(size - blocker->size);
		blocker->size = size;
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
	size_t true_size = size * nmemb;

	if (true_size % 8 != 0) {
		true_size -= true_size % 8;
		true_size += 8;
	}
	if (true_size >= __BRK_SIZE__ - __META_SIZE__) {
		block_meta *blocker = (block_meta *)mmap(NULL, true_size + __META_SIZE__,
							   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		blocker->next = NULL;
		blocker->prev = NULL;
		blocker->status = STATUS_MAPPED;
		blocker->size = true_size;
		char *ret = (char *)(blocker + 1);

		for (size_t i = 0; i < true_size; i++)
			ret[i] = 0;
		return (void *)ret;
	}
	char *ret = (char *)os_malloc(true_size);

	for (size_t i = 0; i < true_size; i++)
		ret[i] = 0;
	return (void *)ret;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
