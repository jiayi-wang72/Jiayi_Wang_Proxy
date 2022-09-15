/**
 * @file cache.c
 * @brief A self-written cache library .c file to provide the use of a
 * cache for proxy. This cache.c file contains cache_init(), cache_add(),
 * cache_loopup(), cache_free(), print_cache() and other helper functions.
 *
 * The cache is a doubly linked list of key-value pair stored in blocks,
 * where key is the URI and value is the web data responded by the server.
 *
 * The cache has maximum size 1024 * 1024 bytes, and each block of web data
 * has macimum size 100 * 1024 bytes. This cache implements LRU eviction policy.
 *
 *
 * @author Jiayi Wang
 */

#include "cache.h"
#include "csapp.h"
#include "http_parser.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

/** @brief
 * This function initializes a cache struct and returns the pointer to the
 * cache struct.
 *
 * @param[in] found A pointer to the block being removed
 * @pre free_mini should not be NULL
 * @pre found should not be NULL
 * */
cache_t *cache_init(void) {
    cache_t *res = Malloc(sizeof(cache_t));
    res->total = 0;
    res->first = NULL;
    return res;
}

/** @brief
 * This function looks up for the response in a block, passing in a key
 * that may or maynot be the key for the block
 *
 * @param[in] block A pointer to the block
 * @param[in] key A string of URI as key we are looking for
 * @param[in] len The length of the key
 *
 * @return A string that contains the response if key is the key of the block
 * @return NULL if the key is not the key of the block
 * */
char *block_lookup(block_t *block, char *key, size_t len) {

    if (!strcmp(*(block->key), key)) {
        return *(block->value);
    }
    return NULL;
}

/** @brief
 * This function inserts a block into the cache at the end of the linked list
 * to implement the LRU policy
 *
 * @param[out] cache A pointer to the cache
 * @param[in] inserted A pointer to the block being inserted
 * */
void insert_block(cache_t *cache, block_t *inserted) {

    block_t *block;
    block_t *start = cache->first;
    block_t *pb = NULL;
    for (block = start; block != NULL; block = block->next) {
        pb = block;
    }
    if (pb == NULL) {
        cache->first = inserted;
    } else {
        pb->next = inserted;
    }
    inserted->prev = pb;
    inserted->next = NULL;
    cache->total += inserted->object_size;

    return;
}

/** @brief
 * This function frees the first block from the linked list in the cache
 * to implement the LRU policy
 *
 * @param[out] cache A pointer to the cache
 * @return The pointer to first block in the cache
 * @return NULL if no block existed in the cache before
 * */
block_t *free_block(cache_t *cache) {

    block_t *start = cache->first;
    assert(start != NULL);
    cache->first = start->next;
    start->next->prev = NULL;
    cache->total -= start->object_size;
    return start;
}

/** @brief
 * This function removes a block from the cache
 *
 * @param[out] cache A pointer to the cache
 * @param[in] block A pointer to the block being removed
 * @pre the block has to be in the cache before
 * */
void remove_block(cache_t *cache, block_t *block) {

    if (cache->first == block) {
        cache->first = block->next;
    }
    if (block->prev != NULL) {
        block->prev->next = block->next;
    }
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
    block->prev = NULL;
    block->next = NULL;
    cache->total -= block->object_size;
    return;
}

/** @brief
 * This function inserts a block into the cache at the end of the linked list
 * to implement the LRU policy
 *
 * @param[out] cache A pointer to the cache
 * @param[in] inserted A pointer to the block being inserted
 * */
block_t *cache_lookup(cache_t *cache, char *key, int len) {
    block_t *start = cache->first;
    if (start == NULL) {
        return NULL;
    }
    block_t *block;
    // if there are things in the list
    for (block = start; block != NULL; block = block->next) {
        char *res = block_lookup(block, key, len);
        if (res != NULL) {
            // current block is reused
            remove_block(cache, block);
            insert_block(cache, block);
            return block;
        }
    }
    return NULL;
}

/** @brief
 * This function add a block into the cache, potentially evict Least
 * recently used one
 *
 * @param[in] cache A pointer to cache
 * @param[in] response A string to the response
 * @param[in] key A string of URI as key
 * @param[in] rlen The length of the response
 * @param[in] klen The length of the key
 *
 * @return -1 if block already in cache
 * @return 0 if block not yet in cache
 * */
int cache_add(cache_t *cache, char *response, char *key, int rlen, int klen) {

    if (cache_lookup(cache, key, klen) != NULL) {
        return -1;
    }

    char **keyp = Malloc(sizeof(char *));
    *keyp = key;
    char **responsep = Malloc(sizeof(char *));
    *responsep = response;

    block_t *new = Malloc(sizeof(block_t));
    new->key = keyp;
    new->object_size = rlen;
    new->value = responsep;
    new->count = 1;

    while (cache->total + rlen > MAX_CACHE_SIZE) {
        block_t *freed = free_block(cache);
        freed->count -= 1;
        if (freed->count == 0) {
            Free(*(freed->key));
            Free(*(freed->value));
            Free(freed->key);
            Free(freed->value);
            Free(freed);
        }
    }

    insert_block(cache, new);
    return 0;
}

/** @brief
 * This function frees the cache
 *
 * @param[in] cache A pointer to the cache
 * */
void cache_free(cache_t *cache) {
    block_t *start = cache->first;
    block_t *block;
    block_t *prev = NULL;
    for (block = start; block != NULL; block = block->next) {
        if (block->prev != NULL) {
            Free(*(block->prev->key));
            Free(block->prev->key);
            Free(*(block->prev->value));
            Free(block->prev->value);
            Free(block->prev);
        }

        if (block->next == NULL) {
            Free(*(block->key));
            Free(block->key);
            Free(*(block->value));
            Free(block->value);
            prev = block;
        }
    }
    if (prev != NULL) {
        Free(prev);
    }

    // free the last block
    Free(cache);
    return;
}

/** @brief
 * This function prints the cache for debugging purposes
 *
 * @param[in] cache A pointer to the cache
 * */
void print_cache(cache_t *cache) {
    sio_printf("ENTER PRINT CACHE FUNCTION\n");
    sio_printf("current cache size is: %ld", (size_t)cache->total);
    block_t *start = cache->first;
    if (start == NULL) {
        sio_printf("\nnothing in the cache\n\n");
    }

    block_t *block;
    for (block = start; block != NULL; block = block->next) {
        sio_printf("\n");
        sio_printf("the next block:\n");
        sio_printf("block key: %s\n", *(block->key));
        sio_printf("block address is %ld\n", (size_t)block);
        sio_printf("\n");
    }

    sio_printf("EXIT PRINT CACHE FUNCTION\n");
}
