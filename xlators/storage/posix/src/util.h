#include <pthread.h>
#include <stdint.h>

#ifndef UTIL_H
#define UTIL_H

#define UPPER(x,y) ((x + y - 1)/y*y)

void my_malloc_init(uint64_t size) ;
void *my_malloc(uint64_t size) ;
void my_free(void* obj, uint64_t size);
void my_posix_memalign(void* obj, int align, uint64_t size) ;

#endif


