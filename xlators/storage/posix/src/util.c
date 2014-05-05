#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static pthread_mutex_t malloc_lock;
static pthread_cond_t malloc_con;
static uint64_t my_malloc_total_size;
static uint64_t my_malloc_current_size;
static uint32_t malloc_count;
static uint32_t free_count;

void my_malloc_init(uint64_t size) {
	my_malloc_total_size = size;
	pthread_mutex_init(&malloc_lock, NULL);
	pthread_cond_init(&malloc_con, NULL);
}

void *my_malloc(uint64_t size) {
//	uint64_t before_malloc =
	void* tmp; 
	malloc_count++;
	pthread_mutex_lock(&malloc_lock);
	while(my_malloc_current_size + size > my_malloc_total_size) {
		pthread_cond_wait(&malloc_con, &malloc_lock);
	} 
	my_malloc_current_size += size;
	tmp = malloc(size);
	pthread_mutex_unlock(&malloc_lock);
	return tmp;
}

void my_free(void* obj, uint64_t size) {
	free(obj);
	pthread_mutex_lock(&malloc_lock);
	my_malloc_current_size -= size;
	pthread_cond_signal(&malloc_con);
	pthread_mutex_unlock(&malloc_lock);
	free_count++;
}

void my_posix_memalign(void* obj, int align, uint64_t size) {
	malloc_count++;
	pthread_mutex_lock(&malloc_lock);
	while(my_malloc_current_size + size > my_malloc_total_size) {
		pthread_cond_wait(&malloc_con, &malloc_lock);
	} 
	my_malloc_current_size += size;
	posix_memalign(obj, align, size);
	pthread_mutex_unlock(&malloc_lock);
}