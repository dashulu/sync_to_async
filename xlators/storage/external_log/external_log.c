#include <pthread.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include "util.h"
#include "external_log.h"

int external_log_init() {
	int i;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		hashtable[i] = NULL;
		pthread_mutex_init (&hashtable_locks[i], NULL); 
	}

	for(i = 0;i < NUM_FD;i++) {
		file_map[i] = NULL;
	}

	pthread_mutex_init(&file_map_lock, NULL);
}

int external_log_finish() {

}

int merge_iovec(struct cache_item** cache, struct iovec* vec, int count, uint32_t offset) {
	int i;
	int internal_offset;

	if(vec == NULL || count < 0 )
		return 0;

	(*cache) = malloc(sizeof(struct cache_item));
	(*cache)->size = 0;
	(*cache)->is_dirty = 1;
	(*cache)->offset = offset;
	(*cache)->next = NULL;
	for(i = 0;i < count;i++) {
		(*cache)->size += vec[i].iov_len;
	}
	(*cache)->data = malloc((*cache)->size);
	for(i = 0, internal_offset = 0;i < count;i++) {
		memcpy((*cache)->data + internal_offset, vec[i].iov_base, vec[i].iov_len);
		internal_offset += vec[i].iov_len;
	}

}


static void insert_cache_item(struct cache_item** head, struct cache_item* data) {
	if((*head) == NULL) {
		(*head) = data;
		return;
	}

	int a1,a2,b1,b2;
	a1 = (*head)->offset;
	a2 = (*head)->offset + (*head)->size;
	b1 = data->offset;
	b2 = data->offset + data->size;
	if(a1 > b2) {
		data->next = (*head);
		(*head) = data;
		return;
	} else if(b1 <= a1 && b2 >= a1 && b2 <= a2) {
		int overlap = b2 - a1;
		int size = a2 - b1;
		char* tmp = malloc(size);
		memcpy(tmp, data->data, data->size);
		memcpy(tmp + data->size, (*head)->data + overlap,
			(*head)->size - overlap);
		free((*head)->data);
		(*head)->data = tmp;
		(*head)->size = size;
		(*head)->offset = data->offset;
		(*head)->is_dirty = 1;
		free(data->data);
		free(data);
	} else if(b1 <= a1 && a2 <= b2) {
		struct cache_item* tmp = (*head);
		(*head) = data;
		free(tmp->data);
		free(tmp);
	} else if(a1 <= b1 && b1 <= a2 && a2 <= b2) {
		char* tmp = malloc(b2 - a1);
		memcpy(tmp, (*head)->data, b1 - a1);
		memcpy(tmp + b1 - a1, data->data, b2 - b1);
		free((*head)->data);
		(*head)->data = tmp;
		(*head)->size = b2 - a1;
		(*head)->offset = a1;
		(*head)->is_dirty = 1;
		free(data->data);
		free(data);
	} else if(a1 <= b1 && b2 <= a2) {
		memcpy((*head)->data + b1 - a1, data->data, b2 - b1);
		free(data->data);
		free(data);
	} else {
		insert_cache_item(&((*head)->next), data);
	}
}



int insert_item(int fd, struct iovec *vec, int count, uint32_t offset) {
	int hash_value;
	char* filename;
	int i;
	struct hash_item** p;
	struct hash_item* q;
	struct cache_item* tmp;

	if(count < 1 || fd < 0 || fd >= NUM_FD || vec == NULL)
		return 0;

	pthread_mutex_lock (&file_map_lock);
	if(file_map[fd] == NULL) {
		return 0;
	} else {
		filename = malloc(strlen(file_map[fd]) + 1);
		strcpy(filename, file_map[fd]);
	}
	pthread_mutex_unlock (&file_map_lock);

	merge_iovec(&tmp, vec, count, offset);

	hash_value = external_log_hash(filename, HASH_ITEM_NUM);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	p = &(hashtable[hash_value]);
	while(1) {
		if((*p) == NULL) {
			(*p) = malloc(sizeof(struct hash_item));
			(*p)->pathname = malloc(strlen(filename) + 1);
			strcpy((*p)->pathname, filename);
			(*p)->next = NULL;
			(*p)->head = tmp;
			break;
		}
		if(!strcmp(filename, (*p)->pathname)) {
			insert_cache_item(&((*p)->head), tmp);
			break;
		}
		p = &((*p)->next);
	}
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
}

static struct iovec* get_iovec(int count, char flag) {
	struct iovec* vec;
	int i,j;

	vec = malloc(sizeof(struct iovec)*count);
	for(i = 0;i < count;i++) {
		vec[i].iov_len = i + 1;
		vec[i].iov_base = malloc(i + 1);
		for(j = 0;j < vec[i].iov_len;j++) {
			((char*)vec[i].iov_base)[j] = flag;
		}
	}
	return vec;
}

void free_iovec(struct iovec* vec, int count) {
	int i;

	for(i = 0;i < count;i++) {
		free(vec[i].iov_base);
	}
	free(vec);
}

static struct cache_item* get_cache_item(int count, uint32_t offset, char flag) {
	struct cache_item* cache;
	struct iovec* vec;

	vec = get_iovec(count, flag);
	merge_iovec(&cache, vec, count, offset);
	return cache;
}

static void test_merge_iovec() {
	struct cache_item* cache;
	int i,j;

	for(i = 0;i < 10;i++) {
		cache = get_cache_item(5+i, i*1000, 'a' + i);
		printf("data:%s size:%u offset:%u is_dirty:%d\n", cache->data, 
			cache->size, cache->offset, cache->is_dirty);
		
		free(cache->data);
		free(cache);
	}
}

static int external_log_init_for_test() {
	int i,j;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		hashtable[i] = NULL;
		pthread_mutex_init (&hashtable_locks[i], NULL); 
	}

	for(i = 0;i < NUM_FD;i++) {
		file_map[i] = malloc(i + 2);
		for(j = 0;j < i + 1;j++) {
			file_map[i][j] = 'a';
		}
		file_map[i + 1] = '\0';
	}

	pthread_mutex_init(&file_map_lock, NULL);
}

void destroy_cache_item(struct cache_item* item) {
	struct cache_item* next;

	if(item == NULL) {
		return;
	}
	next = item->next;
	if(item->data != NULL)
		free(item->data);
	destroy_cache_item(next);
	free(item);
}

void destroy_hash_item(struct hash_item* item) {
	struct hash_item* next;

	if(item == NULL) {
		return;
	}

	next = item->next;
	if(item->pathname != NULL)
		free(item->pathname);
	destroy_cache_item(item->head);
	destroy_hash_item(next);
	free(item);

}

static int external_log_finish_for_test() {
	int i,j;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		if(hashtable[i] != NULL) {
			destroy_hash_item(hashtable[i]);
		}
		pthread_mutex_destroy(&hashtable_locks[i]); 
	}

	for(i = 0;i < NUM_FD;i++) {
		free(file_map[i]);
	}

	pthread_mutex_destroy(&file_map_lock);
}

void print_cache_item(struct cache_item* item , int i) {
	if(item == NULL)
		return;
	printf("i:%d data:%s size:%u offset:%u is_dirty:%d \n", i, item->data, 
			item->size, item->offset, item->is_dirty);
	print_cache_item(item->next, i+1);
}

void print_hash_item(struct hash_item* item, int i) {
	if(item == NULL)
		return;
	printf("i:%d name:%s\n", i, item->pathname);
	print_cache_item(item->head, 1);
	print_hash_item(item->next, i);
}

void traversal_hashtable() {
	int i;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		print_hash_item(hashtable[i], i);
	}
}


void insert_item_test() {
	struct iovec* vec;

	vec = get_iovec(4, 'a');
	insert_item(0, vec, 4, 100);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'b');
	insert_item(0, vec, 4, 0);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'c');
	insert_item(0, vec, 4, 1000);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'd');
	insert_item(0, vec, 4, 95);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'e');
	insert_item(0, vec, 4, 5);
	free_iovec(vec, 4);

	vec = get_iovec(6, 'f');
	insert_item(0, vec, 6, 997);
	free_iovec(vec, 6);

	vec = get_iovec(5, 'g');
	insert_item(0, vec, 5, 1997);
	free_iovec(vec, 5);

	vec = get_iovec(4, 'h');
	insert_item(0, vec, 4, 2000);
	free_iovec(vec, 4);

}

int main() {
	external_log_init_for_test();
	insert_item_test();

	traversal_hashtable();

	external_log_finish_for_test();
}