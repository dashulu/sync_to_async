#include <pthread.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
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

int merge_iovec(struct cache_item* cache, struct iovec* vec, int count, uint32_t offset) {
	int i;
	int internal_offset;

	if(vec == NULL || count < 0 )
		return 0;

	cache = malloc(sizeof(struct cache_item));
	cache->size = 0;
	cache->is_dirty = 1;
	cache->offset = offset;
	cache->next = NULL;
	for(i = 0;i < count;i++) {
		cache->size += vec[i].iov_len;
	}
	cache->data = malloc(cache->size);
	for(i = 0, internal_offset = 0;i < count;i++) {
		memcpy(cache->data + internal_offset, vec[i].iov_base, vec[i].iov_len);
		internal_offset += vec[i].iov_len;
	}

}


static void insert_cache_item(struct cache_item** head, struct cache_item* data) {
	if(head == NULL) {
		(*head) = data;
		return;
	}

	int a1,a2,b1,b2;
	a1 = (*head)->offset;
	a2 = (*head)->offset + (*head)->size;
	b1 = data->offset;
	b2 = data->offset + data->size;
	if(a1 > b2`) {
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
		(*head)->is_dirty = true;
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
		(*head)->is_dirty = true;
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

	merge_iovec(tmp, vec, count, offset);

	hash_value = external_log_hash(filename);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	p = &(hashtable[hash_value]);
	while(true) {
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


int main() {
	printf("hello world");
}