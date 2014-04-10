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

static void insert_cache_item(struct hash_item* head, struct cache_item* data) {
	if(head->head == NULL) {
		head->head = data;
		return;
	}

	int a1,a2,b1,b2;
	a1 = head->head->offset;
	a2 = head->head->offset + head->head->size;
	b1 = data->offset;
	b2 = data->offset + data->size;
	if(head->head->offset > data->offset + size) {
		data->next = head->head;
		head->head = data;
		return;
	} else if(head->head->offset <= data->offset + data->size && 
				data->offset + data->size <= head->head->offset + head->head->size) {
		int overlap = (data->offset + data->size - head->head->offset);
		int size = head->head->offset + head->head->size - data->offset;
		char* tmp = malloc(size);
		memcpy(tmp, data->data, data->size);
		memcpy(tmp + data->size, head->head->data + overlap,
			head->head->size - overlap);
		free(head->head->data);
		head->head->data = tmp;
		head->head->size = size;
		head->head->offset = data->offset;
		head->head->is_dirty = true;
		free(data->data);
		free(data);
	} else if(head->head)
}

int insert_item(int fd, struct iovec *vec, int count, uint32_t offset) {
	int hash_value;
	char* filename;
	int i;
	struct hash_item* p;
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
	if(hashtable[hash_value] == NULL) {
		hashtable[hash_value] = malloc(sizeof(struct hash_item));
		hashtable[hash_value]->pathname = malloc(strlen(filename) + 1);
		strcpy(hashtable[hash_value]->pathname, filename);
		hashtable[hash_value]->next = NULL;
		hashtable[hash_value]->head = tmp;
	} else {
		q = hashtable[hash_value];
		p = q->next;

		if(!strcmp(q->pathname, filename)) {

		} else {
			while(p != NULL) {
				if(!strcmp(p->pathname, filename)) {
					break;
				}
				p = p->next;
			}
		}
	}
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
}


int main() {
	printf("hello world");
}