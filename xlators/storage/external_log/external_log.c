#include <pthread.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
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
	pthread_mutex_init(&external_log_id_lock, NULL);
	pthread_mutex_init(&external_log_offset_lock, NULL);
	
	external_log_fd = open("/home/dashu/external_log", O_RDWR);
	if(external_log_fd <= 0) {
		printf("open failed\n");
		exit(0);
	}
	external_log_offset = 0;

	return 0;
}

int external_log_finish() {
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
	pthread_mutex_destroy(&external_log_id_lock);
	pthread_mutex_destroy(&external_log_offset_lock);

	close(external_log_fd);
	return 0;
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
	return internal_offset;
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

	if((*head)->next != NULL) {
		if(b1 <= a2 && b2 >= (*head)->next->offset) {
			int c1 = (*head)->next->offset;
			int c2 = (*head)->next->offset + (*head)->next->size;
			char* tmp = malloc(c2 - a1);
			memcpy(tmp, (*head)->data, b1 - a1);
			memcpy(tmp + b1 - a1, data->data, b2 - b1);
			memcpy(tmp + b2 - a1, (*head)->next->data + b2 - c1, c2 - b2);
			free((*head)->data);
			(*head)->data = tmp;
			(*head)->size = c2 - a1;
			(*head)->is_dirty = 1;
			free(data->data);
			free(data);
			struct cache_item* item = (*head)->next;
			(*head)->next = item->next;
			free(item->data);
			free(item);
			return;
		}
	}

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

unsigned int external_log_hash(char* str, int upper_bound) {
	unsigned int h;
	unsigned char *p;

	if(!str)
		return 0;

	for(h = 0,p = (unsigned char *) str;*p; p++)
		h = 31 * h + *p;

	return h % upper_bound;
}



int insert_item(int fd, struct iovec *vec, int count, uint32_t offset) {
	int hash_value;
	char* filename;
	int i;
	int ret;
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

	ret = merge_iovec(&tmp, vec, count, offset);

	hash_value = external_log_hash(filename, HASH_ITEM_NUM);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	p = &(hashtable[hash_value]);
	while(1) {
		if((*p) == NULL) {
			(*p) = malloc(sizeof(struct hash_item));
			(*p)->pathname = malloc(strlen(filename) + 1);
			strcpy((*p)->pathname, filename);
			(*p)->pathname[strlen(filename)] = '\0';
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
	return ret;
}

int external_log_flush(struct hash_item* item) {
	int item_num;
	uint32_t size;
	struct cache_item* p;
	uint64_t offset;
	char* desc;
	char* data;
	char* commit;
	char* desc_p;
	char* data_p;
	char* commit_p;
	uint32_t desc_size;
	int ret;

	if(item == NULL)
		return;

	item_num = 0;
	size = 0;
	p = item->head;
	while(p != NULL) {
		item_num++;
		size += p->size;
		p = p->next;
	}

	desc_size = sizeof(struct descriptor_block) + 
			strlen(item->pathname) + item_num*(sizeof(struct record_item));
	desc = malloc(desc_size);
	data = malloc(size);
	commit = malloc(sizeof(struct commit_block));

	pthread_mutex_lock(&external_log_offset_lock);
	offset = external_log_offset;
	external_log_offset += UPPER(desc_size, BLOCK_SIZE) + UPPER(size, BLOCK_SIZE) + BLOCK_SIZE;	
	pthread_mutex_unlock(&external_log_offset_lock);

	*((uint32_t*) desc) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	desc_p = desc + sizeof(uint32_t);
	*((uint32_t*) commit) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	commit_p = commit + sizeof(uint32_t);
	pthread_mutex_lock(&external_log_id_lock);
	*((uint32_t*) desc_p) = external_log_id;
	*((uint32_t*) commit_p) = external_log_id;
	external_log_id++;
	pthread_mutex_unlock(&external_log_id_lock);
	desc_p += sizeof(uint32_t);
	*((int *) desc_p) = item_num;
	desc_p += sizeof(int);
	*((int *) desc_p) = strlen(item->pathname);
	desc_p += sizeof(int);
	memcpy(desc_p, item->pathname, strlen(item->pathname));
	desc_p += strlen(item->pathname);


	p = item->head;
	data_p = data;
	while(p != NULL) {
		*((uint32_t*) desc_p) = p->size;
		desc_p += sizeof(uint32_t);
		*((uint32_t*) desc_p) = p->offset;
		desc_p += sizeof(uint32_t);
		memcpy(data_p, p->data, p->size);
		data_p += p->size;
		p = p->next;
	}

	pwrite(external_log_fd, desc, desc_size, offset);
	pwrite(external_log_fd, data, size, offset + UPPER(desc_size, BLOCK_SIZE));
	pwrite(external_log_fd, commit, sizeof(struct commit_block), 
			offset + UPPER(desc_size, BLOCK_SIZE) + UPPER(size, BLOCK_SIZE));
	ret = fsync(external_log_fd);

	if(ret < 0)
		goto out;

	p = item->head;
	int fd;
	fd = open(item->pathname, O_WRONLY);
	if(fd > 0) {
		while(p != NULL) {
			pwrite(fd, p->data, p->size, p->offset);
			p = p->next;
		}
	}

out:
	free(data);
	free(commit);
	free(desc);
	return ret;
}

int external_log_flush_for_fsync(int fd) {
	int ret = -1;
	int hash_value;
	struct hash_item* item;

	hash_value = external_log_hash(file_map[fd], HASH_ITEM_NUM);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	item = hashtable[hash_value];
	while(item != NULL) {
		if(!strcmp(item->pathname, file_map[fd])) {
			ret = external_log_flush(item);
			break;
		}
		item = item->next;
	}
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
	return ret;
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
	pthread_mutex_init(&external_log_id_lock, NULL);
	pthread_mutex_init(&external_log_offset_lock, NULL);
	
	external_log_fd = open("/home/dashu/external_log", O_RDWR);
	if(external_log_fd <= 0) {
		printf("open failed\n");
		exit(0);
	}
	external_log_offset = 0;
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
	insert_item(1, vec, 4, 0);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'c');
	insert_item(2, vec, 4, 1000);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'd');
	insert_item(2, vec, 4, 95);
	free_iovec(vec, 4);

	vec = get_iovec(4, 'e');
	insert_item(1, vec, 4, 5);
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

	vec = get_iovec(4, 'i');
	insert_item(0, vec, 4, 2990);
	free_iovec(vec, 4);
	vec = get_iovec(4, 'j');
	insert_item(0, vec, 4, 3005);
	free_iovec(vec, 4);
	vec = get_iovec(5, 'k');
	insert_item(0, vec, 5, 2995);
	free_iovec(vec, 5);
}

void fsync_test() {
	int i;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		if(hashtable[i] != NULL)
			external_log_flush(hashtable[i]);
	}
}

void show_log_content() {
	int fd;
	struct descriptor_block* d;
	struct record_item* item;
	struct commit_block* c;
	char desc[BLOCK_SIZE];
	char data[BLOCK_SIZE];
	char commit[BLOCK_SIZE];
	char* pathname;
	char* desc_p = desc + sizeof(struct descriptor_block);
	char* data_p = data;
	int i;

	fd = open("/home/dashu/external_log", O_RDWR);
	read(fd, desc, BLOCK_SIZE);
	read(fd, data, BLOCK_SIZE);
	read(fd, commit, BLOCK_SIZE);
	d = (struct descriptor_block*) desc;

	while(d->sig == EXTERNAL_LOG_METADATA_BLOCK_SIG) {
		desc_p = desc + sizeof(struct descriptor_block);
		c = (struct commit_block*) commit;
		pathname = malloc(d->path_size + 1);
		memcpy(pathname, desc_p, d->path_size);
		pathname[d->path_size] = '\0';
		desc_p += d->path_size;
		printf("pathname:%s sig:%u id:%lu num_of_item:%d path_size:%d\n", 
			pathname, d->sig, d->id, d->num_of_item, d->path_size);
		item = (struct record_item*)desc_p;
		for(i = 0;i < d->num_of_item;i++) {
			printf("size:%u offset:%u\n", item->size, item->offset);
			item++;
		}
		printf("data:%s\n", data);
		printf("commit:%u id:%lu\n", c->sig, c->id);
		if(read(fd, desc, BLOCK_SIZE) <=0 || read(fd, data, BLOCK_SIZE) <= 0 ||
			read(fd, commit, BLOCK_SIZE) <= 0) {
			break;
		}
		free(pathname);
		d = (struct descriptor_block*) desc;
	}

}

int main() {
	external_log_init_for_test();
	insert_item_test();

	traversal_hashtable();
	fsync_test();
	show_log_content();
	external_log_finish_for_test();
	
}