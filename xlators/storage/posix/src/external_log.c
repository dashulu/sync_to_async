#include <pthread.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include "queue.h"
#include "util.h"
#include "external_log.h"

int external_log_flush(struct hash_item* item, pthread_mutex_t* lock);
void destroy_hash_item2(struct hash_item** item);
void destroy_cache_item(struct cache_item* item);
void *background_write_fn(void* obj);
static void log_op(int op, const char* path, void* obj);



void segment_tree_insert(struct segment_tree_node* root, struct cache_item* data) {
//	printf("data->offset:%lu data->size:%lu\n", data->offset, data->size);

	if(data->offset + data->size <= root->item->offset) {
		if(root->left != NULL) {
			segment_tree_insert(root->left, data);
		} else {
			root->left = malloc(sizeof(struct segment_tree_node));
			root->left->left = NULL;
			root->left->right = NULL;
			root->left->parent = root;
			root->left->item = data;
		}
	} else if(data->offset >= root->item->offset + root->item->size) {
		if(root->right != NULL) {
			segment_tree_insert(root->right, data);
		} else {
			root->right = malloc(sizeof(struct segment_tree_node));
			root->right->left = NULL;
			root->right->right = NULL;
			root->right->parent = root;
			root->right->item = data;
		}
	} else if(data->offset >= root->item->offset && 
			root->item->offset + root->item->size >= data->offset + data->size) {
		memcpy(root->item->data + data->offset - root->item->offset, data->data, data->size);
		root->item->is_dirty = 1;
		my_free(data->data, data->original_size);
		free(data);
	} else if(data->offset < root->item->offset && 
			root->item->offset + root->item->size >= data->offset + data->size) {

		memcpy(root->item->data, data->data + root->item->offset - data->offset, 
				data->size - (root->item->offset - data->offset));
		root->item->is_dirty = 1;
		data->size = root->item->offset - data->offset;
		if(root->left != NULL) {
			segment_tree_insert(root->left, data);
		} else {
			root->left = malloc(sizeof(struct segment_tree_node));
			root->left->left = NULL;
			root->left->right = NULL;
			root->left->parent = root;
			root->left->item = data;
		}
	} else if(data->offset >= root->item->offset &&
			data->offset + data->size > root->item->offset + root->item->size) {

		memcpy(root->item->data + data->offset - root->item->offset, data->data, 
				(root->item->offset + root->item->size - data->offset));
		root->item->is_dirty = 1;
		data->size = data->size + data->offset - (root->item->offset + root->item->size);
		data->offset = root->item->offset + root->item->size; 
		char* tmp = my_malloc(data->size);
		memcpy(tmp, data->data + root->item->size + root->item->offset - data->offset,
				data->size);
		my_free(data->data, data->original_size);
		data->original_size = data->size;
		data->data = tmp;

		if(root->right != NULL) {
			segment_tree_insert(root->right, data);
		} else {
			root->right = malloc(sizeof(struct segment_tree_node));
			root->right->left = NULL;
			root->right->right = NULL;
			root->right->parent = root;
			root->right->item = data;
		}
	} else {
		memcpy(root->item->data, data->data + root->item->offset - data->offset, 
				root->item->size);
		root->item->is_dirty = 1;

		struct cache_item* right = malloc(sizeof(struct cache_item));
		right->size = data->size + data->offset - (root->item->offset + root->item->size);
		right->offset = root->item->size + root->item->offset;
		right->original_size = right->size;
		right->is_dirty = 1;
		right->data = my_malloc(right->size);
		memcpy(right->data, data->data + root->item->size + root->item->offset - data->offset,
				right->size);
		if(root->right != NULL) {
			segment_tree_insert(root->right, right);
		} else {
			root->right = malloc(sizeof(struct segment_tree_node));
			root->right->left = NULL;
			root->right->right = NULL;
			root->right->parent = root;
			root->right->item = right;
		}

		struct cache_item* left = malloc(sizeof(struct cache_item));
		left->size = root->item->offset - data->offset;
		left->offset = data->offset;
		left->original_size = left->size;
		left->is_dirty = 1;
		left->data = my_malloc(left->size);
		memcpy(left->data, data->data, left->size);
		if(root->left != NULL) {
			segment_tree_insert(root->left, left);
		} else {
			root->left = malloc(sizeof(struct segment_tree_node));
			root->left->left = NULL;
			root->left->right = NULL;
			root->left->parent = root;
			root->left->item = left;
		}

		my_free(data->data, data->original_size);
		free(data);
	}
}

void segment_tree_read(struct segment_tree_node* root, struct read_record** record, uint64_t size, uint64_t offset) {

	if(root == NULL) {
		return;
	} else if(root->item->offset >= size + offset) {
		segment_tree_read(root->left, record, size, offset);
	} else if(root->item->offset + root->item->size <= offset) {
		segment_tree_read(root->right, record, size, offset);
	} else if(root->item->offset <= offset && 
				root->item->offset + root->item->size >= size + offset ) {
		struct read_record* tmp = malloc(sizeof(struct read_record));
		tmp->size = size;
		tmp->offset = offset;
		tmp->data = malloc(size);
		memcpy(tmp->data, root->item->data + offset - root->item->offset, size);
		tmp->next = *record;
		*record = tmp;
	} else if(offset < root->item->offset && root->item->offset + root->item->size >= offset + size) {
		struct read_record* tmp = malloc(sizeof(struct read_record));
		tmp->size = offset + size - root->item->offset;
		tmp->offset = root->item->offset;
		tmp->data = malloc(tmp->size);
		memcpy(tmp->data, root->item->data, tmp->size);
		tmp->next = *record;
		*record = tmp;
		segment_tree_read(root->left, record, size - tmp->size, offset);
	} else if(offset >= root->item->offset && 
				root->item->offset + root->item->size < size + offset) {
		struct read_record* tmp = malloc(sizeof(struct read_record));
		tmp->size = root->item->offset + root->item->size - offset;
		tmp->offset = offset;
		tmp->data = malloc(tmp->size);
		memcpy(tmp->data, root->item->data + offset - root->item->offset, tmp->size);
		tmp->next = *record;
		*record = tmp;
		segment_tree_read(root->right, record, size - tmp->size, offset + tmp->size);
	} else {
		struct read_record* tmp = malloc(sizeof(struct read_record));
		tmp->size = root->item->size;
		tmp->offset = root->item->offset;
		tmp->data = malloc(tmp->size);
		memcpy(tmp->data, root->item->data, tmp->size);
		tmp->next = *record;
		*record = tmp;
		segment_tree_read(root->left, record, root->item->offset - offset, offset);
		segment_tree_read(root->right, record, 
						offset + size - (root->item->offset + root->item->size),
						root->item->offset + root->item->size);
	}
}

static uint64_t get_size(struct segment_tree_node* root, int *count) {
	if(root == NULL)
		return 0;
	(*count)++;
	return root->item->size + get_size(root->left, count) + get_size(root->right, count);
}

static void segment_tree_fsync_helper(struct segment_tree_node* root, char* ptr, int *count,
										void* desc, int *desc_count) {
	if(root == NULL)
		return;
	memcpy(ptr + (*count), root->item->data, root->item->size);
	(*count) += root->item->size;
	char* tmp = ((char*)desc + (*desc_count)*sizeof(struct record_item));
	*((uint64_t*) tmp) = root->item->size;
	tmp += sizeof(uint64_t);
	*((uint64_t*) tmp) = root->item->offset;
	tmp += sizeof(uint64_t);
	*((uint64_t*) tmp) = root->item->version;
	(*desc_count)++;
	segment_tree_fsync_helper(root->left, ptr, count, desc, desc_count);
	segment_tree_fsync_helper(root->right, ptr, count, desc, desc_count);
}

void segment_tree_fsync(struct hash_item* item) {
	uint64_t data_size = 0;
	uint64_t desc_size = 0;
	uint64_t total_size = 0;
	int count = 0;
	uint64_t local_external_offset;
	uint64_t local_external_id;
	void* ptr;
	void* ptr_copy;
	char* data_copy;

	data_size = get_size(item->tree_root, &count);
	desc_size = sizeof(struct descriptor_block) + strlen(item->pathname) + 
				count*sizeof(struct record_item);
	total_size = UPPER(data_size + desc_size + sizeof(struct commit_block), BLOCK_SIZE);

	pthread_mutex_lock(&external_log_id_lock);
	local_external_id = external_log_id;
	external_log_id++;
	pthread_mutex_unlock(&external_log_id_lock);
	pthread_mutex_lock(&external_log_offset_lock);
	local_external_offset = external_log_offset;
	external_log_offset += total_size;
	pthread_mutex_unlock(&external_log_offset_lock);

	ptr = mmap(NULL, total_size, PROT_WRITE, MAP_SHARED, external_log_fd, local_external_offset);

	if(ptr == (void*)-1) {
		printf("mmap failed:total size%lu offset:%lu\n", total_size, local_external_offset);
		exit(1);
	}
	ptr_copy = ptr;
	*((uint32_t*) ptr_copy) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	ptr_copy = ptr_copy + sizeof(uint32_t);
	*((uint32_t*) ptr_copy) = local_external_id;
	ptr_copy += sizeof(uint32_t);
	*((uint32_t*) ptr_copy) = EXTERNAL_LOG_WRITEV;
	ptr_copy += sizeof(uint32_t);
	*((int *) ptr_copy) = count;
	ptr_copy += sizeof(int);
	*((int *) ptr_copy) = strlen(item->pathname);
	ptr_copy += sizeof(int);
	memcpy(ptr_copy, item->pathname, strlen(item->pathname));
	ptr_copy += strlen(item->pathname);

	data_copy = (char*)ptr;
	data_copy += desc_size;

	int data_count = 0;
	int desc_count = 0;
	segment_tree_fsync_helper(item->tree_root, data_copy, &data_count, ptr_copy, &desc_count);
	data_copy += data_size;
	*((uint32_t*) data_copy) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	data_copy += sizeof(uint32_t);
	*((uint32_t*) data_copy) = local_external_id;
	msync(ptr, total_size, MS_SYNC);
	munmap(ptr, total_size);
}



void *background_flush_thread(void* obj) {
    int i = 0;
    time_t current_time;
    struct hash_item* p;

    while(1) {
        time(&current_time);
        for(i = 0;i < HASH_ITEM_NUM;i++) {
            p = hashtable[i];
            while(p != NULL) {
                if((current_time - p->mtime >= TIME_TO_FLUSH || p->dirty_size >= MAX_DIRTY_SIZE) &&
                			 p->is_dirty) {
                    pthread_mutex_lock(&hashtable_locks[i]);
                    external_log_flush(p, &hashtable_locks[i]);
                } 
                p = p->next;
            }
        }
        sleep(1);
    }
}

int check_continue(struct cache_item* a, struct cache_item* b) {
	struct cache_item* head;
	struct cache_item* next;

	if(hashtable[3879] != NULL) {
		head = hashtable[3879]->head;
		if(head != NULL) {
			next = head->next;
			while(next != NULL) {
				if(head->offset + head->size >= next->offset) {
					break;
				}
				head = next;
				next = next->next;
			}
		}
	}
	return 0;
}

int external_log_init() {
	int i;
	uint64_t size = 6;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		hashtable[i] = NULL;
		pthread_mutex_init (&hashtable_locks[i], NULL); 
	}

/*	for(i = 0;i < NUM_FD;i++) {
		file_map[i] = NULL;
	}
*/
	pthread_mutex_init(&file_map_lock, NULL);
	pthread_mutex_init(&external_log_id_lock, NULL);
	pthread_mutex_init(&external_log_offset_lock, NULL);
	
	external_log_fd = open("/home/user/sdb1/external_log", O_RDWR);
	if(external_log_fd <= 0) {
		printf("open failed\n");
		exit(0);
	}
	external_log_offset = 0;

	size = size*1024*1024*1024; //6G
	my_malloc_init(size);

//	printf("create background_flush_thread:%d\n", pthread_create(&background_pid, NULL, background_flush_thread, NULL));
	if(pthread_create(&background_pid, NULL, background_flush_thread, NULL)) {
		printf("background_flush_thread create failed.\n");
		exit(0);
	}

	return 0;
}

int external_log_finish() {
	int i;
	pthread_mutex_t tmp;

	pthread_mutex_init(&tmp, NULL);

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		if(hashtable[i] != NULL) {
			pthread_mutex_lock(&tmp);
			external_log_flush(hashtable[i], &tmp);
			destroy_hash_item(hashtable[i]);
		}
		pthread_mutex_destroy(&hashtable_locks[i]); 
	}
	pthread_mutex_destroy(&tmp);

	for(i = 0;i < NUM_FD;i++) {
//		free(file_map[i]);
		if(fd_inode_map[i].name != NULL)
			free(fd_inode_map[i].name);
	}
	pthread_mutex_destroy(&file_map_lock);
	pthread_mutex_destroy(&external_log_id_lock);
	pthread_mutex_destroy(&external_log_offset_lock);

	close(external_log_fd);
	return 0;
}

int merge_iovec(struct cache_item** cache, struct iovec* vec, int count, uint64_t offset) {
	int i;
	uint64_t internal_offset;

	if(vec == NULL || count <= 0 )
		return 0;

	(*cache) = malloc(sizeof(struct cache_item));
	(*cache)->size = 0;
	(*cache)->is_dirty = 1;
	(*cache)->offset = offset;
	(*cache)->version = 0;
	(*cache)->next = NULL;
	for(i = 0;i < count;i++) {
		(*cache)->size += vec[i].iov_len;
	}
	(*cache)->data = my_malloc((*cache)->size);
	(*cache)->original_size = (*cache)->size;
//	printf("malloc cache_item data, size:%lu\n", (*cache)->size);
	for(i = 0, internal_offset = 0;i < count;i++) {
		memcpy((*cache)->data + internal_offset, vec[i].iov_base, vec[i].iov_len);
		internal_offset += vec[i].iov_len;
	}
	return internal_offset;
}

int external_log_rename(uint64_t ino, const char* old_name, char* new_name) {
	int i;
	int hash_value;

	for(i = 0;i < NUM_FD;i++) {
		if(ino == fd_inode_map[i].inode_num) {
			log_op(EXTERNAL_LOG_RENAME, old_name, (void*) new_name);
			hash_value = external_log_hash(ino, HASH_ITEM_NUM);
			pthread_mutex_lock(&hashtable_locks[hash_value]);
			if(fd_inode_map[i].name != NULL) {
				free(fd_inode_map[i].name);
				fd_inode_map[i].name = malloc(strlen(new_name) + 1);
				strcpy(fd_inode_map[i].name, new_name);
//				int hash_value = external_log_hash(fd_inode_map[i].ino, HASH_ITEM_NUM);
				free(hashtable[hash_value]->pathname);
				hashtable[hash_value]->pathname = malloc(strlen(new_name) + 1);
				strcpy(hashtable[hash_value]->pathname, new_name);
			}
			pthread_mutex_unlock(&hashtable_locks[hash_value]);
			break;
		}
	}

	return 0;
}

uint64_t calculate(struct cache_item* item) {
	uint64_t sum = 0;

	while(item != NULL) {
		sum += item->size;
		item = item->next;
	}

	return sum;
}

uint64_t calculate_memory() {
	int i;
	uint64_t sum = 0;

	for(i = 0;i < HASH_ITEM_NUM;i++) {
		if(hashtable[i] != NULL) {
			sum += calculate(hashtable[i]->head);
		}
	}

	return sum;

}


static void deal_with_overlap(struct cache_item* item) {
	struct cache_item* p;

	p = item->next;
	while(p != NULL) {
		if(item->offset + item->size <= p->offset) {
			break;
		} else if(item->offset + item->size > p->offset && 
					item->offset + item->size < p->offset + p->size) {
	//		printf("free in deal_with_overlap:%lu\n", p->size);
			p->size = p->offset + p->size - (item->offset + item->size);
			char* tmp = my_malloc(p->size);
	//		printf("malloc in deal_with_overlap:%lu\n", p->size);
			memcpy(tmp, p->data + item->offset + item->size - p->offset, p->size);
			p->offset = item->offset + item->size;

			my_free(p->data, p->original_size);
			p->original_size = p->size;
			p->data = tmp;
			break;
		} else {
			item->next = p->next;
			my_free(p->data, p->original_size);
			free(p);
			p = item->next;
		}
	}
}


static void insert_cache_item(struct cache_item** head, struct cache_item* data) {
	if((*head) == NULL) {
		(*head) = data;
		return;
	} 

	uint64_t a1,a2,b1,b2;
	a1 = (*head)->offset;
	a2 = (*head)->offset + (*head)->size;
	b1 = data->offset;
	b2 = data->offset + data->size;

	if(a1 >= b2) {
		data->next = (*head);
		(*head) = data;
		//check_continue(*head, data);
		return;
	} else if(b1 < a1 && b2 >= a1 && b2 < a2) {
		uint64_t overlap = b2 - a1;
		uint64_t front = a1 - b1; 
		uint64_t end = a2 - b2;
		struct cache_item* p;
		char* tmp;
		//minimize the memory copy size.
		if(end <= overlap + front) {
			p = *head;
			*head = data;
			data->next = p;
			tmp = my_malloc(end);
			memcpy(tmp, p->data + overlap, end);
			my_free(p->data, p->original_size);
			p->data = tmp;
			p->size = end;
			p->original_size = end;
			p->offset = p->offset + overlap;
			data->is_dirty = 1;
		} else {
			memcpy((*head)->data, data->data + front, overlap);
			data->size = front;
			tmp = my_malloc(front);
			memcpy(tmp, data->data, front);
			my_free(data->data, data->original_size);
			data->original_size = front;
			data->data = tmp;
			p = *head;
			*head = data;
			data->next = p;
			p->version++;
			data->is_dirty = 1;
			p->is_dirty = 1;
		}
	} else if(b1 <= a1 && a2 <= b2) {
		struct cache_item* tmp = (*head);
		(*head) = data;
		data->next = tmp->next;
		//check_continue(*head, data);
		my_free(tmp->data, tmp->original_size);
		free(tmp);
		deal_with_overlap(data);
	} else if(a1 < b1 && b1 < a2 && a2 < b2) {
		uint64_t overlap = a2 - b1;
		uint64_t front = b1 - a1; 
		uint64_t end = b2 - a2;
		struct cache_item* p;
		char* tmp;
		//minimize the memory copy size.
		if(front <= overlap + end) {
			p = (*head)->next;
			(*head)->next = data;
			data->next = p;
			tmp = my_malloc(front);
			memcpy(tmp, (*head)->data, front);
			my_free((*head)->data, (*head)->original_size);
			(*head)->data = tmp;
			(*head)->size = front;
			(*head)->original_size = front;
		} else {
			memcpy((*head)->data + front, data->data, overlap);
			(*head)->version++;
			tmp = my_malloc(end);
			memcpy(tmp, data->data + overlap, end);
			my_free(data->data, data->original_size);
			data->data = tmp;
			data->offset = data->offset + overlap;
			data->size = end;
			data->original_size = end;
			p = (*head)->next;
			(*head)->next = data;
			data->next = p;
			data->is_dirty = 1;
			(*head)->is_dirty = 1;
		}
		deal_with_overlap(data);
	} else if(a1 < b1 && b2 < a2) {
		if(b2 - b1 <= a2 - a1 - (b2 - b1)) {
			memcpy((*head)->data + b1 - a1, data->data, b2 - b1);
			(*head)->is_dirty = 1;
			(*head)->version++;
			my_free(data->data, data->original_size);
			free(data);
		} else {
			char* head_data = (*head)->data;
			uint64_t free_size = (*head)->original_size;
			struct cache_item* next = (*head)->next;
			if(b1 - a1) {
				char* tmp = my_malloc(b1 - a1);
				memcpy(tmp, head_data, b1 - a1);
				(*head)->original_size = b1 -a1;
				(*head)->size = b1 - a1;
				(*head)->data = tmp;
				(*head)->next = data;
				data->next = next;
			}
			if(a2 - b2) {
				char* tmp = my_malloc(a2 - b2);
				memcpy(tmp, head_data + b2 - a1, a2 - b2);
				struct cache_item* cache = malloc(sizeof(struct cache_item));
				cache->is_dirty = 1;
				cache->version = 0;
				cache->size = a2 - b2;
				cache->original_size = a2 - b2;
				cache->offset = b2;
				cache->data = tmp;
				cache->next = data->next;
				data->next = cache;
			}
			my_free(head_data, free_size);
		}
	} else {
		insert_cache_item(&((*head)->next), data);
	}
}

/*
unsigned int external_log_hash(const char* str, int upper_bound) {
	unsigned int h;
	unsigned char *p;

	if(!str)
		return 0;

	if(!strcmp("/home/dashu/sdb2/file1", str) || 
		!strcmp("/home/dashu/sdb2/file2", str) || 
		!strcmp("/home/dashu/sdb2/dir1/file1", str)) {
           return 100;
     }

	for(h = 0,p = (unsigned char *) str;*p; p++)
		h = 31 * h + *p;

	return h % upper_bound;
}*/

inline unsigned int external_log_hash(uint64_t num, int upper_bound) {
	return (num % upper_bound);
}



int insert_item(int fd, struct iovec *vec, int count, uint64_t offset) {
	int hash_value;
	char* filename;
	int ret;
	struct hash_item** p;
	struct cache_item* tmp;

	if(count < 1 || fd < 0 || fd >= NUM_FD || vec == NULL)
		return 0;
/*
//	pthread_mutex_lock (&file_map_lock);
	if(file_map[fd] == NULL) {
//		pthread_mutex_unlock (&file_map_lock);
		printf("error in insert_item.\n");
		return 0;
	} else {
//		filename = my_malloc(strlen(file_map[fd]) + 1);
		filename = malloc(strlen(file_map[fd]) + 1);
		strcpy(filename, file_map[fd]);
//		filename[strlen(file_map[fd])] = '\0';
	}
//	pthread_mutex_unlock (&file_map_lock);
*/
	filename = malloc(strlen(fd_inode_map[fd].name) + 1);
	strcpy(filename, fd_inode_map[fd].name);
	ret = merge_iovec(&tmp, vec, count, offset);

	hash_value = external_log_hash(fd_inode_map[fd].inode_num, HASH_ITEM_NUM);


	//printf("insert try lock:%d", hash_value);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	//printf("insert already lock:%d", hash_value);
	p = &(hashtable[hash_value]);
	while(1) {
		if((*p) == NULL) {
			(*p) = malloc(sizeof(struct hash_item));
			(*p)->pathname = malloc(strlen(filename) + 1);
			(*p)->inode_num = fd_inode_map[fd].inode_num;
			strcpy((*p)->pathname, filename);
			(*p)->is_dirty = 1;
			(*p)->next = NULL;
			(*p)->fd = open(filename, O_WRONLY);
			(*p)->head = tmp;
			time(&(*p)->mtime);
			(*p)->root = ALLOC_QUEUE_ROOT();
			if(pthread_create(&(*p)->background_pid, NULL, background_write_fn, (void*) (*p))) {
				printf("create backgound_write_fn failed\n");
				exit(0);
			}
			(*p)->dirty_size = tmp->size;
			(*p)->size = tmp->size;
			(*p)->blocks = (tmp->size + BLOCK_SIZE - 1)/ BLOCK_SIZE;
			break;
		}
		if(!strcmp(filename, (*p)->pathname)) {
			(*p)->is_dirty = 1;
			(*p)->dirty_size += tmp->size;
			time(&(*p)->mtime);
			if(tmp->offset + tmp->size > (*p)->size) {
				(*p)->size = tmp->offset + tmp->size;
				if((*p)->blocks < ((*p)->size + BLOCK_SIZE - 1)/BLOCK_SIZE) {
					(*p)->blocks = ((*p)->size + BLOCK_SIZE - 1)/BLOCK_SIZE;
				}
			}
			insert_cache_item(&((*p)->head), tmp);
			break;
		}
		p = &((*p)->next);
	}
//	my_free(filename, strlen(file_map[fd]) + 1);
	free(filename);
	//printf("insert unlock:%d", hash_value);
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
	return ret;
}

static void log_op(int op, const char* path, void* obj) {
	uint64_t offset;
	struct descriptor_block desc;

	desc.sig = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	pthread_mutex_lock(&external_log_id_lock);
	desc.id = external_log_id;
	external_log_id++;
	pthread_mutex_unlock(&external_log_id_lock);
	desc.op = op;
	desc.path_size = strlen(path);
	desc.num_of_item = 0;
	pthread_mutex_lock(&external_log_offset_lock);
	offset = external_log_offset;
	external_log_offset += BLOCK_SIZE;
	pthread_mutex_unlock(&external_log_offset_lock);
	pwrite(external_log_fd, (char*) &desc, sizeof(struct descriptor_block),offset);
	pwrite(external_log_fd, path, desc.path_size, offset + sizeof(struct descriptor_block));
	if(op == EXTERNAL_LOG_TRUNCATE)
		pwrite(external_log_fd, (char*) obj, sizeof(uint64_t), offset + sizeof(struct descriptor_block) + desc.path_size);
	else if(op == EXTERNAL_LOG_RENAME) {
		pwrite(external_log_fd, (char*) obj, strlen((char*) obj) + 1, offset + sizeof(struct descriptor_block) + desc.path_size);
	}
//	fsync(external_log_fd);
}

int external_log_unlink(uint64_t ino) {
	int hash_value;
	int i;

	for(i = 0;i < NUM_FD;i++) {
		if(ino == fd_inode_map[i].inode_num) {
			log_op(EXTERNAL_LOG_UNLINK, fd_inode_map[ino].name, NULL);
			hash_value = external_log_hash(ino, HASH_ITEM_NUM);
			pthread_mutex_lock(&hashtable_locks[hash_value]);
			destroy_hash_item2(&hashtable[hash_value]);
			pthread_mutex_unlock(&hashtable_locks[hash_value]);
			break;
		}
	}

	return 0;
}

int external_log_truncate(uint64_t ino, uint64_t size) {
	int hash_value;
	struct cache_item** item;
	int index = -1;

	int i;

	for(i = 0;i < NUM_FD;i++) {
		if(ino == fd_inode_map[i].inode_num) {
			index = i;
			break;
		}
	}

	if(index == -1) {
		printf("no item in fd map\n");
		return 0;
	}


	log_op(EXTERNAL_LOG_TRUNCATE, fd_inode_map[index].name, (void*)&size);
	hash_value = external_log_hash(ino, HASH_ITEM_NUM);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	if(hashtable[hash_value]) {
		item = &(hashtable[hash_value]->head);
		hashtable[hash_value]->size = size;
		hashtable[hash_value]->blocks = (size + BLOCK_SIZE - 1)/BLOCK_SIZE;
		while(*item != NULL) {
			if((*item)->offset >= size) {
				destroy_cache_item((*item));
				(*item) = NULL;
				break;
			} else if((*item)->size + (*item)->offset <= size) {
				(*item) = (*item)->next;
			} else {
				destroy_cache_item((*item)->next);
				(*item)->next = NULL;
				(*item)->size = size - (*item)->offset;
				break;
			}
		}
	}
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
	return 0;
}

int external_log_stat(uint64_t ino, struct stat* obj) {
	int hash_value;
	struct hash_item* item;

	hash_value = external_log_hash(ino, HASH_ITEM_NUM);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	item = hashtable[hash_value];
	while(item != NULL) {
		if(ino == item->inode_num) {
			break;
		}
		item = item->next;
	}

	if(item != NULL) {
        if(item->size == -1) {
            item->size = obj->st_size;
            item->blocks = obj->st_blocks;
        } else {
            obj->st_size = item->size > obj->st_size ? item->size : obj->st_size;
            obj->st_blocks = item->blocks > obj->st_blocks ? item->blocks : obj->st_blocks;
        }
   	}
   	pthread_mutex_unlock(&hashtable_locks[hash_value]);
   	return 0;
}

struct hash_item* get_hash_item(int fd) {
	int hash_value;
	struct hash_item* item;

/*	if(file_map[fd] == NULL) 
		return NULL;
*/
	hash_value = external_log_hash(fd_inode_map[fd].inode_num, HASH_ITEM_NUM);
	item = hashtable[hash_value];
	while(item != NULL) {
		if(item->inode_num == fd_inode_map[fd].inode_num) {
			break;
		}
		item = item->next;
	}
	return item;
}

static int __external_log_read(struct cache_item* item, struct read_record** record, uint64_t size, uint64_t offset) {
	struct read_record* tmp;

	*record = NULL;
	tmp = NULL;
	while(item != NULL && item->offset < offset + size) {
		if(item->offset >= offset && offset + size > item->offset && offset + size <= item->offset + item->size) {
			if(*record == NULL) {
				*record = malloc(sizeof(struct read_record));
				tmp = *record;
			} else {
				tmp->next = malloc(sizeof(struct read_record));
				tmp = tmp->next;
			}
			tmp->size = offset + size - item->offset;
			tmp->next = NULL;
			tmp->offset = item->offset;
			tmp->data = malloc(tmp->size);
			memcpy(tmp->data, item->data, tmp->size);
		} else if(item->offset + item->size > offset && item->offset + item->size <= offset + size && item->offset <= offset) {
			if(*record == NULL) {
				*record = malloc(sizeof(struct read_record));
				tmp = *record;
			} else {
				tmp->next = malloc(sizeof(struct read_record));
				tmp = tmp->next;
			}
			tmp->size = item->offset + item->size - offset;
			tmp->offset = offset;
			tmp->next = NULL;
			tmp->data = malloc(tmp->size);
			memcpy(tmp->data, item->data + offset - item->offset, tmp->size);
		} else if(item->offset <= offset && offset + size <= item->offset + item->size){
			if(*record == NULL) {
				*record = malloc(sizeof(struct read_record));
				tmp = *record;
			} else {
				tmp->next = malloc(sizeof(struct read_record));
				tmp = tmp->next;
			}
			tmp->size = size;
			tmp->offset = offset;
			tmp->next = NULL;
			tmp->data = malloc(tmp->size);
			memcpy(tmp->data, item->data + offset - item->offset, tmp->size);
		} else if(item->offset >= offset && offset + size >= item->offset + item->size){
			if(*record == NULL) {
				*record = malloc(sizeof(struct read_record));
				tmp = *record;
			} else {
				tmp->next = malloc(sizeof(struct read_record));
				tmp = tmp->next;
			}
			tmp->size = item->size;
			tmp->offset = item->offset;
			tmp->next = NULL;
			tmp->data = malloc(tmp->size);
			memcpy(tmp->data, item->data, tmp->size);
		}
		item = item->next;
	}
	return 0;
}

int external_log_read(int fd, struct read_record** record, uint64_t size, uint64_t offset) {
	int hash_value;
	struct hash_item* item;

/*	if(file_map[fd] == NULL) {
		*record = NULL;
		return 0;
	}*/

	hash_value = external_log_hash(fd_inode_map[fd].inode_num, HASH_ITEM_NUM);
	//printf("read try lock:%d\n", hash_value);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	//printf("read already lock:%d\n", hash_value);
	item = hashtable[hash_value];
	while(item != NULL) {
		if(item->inode_num == fd_inode_map[fd].inode_num) {
			break;
		}
		item = item->next;
	}
	if(item == NULL) {
		*record = NULL;
		printf("can't find the item when read:%s ", fd_inode_map[fd].name);
		//printf("read unlock:%d\n", hash_value);
		pthread_mutex_unlock(&hashtable_locks[hash_value]);
		return 0;
	}
	__external_log_read(item->head, record, size, offset);
	//printf("read unlock:%d\n", hash_value);
	pthread_mutex_unlock(&hashtable_locks[hash_value]);
	return 0;
}

void *background_write_fn(void* obj) {
	struct queue_root* root = ((struct hash_item*) obj)->root;
	int fd = ((struct hash_item*) obj)->fd;
	struct write_to_real_path_para* paras;
	struct descriptor_block* desc;
	char* filename;
	char* data;
	struct record_item* records;
	int i; 
	uint64_t ino;
	struct hash_item* h_item;
	struct cache_item** head;
	struct cache_item* next;
	struct queue_head* item;
	uint64_t data_size;
	uint64_t free_data_size = 0;

	while(1) {
		item = queue_get(root);
//		printf("free_data_size%lu\n", free_data_size);
		if(item) {
			paras = (struct write_to_real_path_para*) item->data;
			ino = paras->ino;
			desc = (struct descriptor_block*)paras->records;
			filename = malloc(desc->path_size + 1);
			memcpy(filename, (char*) (paras->records) + sizeof(struct descriptor_block), desc->path_size);
			filename[desc->path_size] = '\0';
			records = (struct record_item*)((char*)(paras->records)  + sizeof(struct descriptor_block) + desc->path_size);
			data = paras->data;//(char*) records + desc->num_of_item*sizeof(struct record_item);


			data_size = 0;

//			fd = open(filename, O_WRONLY);
			if(fd > 0) {
				for(i = 0;i < desc->num_of_item;i++) {
					pwrite(fd, data, records[i].size, records[i].offset);
					data += records[i].size;
					data_size += records[i].size;
				}
			} else {
				printf("open %s failed \n", filename);
			}

			free_data_size += data_size;

			my_free(paras->data, data_size + sizeof(struct commit_block));
//			free(paras->data);
			int hash_value = external_log_hash(ino, HASH_ITEM_NUM);
			//printf("write try lock %d.\n", hash_value);
			pthread_mutex_lock(&hashtable_locks[hash_value]);
			//printf("write already lock %d\n", hash_value);
			h_item = hashtable[hash_value];
			while(h_item != NULL) {
				if(!strcmp(h_item->pathname, filename)) {
					head = &(h_item->head);
					for(i = 0;i < desc->num_of_item;i++) {
						while(*head != NULL) {
							if((*head)->is_dirty == 0 && (*head)->offset >= records[i].offset &&
								(*head)->offset + (*head)->size >= records[i].offset + records[i].size &&
								(*head)->version == records[i].version) {
								next = (*head)->next;

								my_free((*head)->data, (*head)->original_size);
								free(*head);
								(*head) = next;

							} else if((*head)->offset >= records[i].offset + records[i].size){
								break;
							} else {
								head = &((*head)->next);
							}
						}
					}		
					break;
				}
				h_item = h_item->next;
			}
			//printf("write to unlock %d", hash_value);
			pthread_mutex_unlock(&hashtable_locks[hash_value]);
//			free(paras->records);
			my_free(paras->records, sizeof(struct descriptor_block) + desc->path_size + 
					desc->num_of_item*sizeof(struct record_item));
			free(paras);
			free(filename);
			free(item);
			
/*			my_free(paras, sizeof(struct write_to_real_path_para));
			my_free(filename, strlen(filename) + 1);
			my_free(item, sizeof(struct queue_head));
*/		} else {
			sleep(1);
		}
	}
	return NULL;
}

void destroy_cache_item(struct cache_item* item) {
	struct cache_item* next;

	if(item == NULL) {
		return;
	}
	next = item->next;
	if(item->data != NULL)
		my_free(item->data, item->original_size);
	destroy_cache_item(next);
	free(item);
}

void destroy_hash_item2(struct hash_item** item) {
	struct hash_item* next;

	if(*item == NULL)
		return;

	next = (*item)->next;
	if((*item)->pathname != NULL)
		free((*item)->pathname);
	destroy_cache_item((*item)->head);
	free(*item);
	*item = next;
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



int external_log_flush(struct hash_item* item, pthread_mutex_t* lock) {
	int item_num;
	uint64_t size;
	struct cache_item* p;
	uint64_t offset;
	char* log_item;
	char* data;
	char* log_item_p;
	char* data_p;
	uint64_t desc_size;
	int ret;
	uint32_t id;

	if(item == NULL) {
		pthread_mutex_unlock(lock);
		return -1;
	}

	item->dirty_size = 0;

	if(!item->is_dirty) {
		pthread_mutex_unlock(lock);
		return 0;
	}

	item_num = 0;
	size = 0;
	p = item->head;
	while(p != NULL) {
		if(p->is_dirty) {
			item_num++;
			size += p->size;
		}
		p = p->next;
	}

	item->is_dirty = 0;

	desc_size = sizeof(struct descriptor_block) + 
			strlen(item->pathname) + item_num*(sizeof(struct record_item));
//	log_item = malloc(desc_size);
//	data = malloc(size + sizeof(struct commit_block));
	my_posix_memalign((void*)&log_item, BLOCK_SIZE, desc_size);
	my_posix_memalign((void*)&data, BLOCK_SIZE, size + sizeof(struct commit_block));

/*	posix_memalign((void*)&log_item, BLOCK_SIZE, desc_size);
	posix_memalign((void*)&data, BLOCK_SIZE, size + sizeof(struct commit_block));
*/
	pthread_mutex_lock(&external_log_offset_lock);
	offset = external_log_offset;
	external_log_offset += UPPER(desc_size + size + sizeof(struct commit_block), BLOCK_SIZE);	
	pthread_mutex_unlock(&external_log_offset_lock);

	*((uint32_t*) log_item) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	log_item_p = log_item + sizeof(uint32_t);
	pthread_mutex_lock(&external_log_id_lock);
	id = external_log_id;
	external_log_id++;
	pthread_mutex_unlock(&external_log_id_lock);
	*((uint32_t*) log_item_p) = id;
	log_item_p += sizeof(uint32_t);
	*((uint32_t*) log_item_p) = EXTERNAL_LOG_WRITEV;
	log_item_p += sizeof(uint32_t);
	*((int *) log_item_p) = item_num;
	log_item_p += sizeof(int);
	*((int *) log_item_p) = strlen(item->pathname);
	log_item_p += sizeof(int);
	memcpy(log_item_p, item->pathname, strlen(item->pathname));
	log_item_p += strlen(item->pathname);

	p = item->head;
	data_p = data;
	while(p != NULL) {
		if(p->is_dirty) {
			*((uint64_t*) log_item_p) = p->size;
			log_item_p += sizeof(uint64_t);
			*((uint64_t*) log_item_p) = p->offset;
			log_item_p += sizeof(uint64_t);
			*((uint64_t*) log_item_p) = p->version;
			log_item_p += sizeof(uint64_t);
			memcpy(data_p, p->data, p->size);
			data_p += p->size;
			p->is_dirty = 0;
		}
		p = p->next;
	}

	//printf("flush unlock:%d\n", external_log_hash(item->pathname, HASH_ITEM_NUM));
	pthread_mutex_unlock(lock);

//	memcpy(log_item_p, data, size);
//	log_item_p += size;
	*((uint32_t*) data_p) = EXTERNAL_LOG_METADATA_BLOCK_SIG;
	data_p += sizeof(uint32_t);
	*((uint32_t*) data_p) = id;
	//need checksum to guarantee write order	

	pwrite(external_log_fd, log_item, desc_size, offset);
	pwrite(external_log_fd, data, size + sizeof(struct commit_block), offset + desc_size);
	ret = fsync(external_log_fd);
	if(ret < 0) {
		/*
		my_free(log_item, desc_size);
		my_free(data, size + sizeof(struct commit_block));*/
		free(log_item);
		free(data);
		goto out;
	}
	struct write_to_real_path_para* paras = malloc(sizeof (struct write_to_real_path_para));
	if(paras != NULL) {
		paras->data = data;
		paras->records = log_item;
		paras->ino = item->inode_num;
	}
	struct queue_head* q = malloc(sizeof(struct queue_head));
	q->data = (void*) paras;
	q->next = NULL;
	
	queue_put((void*) q, item->root);
/*	pthread_t pid;
	pthread_create(&pid, NULL, write_to_real_path, (void*) paras);*/

out:
	return ret;
}



int external_log_flush_for_fsync(int fd) {
	int ret = 0;
	int hash_value;
	struct hash_item* item;
	int flag = 1;

	hash_value = external_log_hash(fd_inode_map[fd].inode_num, HASH_ITEM_NUM);
	//printf("fsync try lock %d", hash_value);
	pthread_mutex_lock(&hashtable_locks[hash_value]);
	//printf("fsync already lock %d", hash_value);
	item = hashtable[hash_value];
	while(item != NULL) {
		if(item->inode_num == fd_inode_map[fd].inode_num) {
			if(item->is_dirty) {
				ret = external_log_flush(item, &hashtable_locks[hash_value]);
				flag = 0;
			}
			break;
		}
		item = item->next;
	}
	if(flag) {
		//printf("fsync unlock %d", hash_value);
		pthread_mutex_unlock(&hashtable_locks[hash_value]);
	}
	return ret;
}

/*

static struct iovec* get_iovec(int count, char flag) {
	struct iovec* vec;
	int i,j;

	vec = my_malloc(sizeof(struct iovec)*count);
	for(i = 0;i < count;i++) {
		vec[i].iov_len = i + 1;
		vec[i].iov_base = my_malloc(i + 1);
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

static struct cache_item* get_cache_item(int count, uint64_t offset, char flag) {
	struct cache_item* cache;
	struct iovec* vec;

	vec = get_iovec(count, flag);
	merge_iovec(&cache, vec, count, offset);
	return cache;
}

static void test_merge_iovec() {
	struct cache_item* cache;
	int i;

	for(i = 0;i < 10;i++) {
		cache = get_cache_item(5+i, i*1000, 'a' + i);
		printf("data:%s size:%lu offset:%lu is_dirty:%d\n", cache->data, 
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
		file_map[i] = my_malloc(i + 2);
		for(j = 0;j < i + 1;j++) {
			file_map[i][j] = 'a';
		}
		file_map[i + 1] = '\0';
	}

	pthread_mutex_init(&file_map_lock, NULL);
	pthread_mutex_init(&external_log_id_lock, NULL);
	pthread_mutex_init(&external_log_offset_lock, NULL);
	
	external_log_fd = open("/home/dashu/external_log", O_RDWR | O_DIRECT);
	if(external_log_fd <= 0) {
		printf("open failed\n");
		exit(0);
	}
	external_log_offset = 0;
	return 0;
}


static int external_log_finish_for_test() {
	int i;

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
	return 0;
}

void print_cache_item(struct cache_item* item , int i) {
	if(item == NULL)
		return;
	printf("i:%d data:%s size:%lu offset:%lu is_dirty:%d \n", i, item->data, 
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



int main() {
	struct read_record* rec;
	external_log_init_for_test();
	insert_item_test();

	traversal_hashtable();
//	fsync_test();
	external_log_read(0, &rec, 10, 1000);
	if(rec == NULL) {
		printf("null\n");
	} else {
		printf("%s  %lu %lu\n", (char*)rec->data, rec->offset, rec->size);
	}
	show_log_content();
	external_log_finish_for_test();
	return 0;


}
*/

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
	int i;

	fd = open("/home/dashu/sdb1/external_log", O_RDWR);
	read(fd, desc, BLOCK_SIZE);
	read(fd, data, BLOCK_SIZE);
	read(fd, commit, BLOCK_SIZE);
	d = (struct descriptor_block*) desc;

	while(d->sig == EXTERNAL_LOG_METADATA_BLOCK_SIG) {
		desc_p = desc + sizeof(struct descriptor_block);
		c = (struct commit_block*) commit;
		pathname = my_malloc(d->path_size + 1);
		memcpy(pathname, desc_p, d->path_size);
		pathname[d->path_size] = '\0';
		desc_p += d->path_size;
		printf("pathname:%s sig:%u id:%u num_of_item:%d path_size:%d\n", 
			pathname, d->sig, d->id, d->num_of_item, d->path_size);
		item = (struct record_item*)desc_p;
		for(i = 0;i < d->num_of_item;i++) {
			printf("size:%lu offset:%lu\n", item->size, item->offset);
			item++;
		}
		printf("data:%s\n", item);
		printf("commit:%u id:%u\n", c->sig, c->id);
		if(read(fd, desc, BLOCK_SIZE) <=0 || read(fd, data, BLOCK_SIZE) <= 0 ||
			read(fd, commit, BLOCK_SIZE) <= 0) {
			break;
		}
		free(pathname);
		d = (struct descriptor_block*) desc;
	}

}

void print_segment_tree(struct segment_tree_node* root) {
	if(root == NULL) {
		printf("null\n");
		return;
	}
	printf("root:\n");
	printf("offset:%lu size:%lu data:%s\n", root->item->offset, 
		root->item->size, root->item->data);
	printf("left:\n");
	print_segment_tree(root->left);
	printf("right:\n");
	print_segment_tree(root->right);
}

void segment_tree_test() {
	int i;
	struct segment_tree_node* root = malloc(sizeof(struct segment_tree_node));
	
	root->left = NULL;
	root->right = NULL;
	root->parent = NULL;
	root->item = malloc(sizeof(struct cache_item));
	root->item->size = 10;
	root->item->offset = 100;
	root->item->version = 0;
	root->item->data = malloc(10);
	for(i = 0;i < 10;i++)
		root->item->data[i] = 'a';



	struct cache_item* tmp = malloc(sizeof(struct cache_item));
	tmp->size = 10;
	tmp->offset = 20;
	tmp->version = 0;
	tmp->data = malloc(tmp->size);
	for(i = 0;i < 10;i++)
		tmp->data[i] = 'b';
	segment_tree_insert(root, tmp);


	tmp = malloc(sizeof(struct cache_item));
	tmp->size = 10;
	tmp->offset = 180;
	tmp->version = 0;
	tmp->data = malloc(tmp->size);
	for(i = 0;i < 10;i++)
		tmp->data[i] = 'c';
	segment_tree_insert(root, tmp);



	tmp = malloc(sizeof(struct cache_item));
	tmp->size = 12;
	tmp->offset = 90;
	tmp->version = 0;
	tmp->data = malloc(tmp->size);
	for(i = 0;i < 12;i++)
		tmp->data[i] = 'd';
	printf("root:%s\n", root->item->data);
	segment_tree_insert(root, tmp);

	tmp = malloc(sizeof(struct cache_item));
	tmp->size = 12;
	tmp->offset = 108;
	tmp->version = 0;
	tmp->data = malloc(tmp->size);
	for(i = 0;i < 12;i++)
		tmp->data[i] = 'e';
	segment_tree_insert(root, tmp);


	print_segment_tree(root);

	tmp = malloc(sizeof(struct cache_item));
	tmp->size = 20;
	tmp->offset = 95;
	tmp->version = 0;
	tmp->data = malloc(tmp->size);
	for(i = 0;i < 20;i++)
		tmp->data[i] = 'f';
	segment_tree_insert(root, tmp);

	print_segment_tree(root);

	printf("7 100");
	struct read_record* record = NULL;
	segment_tree_read(root, &record, 7, 100);
	while(record != NULL) {
		printf("offset:%lu size:%lu data:%s\n", record->offset, record->size, record->data);
		record = record->next;
	}

	printf("15 100");
	record = NULL;
	segment_tree_read(root, &record, 15, 100);
	while(record != NULL) {
		printf("offset:%lu size:%lu data:%s\n", record->offset, record->size, record->data);
		record = record->next;
	}

	printf("15 90");
	record = NULL;
	segment_tree_read(root, &record, 15, 90);
	while(record != NULL) {
		printf("offset:%lu size:%lu data:%s\n", record->offset, record->size, record->data);
		record = record->next;
	}

	printf("30 90");
	record = NULL;
	segment_tree_read(root, &record, 30, 90);
	while(record != NULL) {
		printf("offset:%lu size:%lu data:%s\n", record->offset, record->size, record->data);
		record = record->next;
	}


	printf("10 105");
	record = NULL;
	segment_tree_read(root, &record, 10, 105);
	while(record != NULL) {
		printf("offset:%lu size:%lu data:%s\n", record->offset, record->size, record->data);
		record = record->next;
	}

	external_log_fd = open("/home/dashu/sdb1/external_log", O_RDWR);
//	lseek(external_log_fd, 4096, 0);
//	write(external_log_fd, " ", 1);
	struct hash_item t;
	t.tree_root = root;
	segment_tree_fsync(&t);

	show_log_content();

}



void main() {
	uint64_t size = 6;
	size = size*1024*1024*1024; //6G
	my_malloc_init(size);
	segment_tree_test();
}
