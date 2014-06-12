#include <pthread.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "queue.h"

#ifndef EXTERNAL_LOG_H
#define EXTERNAL_LOG_H


struct file_info {
	uint64_t inode_num;
	char* name;
};

struct read_record {
	void* data;
	uint64_t size;
	uint64_t offset;
	struct read_record* next;
};


struct write_to_real_path_para{
	char* records;
	char* data;
	uint64_t ino;
};



// log structure in the disk
struct record_item {
//	uint32_t begin;  // the begin of data for this item in the log file;
	uint64_t size;	// size of this data
	uint64_t offset;	// the place that data needs to write;
	uint64_t version;
//	char	substitute_flag; // if the first 4 byte is the same to sig, it will be substitute by 0x0000;
};

struct descriptor_block {
	uint32_t sig;
	uint32_t id;
	uint32_t op;
	int num_of_item;
	int path_size;
//	char* pathname;
//	struct record_item* items;
};

struct commit_block {
	uint32_t sig;
	uint32_t id;
	uint32_t checksum;
};


// data structure for management in memory
struct record_of_data {
	char* path;
	uint64_t size;
	uint64_t offset;
	char* data;
	struct record_of_data *pre;
	struct record_of_data *next;
};



struct cache_item {
	char* data;
	uint64_t size;
	uint64_t original_size;
	uint64_t offset;
	uint32_t external_log_id;
	uint32_t finish_log_id;
	int is_dirty;
	uint32_t version;
//	bool is_commiting;
	struct cache_item* next;
	pthread_mutex_t lock;
};

struct hash_item {
	char* pathname;
	uint64_t inode_num;
	int is_dirty;
	uint64_t dirty_size; 
	int64_t size;
	int64_t blocks;
	time_t mtime;

	int fd;

	pthread_t background_pid;
	struct queue_root* root;
	struct segment_tree_node* tree_root;


//	pthread_mutex_t lock;
//	bool is_dirty;
//	bool is_busy; // for write behind thread, if busy flag is true, it means some thread are read/write the file
	struct hash_item *next;
	struct cache_item *head;
//	spinlock_t  hash_lock = SPIN_LOCK_UNLOCKED; 
};

#define NUM_FD 2048
#define HASH_ITEM_NUM 4099
#define EXTERNAL_LOG_METADATA_BLOCK_SIG 0xbeefbeef
#define BLOCK_SIZE 4096
#define MAX_DIRTY_SIZE 52428800  // 50M
#define TIME_TO_FLUSH 5

#define EXTERNAL_LOG_WRITEV 1
#define EXTERNAL_LOG_TRUNCATE 2
#define EXTERNAL_LOG_UNLINK 3
#define EXTERNAL_LOG_RENAME 4



// a map from fd to the path of file. fd is the index;
//char* file_map[NUM_FD];
struct file_info fd_inode_map[NUM_FD];
pthread_mutex_t file_map_lock;

int external_log_fd;
uint64_t external_log_offset;
pthread_mutex_t external_log_offset_lock;


pthread_t background_pid;

uint32_t external_log_id;
pthread_mutex_t external_log_id_lock;

struct hash_item* hashtable[HASH_ITEM_NUM];
pthread_mutex_t hashtable_locks[HASH_ITEM_NUM];

int init_hashtable(struct hash_item* hashtable, int num);
int insert_item(int fd, struct iovec *vec, int count, uint64_t offset);
void destroy_hash_item(struct hash_item* item);
//unsigned int external_log_hash(const char* str, int upper_bound);
unsigned int external_log_hash(uint64_t num, int upper_bound);
int external_log_init();
int external_log_finish();
int external_log_flush_for_fsync(int fd);
int external_log_read(int fd, struct read_record** record, uint64_t size, uint64_t offset);
//struct hash_item* get_hash_item(int fd);
//int external_log_stat_by_fd(int fd, struct stat* obj);
int external_log_stat(uint64_t ino, struct stat* obj);
//int external_log_stat2(uint64_t ino, struct stat* obj);
int external_log_truncate(uint64_t ino, uint64_t size);
int external_log_unlink(uint64_t ino);
int external_log_rename(uint64_t ino, const char* old_name, char* new_name);
int segment_tree_insert_item(int fd, struct iovec *vec, int count, uint64_t offset);

#endif

#ifndef SEGMENT_TREE
#define SEGMENT_TREE
struct segment_tree_node {
	struct segment_tree_node* parent;
	struct segment_tree_node* left;
	struct segment_tree_node* right;
	struct cache_item* item;
};



#endif