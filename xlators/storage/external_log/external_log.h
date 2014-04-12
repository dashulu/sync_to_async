#include <pthread.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>


// log structure in the disk
struct record_item {
//	uint32_t begin;  // the begin of data for this item in the log file;
	uint32_t size;	// size of this data
	uint32_t offset;	// the place that data needs to write;
//	char	substitute_flag; // if the first 4 byte is the same to sig, it will be substitute by 0x0000;
};

struct descriptor_block {
	uint32_t sig;
	uint64_t id;
	int num_of_item;
	int path_size;
//	char* pathname;
//	struct record_item* items;
};

struct commit_block {
	uint32_t sig;
	uint64_t id;
};


// data structure for management in memory
struct record_of_data {
	char* path;
	uint32_t size;
	uint32_t offset;
	char* data;
	struct record_of_data *pre;
	struct record_of_data *next;
};



struct cache_item {
	char* data;
	uint32_t size;
	uint32_t offset;
	int is_dirty;
//	bool is_commiting;
	struct cache_item* next;
	pthread_mutex_t lock;
};

struct hash_item {
	char* pathname;
//	pthread_mutex_t lock;
//	bool is_dirty;
//	bool is_busy; // for write behind thread, if busy flag is true, it means some thread are read/write the file
	struct hash_item *next;
	struct cache_item *head;
//	spinlock_t  hash_lock = SPIN_LOCK_UNLOCKED; 
};

#define NUM_FD 1024
#define HASH_ITEM_NUM 10
#define EXTERNAL_LOG_METADATA_BLOCK_SIG 0xbeefbeef
#define BLOCK_SIZE 4096


// a map from fd to the path of file. fd is the index;
char* file_map[NUM_FD];
pthread_mutex_t file_map_lock;

int external_log_fd;
uint64_t external_log_offset;
pthread_mutex_t external_log_offset_lock;

int external_log_id;
pthread_mutex_t external_log_id_lock;

struct hash_item* hashtable[HASH_ITEM_NUM];
pthread_mutex_t hashtable_locks[HASH_ITEM_NUM];

int init_hashtable(struct hash_item* hashtable, int num);
int insert_item(int fd, struct iovec *vec, int count, uint32_t offset);
