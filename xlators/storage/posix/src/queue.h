#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>

struct queue_root;

#define ONMEMINODE	0
#define ONDISKINODE	1

struct queue_head {
	char* data;
	struct queue_head *next;
};

struct queue_root *ALLOC_QUEUE_ROOT(void);
void INIT_QUEUE_HEAD(struct queue_head *head);

void queue_put(struct queue_head *new,
	       struct queue_root *root);

struct queue_head *queue_get(struct queue_root *root);

#endif // QUEUE_H
