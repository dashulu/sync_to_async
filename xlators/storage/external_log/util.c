#include "util.h"
#include <stdlib.h>
#include <stdio.h>

unsigned int external_log_hash(char* str, int upper_bound) {
	unsigned int h;
	unsigned char *p;

	if(!str)
		return 0;

	for(h = 0,p = (unsigned char *) str;*p; p++)
		h = 31 * h + *p;

	return h % upper_bound;
}

