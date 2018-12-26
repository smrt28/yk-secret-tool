
#include <stdlib.h>

void * alloc_safe_mem(size_t req_sz) {
	return malloc(req_sz);
}

void _free_safe_mem(void *mem) {
	if (!mem) return;
	free(mem);
}

