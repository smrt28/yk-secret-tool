#ifndef SAFE_MEM_H
#define SAFE_MEM_H

void * alloc_safe_mem(size_t req_sz);
void _free_safe_mem(void *mem);

#define free_safe_mem(x) \
	_free_safe_mem((void *)(x))

#endif
