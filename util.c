#include "util.h"

void debug_print(const char *str)
{
#ifdef	_DEBUG_
	printf(str);
#endif	
}

__u32 __align(__u32 size)
{
	return ((size + ALIGN - 1) & ~(ALIGN - 1));
}

