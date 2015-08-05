#include "eth.h"

int samemac(const __u8 *a, const __u8 *b)
{
	return !strncasecmp(a, b, ETH_ALEN);
}
