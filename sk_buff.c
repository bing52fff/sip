#include "util.h"
#include "sk_buff.h"

struct sk_buff* skb_alloc(__u32 size)
{
	struct sk_buff *skb = (struct sk_buff*) malloc(sizeof(struct sk_buff));
	if (!skb)
	{
		debug_print("malloc skb error\n");
		return NULL;
	}
	memset(skb, 0, sizeof(struct sk_buff));
	size = __align(size);
	skb->head = (__u8*) malloc(size);
	if (!skb->head)
	{
		debug_print("malloc data error\n");
		free(skb);
		return NULL;
	}
	skb->data = skb->head;
	skb->tail = skb->end = skb->data + size;
	skb->next = NULL;
	skb->tot_len = 0;
	skb->len = 0;
	return skb;
}
void skb_free(struct sk_buff *skb)
{
	if (skb)
	{
		if (skb->head)
			free(skb->head);
		free(skb);
	}
}
void skb_clone(struct sk_buff *from, struct sk_buff *to)
{
	assert(from && to);
	memcpy(to->head, from->head, sizeof(struct sk_buff));
	to->pyh.ethh = (struct sip_ethhdr*) skb_put(to, ETH_ALEN);
	to->nh.iph = (struct sip_iphdr*) skb_put(to, IPHDR_LEN);
}
__u8* skb_put(struct sk_buff *skb, __u32 len)
{
	assert(skb);
	__u8* tmp = skb->tail;
	skb->tail += len;
	skb->len -= len;
	return tmp;
}
