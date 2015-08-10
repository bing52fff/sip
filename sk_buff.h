#ifndef __SKBUFF_H
#define __SKBUFF_H

#include "util.h"

#define	CHECKSUM_NONE	0

struct sk_buff
{
	struct sk_buff *next;
	union
	{
		struct sip_tcphdr	*tcph;
		struct sip_udphdr	*udph;
		struct sip_icmphdr	*icmph;
		struct sip_igmphdr	*igmph;
		__u8				*raw;
	} th;	
	union
	{
		struct sip_iphdr	*iph;
		struct sip_arphdr	*arph;
		__u8				*raw;
	} nh;
	union
	{
		struct sip_ethhdr	*ethh;
		__u8				*raw;
	} pyh;

	struct net_device	*dev;
	__be16				protocol;
	__u32				tot_len;
	__u32				len;
	__u8				csum;
	__u8				ip_summed;
	__u8				*head,
						*data,
						*tail,
						*end;
};

struct sk_buff* skb_alloc(__u32 size);
void skb_free(struct sk_buff *skb);
void skb_clone(struct sk_buff *from, struct sk_buff *to);
__u8* skb_put(struct sk_buff *skb, __u32 len);

#endif	//skbuff.h
