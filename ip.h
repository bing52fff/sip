#ifndef __IP_H
#define __IP_H

#include "util.h"
#include "sk_buff.h"
#include "net_device.h"

#define	IPHDR_LEN	20

struct sip_iphdr
{
#if	defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
			version:4;
#elif	defined(__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
			ihl:4;
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__be16	check;
	__be32	saddr;
	__be32	daddr;
};

struct sip_reass
{
	struct sip_reass	*next;
	struct sk_buff		*skb;
	struct sip_iphdr	*iphdr;
	__u16				datagram_len;
	__u8				flags;
	__u8				timer;
};

int ip_input(struct sk_buff *skb, struct net_device *dev);
inline int IP_IS_BROADCAST(struct net_device *dev, __be32 ip);
int ip_output(struct sk_buff *skb, struct net_device *dev, struct in_addr *src, struct in_addr *dest, __u8 ttl, __u8 tos, __u8 proto);
struct sk_buff* sip_reassemble(struct sk_buff *skb);

#endif	//ip.h
