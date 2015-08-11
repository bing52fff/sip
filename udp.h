#ifndef	__UDP_H
#define	__UDP_H

#include "util.h"
#include "socket.h"
#include "sk_buff.h"
#include "net_device.h"

#define	UDP_HTABLE_SIZE	128
#define UDP_FLAGS_NOCHKSUM	0

struct sip_udphdr
{
	__be16	source;
	__be16	dest;
	__u16	len;
	__be16	check;
};

struct udp_pcb
{
	struct in_addr	ip_local;
	__u16			port_local;
	struct in_addr	ip_remote;
	__u16			port_remote;
	__u8			tos;
	__u8			ttl;
	__u8			flags;
	struct sock		*sock;
	struct udp_pcb	*next;
	struct udp_pcb	*prev;
};

int udp_input(struct sk_buff *skb, struct net_device *dev);
int udp_output(struct sk_buff *skb, struct net_device *dev, struct udp_pcb *pcb, struct in_addr *src, struct in_addr *dest);
struct udp_pcb* udp_new();
void udp_remove(struct udp_pcb *pcb);
int udp_bind(struct udp_pcb *pcb, struct in_addr *ipaddr, __u16 port);
int udp_sendto(struct net_device *dev, struct udp_pcb *pcb, struct sk_buff *skb, struct in_addr *dst_ip, __u16 dst_port);
__u16 udp_chksum(struct sk_buff *skb, struct in_addr *src, struct in_addr *dest, __u8 proto, __u16 proto_len);

#endif	//udp.h
