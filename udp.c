#include "udp.h"

static struct udp_pcb* udp_pcbs[UDP_HTABLE_SIZE];
static __u16 found_a_port()
{
	static __u32 index = 1024;
	index ++;
	return (__u16)(index & 0xffff);
}

int udp_input(struct sk_buff *skb, struct net_device *dev)
{
	__u16 port = ntohs(skb->th.udph->dest);
	struct udp_pcb *upcb = NULL;
	for (upcb = udp_pcbs[port%UDP_HTABLE_SIZE]; upcb != NULL; upcb = upcb->next)
	{
		if (upcb->port_local == port)
			break;
	}
	if (!upcb)
		return -1;
	struct sock *sock = upcb->sock;
	if (!sock)
		return -1;
	struct sk_buff *recvl = sock->skb_recv;
	if (!recvl)
	{
		sock->skb_recv = skb;
		skb->next = NULL;
	}
	else
	{
		for (; recvl->next != NULL; upcb = upcb->next)
			;
		recvl->next = skb;
		skb->next = NULL;
	}
	sem_post(&sock->sem_recv);
	return 0;
}
int udp_output(struct sk_buff *skb, struct net_device *dev, struct udp_pcb *pcb, struct in_addr *src, struct in_addr *dest)
{
	ip_output(skb, dev, src, dest, pcb->ttl, pcb->tos, IPPROTO_UDP);
}
struct udp_pcb* udp_new()
{
	struct udp_pcb *pcb = NULL;
	pcb = (struct udp_pcb*) malloc(sizeof(struct udp_pcb));
	if (pcb != NULL)
	{
		memset(pcb, 0, sizeof(struct udp_pcb));
		pcb->ttl = 255;
	}
	return pcb;
}
void udp_remove(struct udp_pcb *pcb)
{
	struct udp_pcb *pcb_t;
	int i = 0;
	if (!pcb)
	{
		return ;
	}
	pcb_t = udp_pcbs[pcb->port_local%UDP_HTABLE_SIZE];
	if (!pcb_t)
	{
		;
	}
	else if (pcb_t == pcb)
		udp_pcbs[pcb->port_local%UDP_HTABLE_SIZE];
	else
	{
		for (; pcb_t->next != NULL; pcb_t = pcb_t->next)
		{
			if (pcb_t->next == pcb)
				pcb_t->next = pcb->next;
		}
	}
	free(pcb);
}
int udp_bind(struct udp_pcb *pcb, struct in_addr *ipaddr, __u16 port)
{
	struct udp_pcb *ipcb;
	__u8 rebind = 0;
	for (ipcb = udp_pcbs[port&(UDP_HTABLE_SIZE-1)]; ipcb != NULL; ipcb = ipcb->next)
	{
		if (pcb == ipcb)
			rebind = 1;
	}
	pcb->ip_local.s_addr = ipaddr->s_addr;
	if (port == 0)
	{
#define	UDP_PORT_RANGE_START	4096
#define	UDP_PORT_RANGE_END		0x7fff
		port = found_a_port();
		ipcb = udp_pcbs[port];
		while ((ipcb != NULL) && (port != UDP_PORT_RANGE_END))
		{
			if (ipcb->port_local == port)
			{
				port = found_a_port();
				ipcb = udp_pcbs[port];
			}
			else
			{
				ipcb = ipcb->next;
			}
		}
		if (ipcb != NULL)
			return -1;
	}
	pcb->port_local = port;
	if (rebind == 0)
	{
		pcb->next = udp_pcbs[port];
		udp_pcbs[port] = pcb;
	}
	return 0;
}
int udp_sendto(struct net_device *dev, struct udp_pcb *pcb, struct sk_buff *skb, struct in_addr *dst_ip, __u16 dst_port)
{
	struct sip_udphdr *udphdr;
	struct in_addr *src_ip;
	int err;
	if (pcb->port_local == 0)
	{
		err = udp_bind(pcb, &pcb->ip_local, pcb->port_local);
		if (err != 0)
			return err;
	}
	udphdr = skb->th.udph;
	udphdr->source = htons(pcb->port_local);
	udphdr->dest = htons(dst_port);
	udphdr->check = 0x0000;
	if (pcb->ip_local.s_addr == 0)
		src_ip = &dev->ip_host;
	else
		src_ip = &pcb->ip_local;
	udphdr->len = htons(skb->len);
	if ((pcb->flags & UDP_FLAGS_NOCHKSUM) == 0)
	{
		udphdr->check = udp_chksum(skb, src_ip, dst_ip, IPPROTO_UDP, skb->len);
		if (udphdr->check = 0x0000)
			udphdr->check = 0xffff;
	}
	err = udp_output(skb, dev, pcb, src_ip, dst_ip);
	return err;
}
__u16 udp_chksum(struct sk_buff *skb, struct in_addr *src, struct in_addr *dest, __u8 proto, __u16 proto_len)
{
	__u32 acc = 0;
	__u8 swapped = 0;
	{
		acc += sip_chksum(skb->data, skb->end - skb->data);
		while ((acc >> 16) != 0)
		{
			acc = (acc & 0xffffUL) + (acc >> 16);
		}
		if (skb->len % 2 != 0)
		{
			swapped = 1 - swapped;
			acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
		}
	}
	if (swapped)
		acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
	acc += (src->s_addr & 0xffffUL);
	acc += ((src->s_addr >> 16) & 0xffffUL);
	acc += (dest->s_addr & 0xffffUL);
	acc += ((dest->s_addr >> 16) & 0xffffUL);
	acc += (__u32)htons((__u16)proto);
	acc += (__u32)htons(proto_len);
	while ((acc >> 16) != 0)
		acc = (acc & 0xffffUL) + (acc >> 16);
	return (__u16)~(acc & 0xffffUL);
}
