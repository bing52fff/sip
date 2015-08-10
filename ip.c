#include "ip.h"
#include "icmp.h"
#include "udp.h"

int ip_input(struct sk_buff *skb, struct net_device *dev)
{
	int retval = 0;
	if (skb->len < 0)
	{
		debug_print("skb data len invalid\n");
		goto ip_error;
	}
	if (skb->nh.iph->version != 4)
	{
		debug_print("version error\n");
		goto ip_error;
	}
	__u16 hlen = skb->nh.iph->ihl << 2;
	if (hlen < IPHDR_LEN)
	{
		debug_print("header len invalid\n");
		goto ip_error;
	}
	if (skb->tot_len - ETH_HLEN < ntohs(skb->nh.iph->tot_len))
	{
		debug_print("total len invalid\n");
		goto ip_error;
	}
	if (hlen < ntohs(skb->nh.iph->tot_len))
	{
		debug_print("header len invalid\n");
		goto ip_error;
	}
	if (sip_chksum(skb->nh.raw, IPHDR_LEN))
	{
		debug_print("ip check sum mismatch\n");
		goto ip_error;
	}
	if ((skb->nh.iph->daddr != dev->ip_host.s_addr &&  !IP_IS_BROADCAST(dev, skb->nh.iph->daddr)) || IP_IS_BROADCAST(dev, skb->nh.iph->saddr))
	{
		debug_print("ip address invalid\n");
		goto ip_error;
	}
	if ((ntohs(skb->nh.iph->frag_off) & 0x3fff) != 0)
	{
		skb = sip_reassemble(skb);
		if (!skb)
		{
			retval = 0;
			goto out;
		}
	}
	
	switch (ntohs(skb->nh.iph->protocol))
	{
	case IPPROTO_ICMP:
		skb->th.icmph = (struct sip_icmphdr*)skb_put(skb, sizeof(struct sip_icmphdr));
		icmp_input(skb, dev);
		break;
	case IPPROTO_UDP:
		skb->th.udph = (struct sip_udphdr*)skb_put(skb, sizeof(struct sip_udphdr));
		udp_input(skb, dev);
		break;
	default:
		break;
	}
out:
	return retval;
ip_error:
	skb_free(skb);
	retval = -1;
	return retval;
}
int IP_IS_BROADCAST(struct net_device *dev, __be32 ip)
{
	int retval = 1;
	if ((ip == IP_ADDR_ANY_VALUE) || (~ip == IP_ADDR_ANY_VALUE))
	{
		retval = 1;
		goto out;
	}
	else if (ip == dev->ip_host.s_addr)
	{
		retval = 0;
		goto out;
	}
	else if (((ip & dev->ip_netmask.s_addr) == (dev->ip_host.s_addr & dev->ip_netmask.s_addr)) && ((ip & ~dev->ip_netmask.s_addr) == (IP_ADDR_BROADCAST_VALUE & ~dev->ip_netmask.s_addr)))
	{
		retval = 1;
		goto out;
	}
	else
		retval = 0;
out:
	return retval;
}
struct sk_buff* sip_reassemble(struct sk_buff *skb)
{
	return NULL;
}
int ip_output(struct sk_buff *skb, struct net_device *dev, struct in_addr *src, struct in_addr *dest, __u8 ttl, __u8 tos, __u8 proto)
{
	struct sip_iphdr *iph = skb->nh.iph;
	iph->protocol = proto;
	iph->tos = tos;
	iph->ttl = ttl;
	iph->daddr = dest->s_addr;
	iph->saddr = src->s_addr;
	iph->check = 0;
	iph->check = sip_chksum(skb->nh.raw, sizeof(struct sip_iphdr));
	skb->len = skb->tot_len;
	if (skb->len > dev->mtu)
		skb = ip_frag(skb, dev);
	dev->output(skb, dev);
	return 0;
}
struct sk_buff* ip_frag(struct sk_buff *skb, struct net_device *dev)
{
	__u8 frag_num = 0;
	__u16 tot_len = ntohs(skb->nh.iph->tot_len);
	__u8 mtu = dev->mtu;
	__u8 half_mtu = (mtu+1)/2;
	frag_num = (tot_len - IPHDR_LEN + half_mtu) / (mtu - IPHDR_LEN -ETH_HLEN);
	__u16 i = 0;
	struct sk_buff *skb_h = NULL, *skb_t = NULL, *skb_c = NULL;
	for (i = 0, skb->tail = skb->head; i < frag_num; i ++)
	{
		if (i == 0)
		{
			skb_t = skb_alloc(mtu);
			skb_t->pyh.raw = skb_put(skb_t, ETH_HLEN);
			skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);
			memcpy(skb_t->head, skb->head, mtu);
			skb_put(skb, mtu);
			skb_t->nh.iph->frag_off = htons(0x2000);
			skb_t->nh.iph->tot_len = htons(mtu - ETH_HLEN);
			skb_t->nh.iph->check = 0;
			skb_t->nh.iph->check = sip_chksum(skb_t->nh.raw, IPHDR_LEN);
			skb_h = skb_c = skb_t;
		}
		else if (i == frag_num - 1)
		{
			skb_t = skb_alloc(mtu);
			skb_t->pyh.raw = skb_put(skb_t, ETH_HLEN);
			skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);
			memcpy(skb_t->head, skb->head, ETH_HLEN + IPHDR_LEN);
			memcpy(skb_t->head + ETH_HLEN + IPHDR_LEN, skb->tail, skb->end - skb->tail);
			skb_t->nh.iph->frag_off = htons(i * (mtu - ETH_HLEN - IPHDR_LEN) + IPHDR_LEN);
			skb_t->nh.iph->tot_len = htons(skb->end - skb->tail + IPHDR_LEN);
			skb_t->nh.iph->check = 0;
			skb_t->nh.iph->check = sip_chksum(skb_t->nh.raw, IPHDR_LEN);
			skb_c->next = skb_t;
		}
		else
		{
			skb_t = skb_alloc(mtu);
			skb_t->pyh.raw = skb_put(skb_t, ETH_HLEN);
			skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);
			memcpy(skb_t->head, skb->head, ETH_HLEN + IPHDR_LEN);
			memcpy(skb_t->head + ETH_HLEN + IPHDR_LEN, skb->tail, mtu - ETH_HLEN - IPHDR_LEN);
			skb_put(skb_t, mtu - ETH_HLEN - IPHDR_LEN);
			skb_t->nh.iph->frag_off = htons((i * (mtu - ETH_HLEN - IPHDR_LEN) + IPHDR_LEN) | 0x2000);
			skb_t->nh.iph->tot_len = htons(mtu - ETH_HLEN);
			skb_t->nh.iph->check = 0;
			skb_t->nh.iph->check = sip_chksum(skb_t->nh.raw, IPHDR_LEN);
			skb_c->next = skb_t;
			skb_c = skb_t;
		}
		skb_t->ip_summed = 1;
	}
	skb_free(skb);
	return skb_h;
}
