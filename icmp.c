#include "icmp.h"

void icmp_discard(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp descard\n");
}
void icmp_unreach(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp unreach\n");
}
void icmp_redirect(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp redirect\n");
}
void icmp_timestamp(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp timestamp\n");
}
void icmp_address(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp address\n");
}
void icmp_address_reply(struct sk_buff *skb, struct net_device *dev)
{
	debug_print("icmp address reply");
}
static const struct icmp_control icmp_pointers[NR_ICMP_TYPES + 1] = {
	[ICMP_ECHOREPLY] = {.handler = icmp_discard, },
	[1] = {.handler = icmp_discard, .error = 1},
	[2] = {.handler = icmp_discard, .error = 1},
	[ICMP_DEST_UNREACH] = {.handler = icmp_unreach, .error = 1},
	[ICMP_SOURCE_QUENCH] = {.handler = icmp_discard, .error = 1},
	[ICMP_REDIRECT] = {.handler = icmp_redirect, .error = 1},
	[6] = {.handler = icmp_discard, .error = 1},
	[7] = {.handler = icmp_discard, .error = 1},
	[ICMP_ECHO] = {.handler = icmp_echo, .error = 1},
	[9] = {.handler = icmp_discard, .error = 1},
	[10] = {.handler = icmp_discard, .error = 1},
	[ICMP_TIME_EXCEEDED] = {.handler = icmp_unreach, .error = 1},
	[ICMP_PARAMETERPROB] = {.handler = icmp_unreach, .error = 1},
	[ICMP_TIMESTAMP] = {.handler = icmp_timestamp,},
	[ICMP_TIMESTAMPREPLY] = {.handler = icmp_unreach,},
	[ICMP_INFO_REQUEST] = {.handler = icmp_unreach,},
	[ICMP_INFO_REPLY] = {.handler = icmp_unreach,},
	[ICMP_ADDRESS] = {.handler = icmp_unreach,},
	[ICMP_ADDRESSREPLY] = {.handler = icmp_address_reply,},
};

int icmp_input(struct sk_buff *skb, struct net_device *dev)
{
	struct sip_icmphdr *icmph;
	switch (skb->ip_summed)
	{
	case CHECKSUM_NONE:
		skb->csum = 0;
		if (sip_chksum(skb->pyh.raw, 0))
		{
			debug_print("level error\n");
			goto drop;
		}
		break;
	default:
		break;
	}
	icmph = skb->th.icmph;
	if (icmph->type > NR_ICMP_TYPES)
		goto drop;
	icmp_pointers[icmph->type].handler(skb, dev);
out:
	return 0;
drop:
	skb_free(skb);
	goto out;
}

void icmp_echo(struct sk_buff *skb, struct net_device *dev)
{
	struct sip_icmphdr *icmph = skb->th.icmph;
	struct sip_iphdr *iph = skb->nh.iph;
	if (IP_IS_BROADCAST(dev, skb->nh.iph->daddr) || IP_IS_BROADCAST(dev, skb->nh.iph->daddr))
		goto out;
	icmph->type = ICMP_ECHOREPLY;
	if (icmph->checksum >= htons(0xffff - (ICMP_ECHO << 8)))
		icmph->checksum += (htons(ICMP_ECHO << 8) + 1);
	else
		icmph->checksum += htons(ICMP_ECHO << 8);
	struct in_addr dest;
	dest.s_addr = skb->nh.iph->saddr;
	ip_output(skb, dev, &dev->ip_host, &dest, 255, 0, IPPROTO_ICMP);
out:
	return ;
}
