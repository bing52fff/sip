#include "net_device.h"
#include "ip.h"
#include "arp.h"

__u8 input(struct sk_buff *pskb, struct net_device *dev)
{
	char ef[ETH_FRAME_LEN];
	int n, i;
	int retval = 0;
	n = read(dev->s, ef, ETH_FRAME_LEN, 0);
	if (n <= 0)
	{
		debug_print("read error\n");
		retval = -1;
		goto out;
	}
	
	struct sk_buff *skb = skb_alloc(n);
	memcpy(skb->head, ef, n);
	skb->tot_len = n;
	skb->pyh.ethh = (struct sip_ethhdr*) skb_put(skb, sizeof(struct sip_ethhdr));
	if (samemac(skb->pyh.ethh->h_dest, dev->hwaddr) || samemac(skb->pyh.ethh->h_dest, dev->hwbroadcast))
	{
		switch (ntohs(skb->pyh.ethh->h_proto))
		{
		case ETH_P_IP:
			skb->nh.iph = (struct sip_iphdr*) skb_put(skb, sizeof(struct sip_iphdr));
			arp_add_entry(skb->nh.iph->saddr, skb->pyh.ethh->h_source, ARP_ESTABLISHED);
			ip_input(skb, dev);
			break;
		case ETH_P_ARP:
			skb->nh.arph = (struct sip_arphdr*) skb_put(skb, sizeof(struct sip_arphdr));
			if (*(__u32*)skb->nh.arph->ar_tip == dev->ip_host.s_addr)
				arp_input(&skb, dev);
			skb_free(skb);
			break;
		default:
			debug_print("unknown protocol\n");
			skb_free(skb);
			retval = -1;
			break;
		}
	}
	else
	{
		skb_free(skb);
	}
out:
	return retval;
}
__u8 lowoutput(struct sk_buff *skb, struct net_device *dev)
{
	int n = 0;
	int len = sizeof(struct sockaddr);
	struct sk_buff *p = NULL;
	for (p = skb; p != NULL; skb = p, p = p->next, skb_free(skb), skb = NULL)
	{
		n = sendto(dev->s, skb->head, skb->len, 0, &dev->to, len);
	}
	return 0;
}
__u8 output(struct sk_buff *skb, struct net_device *dev)
{
	int retval = 0;
	struct arpt_arp *arp = NULL;
	int times = 0, found = 0;
	__be32 destip = skb->nh.iph->daddr;
	if ((skb->nh.iph->daddr & dev->ip_netmask.s_addr) != (dev->ip_host.s_addr & dev->ip_netmask.s_addr))
		destip = dev->ip_gw.s_addr;
	while (((arp = arp_find_entry(destip)) == NULL) && times < 5)
	{
		arp_request(dev, destip);
		sleep(1);
		times ++;
	}
	if (!arp)
	{
		retval = -1;
		goto out;
	}
	else
	{
		struct sip_ethhdr *eh = skb->pyh.ethh;
		memcpy(eh->h_dest, arp->ethaddr, ETH_ALEN);
		memcpy(eh->h_source, dev->hwaddr, ETH_ALEN);
		dev->linkoutput(skb, dev);
	}
out:
	return retval;
}

void sip_init_ethnet(struct net_device *dev)
{
	debug_print("init net_device...\n");
	memset(dev, 0, sizeof(struct net_device));
	dev->s = socket(AF_INET, SOCK_PACKET, ETH_P_ALL);
	if (dev->s < 0)
	{
		debug_print("create sock_packet error\n");
		return ;
	}
	strcpy(dev->name, INTER_NAME);
	memset(&dev->to, 0, sizeof(struct sockaddr));
	dev->to.sa_family = AF_INET;
	strcpy(dev->to.sa_data, dev->name);
	int r = bind(dev->s, &dev->to, sizeof(struct sockaddr));
	strncpy(dev->hwaddr, MAC_ADDR, ETH_ALEN);
	dev->hwaddr_len = ETH_ALEN;
	dev->ip_host.s_addr = inet_addr(LOCAL_IP);
	dev->ip_netmask.s_addr = inet_addr(NETMASK);
	dev->ip_broadcast.s_addr = inet_addr(BROADCAST_IP);
	dev->ip_gw.s_addr = inet_addr(DEF_GW);
	dev->type = ETH_P_802_3;
	dev->input = input;
	dev->output = output;
	dev->linkoutput = lowoutput;
}
