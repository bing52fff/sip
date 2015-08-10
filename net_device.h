#ifndef __NET_DEVICE_H
#define __NET_DEVICE_H

#include "util.h"
#include "sk_buff.h"
#include "eth.h"

#define	IFNAMESIZ	16
#define	INTER_NAME	"wlan0"
#define	MAC_ADDR	"112233445566"
#define	LOCAL_IP	"192.168.1.111"
#define	NETMASK		"255.255.255.0"
#define	BROADCAST_IP	"192.168.1.255"
#define	DEF_GW		"192.168.1.1"

struct net_device
{
	char	name[IFNAMESIZ];
	struct in_addr	ip_host;
	struct in_addr	ip_netmask;
	struct in_addr	ip_broadcast;
	struct in_addr	ip_gw;
	struct in_addr	ip_dest;
	
	__u16	type;
	__u8 (*input)(struct sk_buff *skb, struct net_device *dev);	
	__u8 (*output)(struct sk_buff *skb, struct net_device *dev);
	__u8 (*linkoutput)(struct sk_buff *skb, struct net_device *dev);

	__u8	hwaddr_len;
	__u8	hwaddr[ETH_ALEN];
	__u8	hwbroadcast[ETH_ALEN];
	__u8	mtu;
	int		s;
	struct sockaddr	to;
};

void sip_init_ethnet(struct net_device *dev);
__u8 input(struct sk_buff *pskb, struct net_device *dev);
__u8 lowoutput(struct sk_buff *skb, struct net_device *dev);
__u8 output(struct sk_buff *skb, struct net_device *dev);

#endif	//net_device.h
