#ifndef	__ICMP_H
#define __ICMP_H

#include "ip.h"
#include "net_device.h"
#include "sk_buff.h"
#include "util.h"

#define	NR_ICMP_TYPES	128
#define	ICMP_ECHOREPLY	0
#define	ICMP_DEST_UNREACH	3
#define	ICMP_SOURCE_QUENCH	4
#define	ICMP_REDIRECT	5
#define	ICMP_ECHO	8
#define	ICMP_TIME_EXCEEDED	11
#define	ICMP_PARAMETERPROB	12
#define	ICMP_TIMESTAMP	13
#define	ICMP_TIMESTAMPREPLY	14
#define	ICMP_INFO_REQUEST	15
#define	ICMP_INFO_REPLY	16
#define	ICMP_ADDRESS	17
#define	ICMP_ADDRESSREPLY	18

struct sip_icmphdr
{
	__u8	type;
	__u8	code;
	__u16	checksum;
	union
	{
		struct 
		{
			__u16	id;
			__u16	sequence;
		} echo;
		__u32	gateway;
		struct 
		{
			__u16	__unused;
			__u16	mtu;
		} frag;
	}un;
};

struct icmp_control
{
	void (*handler)(struct sk_buff* skb, struct net_device* dev);
	short error;
};

int icmp_input(struct sk_buff *skb, struct net_device *dev);
void icmp_echo(struct sk_buff *skb, struct net_device *dev);
void icmp_discard(struct sk_buff *skb, struct net_device *dev);
void icmp_unreach(struct sk_buff *skb, struct net_device *dev);
void icmp_redirect(struct sk_buff *skb, struct net_device *dev);
void icmp_timestamp(struct sk_buff *skb, struct net_device *dev);
void icmp_address(struct sk_buff *skb, struct net_device *dev);
void icmp_address_reply(struct sk_buff *skb, struct net_device *dev);

#endif	//icmp.h
