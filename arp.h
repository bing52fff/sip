#ifndef __ARP_H
#define __ARP_H

#include "util.h"
#include "sk_buff.h"
#include "net_device.h"
#include "eth.h"

#define	ARP_LIVE_TIME	30
#define	ARP_TABLE_SIZE	10
#define	ARPOP_REQUEST	1
#define	ARPOP_REPLY		2

enum arp_status
{
	ARP_EMPTY,
	ARP_ESTABLISHED
};

struct sip_arphdr
{
	__be16		ar_hrd;
	__be16		ar_pro;
	__u8		ar_hln;
	__u8		ar_pln;
	__be16		ar_op;

	__u8		ar_sha[ETH_ALEN];
	__u32		ar_sip[4];
	__u8		ar_tha[ETH_ALEN];
	__u32		ar_tip[4];
};

struct arpt_arp
{
	__u32		ipaddr;
	__u8		ethaddr[ETH_ALEN];
	time_t		ctime;
	enum arp_status	status;
};

void init_arp_entry();
struct arpt_arp* arp_find_entry(__u32 ip);
struct arpt_arp* update_arp_entry(__u32 ip, __u8 *ethaddr);
void arp_add_entry(__u32 ip, __u8 *ethaddr, int status);
struct sk_buff* arp_create(struct net_device *dev,
		int type,
		__u32 src_ip,
		__u32 dest_ip,
		__u8 *src_hw,
		__u8 *dest_hw,
		__u8 *target_hw);
int arp_input(struct sk_buff **pskb, struct net_device *dev);
void arp_send(struct net_device *dev,
		int type,
		__u32 src_ip,
		__u32 dest_ip,
		__u8 *src_hw,
		__u8 *dest_hw,
		__u8 *target_hw);
int arp_request(struct net_device *dev, __u32 ip);

#endif	//arp.h
