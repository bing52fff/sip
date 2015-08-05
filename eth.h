#ifndef __ETH_H
#define __ETH_H

#include "util.h"

#define	ETH_ALEN	6
#define	ETH_P_802_3	0x0001
#define	ETH_P_ALL	0x0003
#define	ETH_P_IP	0x0800
#define	ETH_P_ARP	0x0806
#define	ETH_ZLEN	60
#define	ETH_FRAME_LEN	1518
#define	ETH_HLEN	14
#define	ETH_DATA_LEN	1500

struct sip_ethhdr
{
	__u8	h_dest[ETH_ALEN];
	__u8	h_source[ETH_ALEN];
	__u16	h_proto;
};

int samemac(const __u8 *a, const __u8 *b);

#endif	//eth.h
