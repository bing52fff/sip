#include "udp.h"

int udp_input(struct sk_buff *skb, struct net_device *dev);
int udp_output(struct sk_buff *skb, struct net_device *dev, struct udp_pcb *pcb, struct in_addr *src, struct in_addr *dest);
struct udp_new();
void udp_remove(struct udp_pcb *pcb);
int udp_bind(struct udp_pcb *pcb, struct in_addr *ipaddr, __u16 port);
int udp_sendto(struct net_device *dev, struct udp_pcb *pcb, struct sk_buff *skb, struct in_addr *dst_ip, __u16 dst_port);
__u16 udp_chksum(struct sk_buff *skb, struct in_adddr *src, struct in_addr *dest, __u8 proto, __u16 proto_len);
