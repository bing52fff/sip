#ifndef __SOCKET_H
#define __SOCKET_H

struct sock
{
	int type;
	int state;
	union
	{
		struct ip_pcb *ip;
		struct tcp_pcb *tcp;
		struct udp_pcb *udp;
	} pcb;
	int err;
	struct sk_buff *skb_recv;
	sem_t sem_recv;
	int socket;
	int recv_timeout;
	__u16 recv_avail;
};

struct sip_socket
{
	struct sock *sock;
	struct sk_buff *lastdata;
	__u16 lastoffset;
	int err;
};

int sip_sockbind(struct sock *sock, struct in_addr *addr, __u16 port);
struct sk_buff* sip_sockrecv(struct sock *sock);

int sip_socket(int domain, int type, int protocol);
int sip_close(int s);
int sip_bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen);
int sip_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
ssize_t sip_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t sip_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

#endif	//socket.h
