#include "socket.h"

int sip_sockbind(struct sock *sock, struct in_addr *addr, __u16 port)
{
	if (sock->pcb.tcp != NULL)
	{
		switch (sock->type)
		{
		case SOCK_RAW:
			break;
		case SOCK_DGRAM:
			sock->err = udp_bind(sock->pcb.udp, addr, port);
			break;
		case SOCK_STREAM:
			break;
		default:
			break;
		}
	}
}
struct sk_buff* sip_sockrecv(struct sock *sock)
{
	struct sk_buff *skb_recv = NULL;
	int num = 0;
	if (sem_getvalue(&sock->sem_recv, &num))
	{
		struct timespec timeout;
		timeout.tv_sec = sock->recv_timeout;
		timeout.tv_nsec = 0;
		sem_timedwait(&sock->sem_recv, &timeout);
	}
	else
		sem_wait(&sock->sem_recv);
	skb_recv = sock->skb_recv;
	if (skb_recv == NULL)
		return NULL;
	sock->skb_recv = skb_recv->next;
	skb_recv->next = NULL;
	return skb_recv;
}

int sip_socket(int domain, int type, int protocol);
int sip_close(int s);
int sip_bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen);
int sip_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
ssize_t sip_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t sip_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

