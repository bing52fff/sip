#include "socket.h"
#include "eth.h"
#include "ip.h"
#include "udp.h"

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

int sip_socket(int domain, int type, int protocol)
{
	struct sock *sock;
	int i = 0;
	if (domain != AF_INET || protocol != 0)
		return -1;
	switch (type)
	{
	case SOCK_DGRAM:
		sock = (struct sock*) sock_new(SOCK_DGRAM);
		break;
	case SOCK_STREAM:
		break;
	default:
		break;
	}
	if (!sock)
		return -1;
	i = alloc_socket(sock);
	if (i == -1)
	{
		sock_delete(sock);
		return -1;
	}
	sock->socket = i;
	return i;
}
int sip_close(int s)
{
	struct sip_socket *socket;
	socket = get_socket(s);
	if (!socket)
		return -1;
	sock_delete(socket->sock);
	if (socket->lastdata)
		skb_free(socket->lastdata);
	socket->lastdata = NULL;
	socket->sock = NULL;
	return 0;
}
int sip_bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	struct sip_socket *socket;
	struct in_addr local_addr;
	__u16 port_local;
	int err;
	socket = get_socket(sockfd);
	if (!socket)
		return -1;
	local_addr.s_addr = ((struct sockaddr_in*)my_addr)->sin_addr.s_addr;
	port_local = ((struct sockaddr_in*) my_addr)->sin_port;
	err = sip_sockbind(socket->sock, &local_addr, ntohs(port_local));
	if (err)
		return -1;
	return 0;
}
int sip_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	struct sip_socket *socket;
	int err;
	socket = get_socket(sockfd);
	if (!socket)
		return -1;
	struct in_addr remote_addr;
	__u16 remote_port;
	remote_addr.s_addr = ((struct sockaddr_in*)serv_addr)->sin_addr.s_addr;
	remote_port = ((struct sockaddr_in*)serv_addr)->sin_port;
	err = sip_sockconnect(socket->sock, &remote_addr, ntohs(remote_port));
	return 0;
}
ssize_t sip_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	struct sip_socket *socket;
	struct sk_buff *skb;
	struct sockaddr_in *f = (struct sockaddr_in*) from;
	int len_copy = 0;
	socket = get_socket(s);
	if (!socket)
		return -1;
	if (!socket->lastdata)
	{
		socket->lastdata = (struct sk_buff*) sip_sockrecv(socket->sock);
		socket->lastoffset = 0;
	}
	skb = socket->lastdata;
	*fromlen = sizeof(struct sockaddr_in);
	f->sin_family = AF_INET;
	f->sin_addr.s_addr = skb->nh.iph->saddr;
	f->sin_port = skb->th.udph->source;
	len_copy = skb->len - socket->lastoffset;
	if (len > len_copy)
	{
		memcpy(buf, skb->data + socket->lastoffset, len_copy);
		skb_free(skb);
		socket->lastdata = NULL;
		socket->lastoffset = 0;
	}
	else
	{
		len_copy = len;
		memcpy(buf, skb + socket->lastoffset, len_copy);
		socket->lastoffset += len_copy;
	}
	return len_copy;
}
ssize_t sip_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	struct sip_socket *socket;
	struct in_addr remote_addr;
	struct sockaddr_in *to_in = (struct sockaddr_in*) to;
	int l_head = sizeof(struct sip_ethhdr) + sizeof(struct sip_iphdr) + sizeof(struct sip_udphdr);
	int size = l_head + len;
	struct sk_buff *skb = skb_alloc(size);
	char *data = skb_put(skb, l_head);
	memcpy(data, buf, len);
	socket = get_socket(s);
	if (!socket)
		return -1;
	sip_socksendto(socket->sock, skb, &remote_addr, to_in->sin_port);
	return len;
}
