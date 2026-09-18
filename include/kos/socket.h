#ifndef KOS_SOCKET_H
#define KOS_SOCKET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/object.h>
#include <kos/spinlock.h>
#include <kos/wait.h>
#include <kos/net.h>

/* Address Families */
#define AF_UNSPEC     0
#define AF_UNIX       1
#define AF_LOCAL      AF_UNIX
#define AF_INET       2
#define AF_INET6      10

/* Socket Types */
#define SOCK_STREAM   1
#define SOCK_DGRAM    2
#define SOCK_RAW      3
#define SOCK_NONBLOCK 0x0800
#define SOCK_CLOEXEC  0x80000

/* Protocols */
#define IPPROTO_IP    0
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17
#define IPPROTO_RAW   255

/* Shutdown Flags */
#define SHUT_RD       0
#define SHUT_WR       1
#define SHUT_RDWR     2

/* Message Flags */
#define MSG_DONTWAIT  0x40
#define MSG_PEEK      0x02

/* Poll Events */
#define POLLIN        0x0001
#define POLLPRI       0x0002
#define POLLOUT       0x0004
#define POLLERR       0x0008
#define POLLHUP       0x0010
#define POLLNVAL      0x0020
#define POLLRDNORM    0x0040
#define POLLRDBAND    0x0080
#define POLLWRNORM    0x0100

/* Socket Options Levels & Names */
#define SOL_SOCKET    1
#define SO_DEBUG      1
#define SO_REUSEADDR  2
#define SO_TYPE       3
#define SO_ERROR      4
#define SO_DONTROUTE  5
#define SO_BROADCAST  6
#define SO_SNDBUF     7
#define SO_RCVBUF     8
#define SO_KEEPALIVE  9
#define SO_OOBINLINE  10
#define SO_RCVTIMEO   20
#define SO_SNDTIMEO   21

/* Standard POSIX Error Numbers */
#ifndef EAGAIN
#define EAGAIN        11
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK   EAGAIN
#endif
#ifndef EBADF
#define EBADF         9
#endif
#ifndef EIO
#define EIO           5
#endif
#ifndef ENOMEM
#define ENOMEM        12
#endif
#ifndef EMFILE
#define EMFILE        24
#endif
#ifndef EPIPE
#define EPIPE         32
#endif
#ifndef EINVAL
#define EINVAL        22
#endif
#ifndef ENOTSOCK
#define ENOTSOCK      88
#endif
#ifndef EDESTADDRREQ
#define EDESTADDRREQ  89
#endif
#ifndef EMSGSIZE
#define EMSGSIZE      90
#endif
#ifndef EPROTOTYPE
#define EPROTOTYPE    91
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT   92
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 93
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP    95
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT  97
#endif
#ifndef EADDRINUSE
#define EADDRINUSE    98
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 99
#endif
#ifndef ENETDOWN
#define ENETDOWN      100
#endif
#ifndef ENETUNREACH
#define ENETUNREACH   101
#endif
#ifndef ECONNRESET
#define ECONNRESET    104
#endif
#ifndef ENOBUFS
#define ENOBUFS       105
#endif
#ifndef EISCONN
#define EISCONN       106
#endif
#ifndef ENOTCONN
#define ENOTCONN      107
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT     110
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED  111
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH  113
#endif
#ifndef EALREADY
#define EALREADY      114
#endif
#ifndef EINPROGRESS
#define EINPROGRESS   115
#endif

static inline uint16_t htons(uint16_t val) {
    return (uint16_t)((val << 8) | (val >> 8));
}
static inline uint16_t ntohs(uint16_t val) {
    return htons(val);
}
static inline uint32_t htonl(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val >> 8) & 0xff00) | ((val << 8) & 0xff0000) | ((val << 24) & 0xff000000);
}
static inline uint32_t ntohl(uint32_t val) {
    return htonl(val);
}

/* POSIX Network Structures */
typedef uint16_t sa_family_t;
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;

struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

/* Socket State */
enum socket_state {
    SS_UNCONNECTED = 1,
    SS_CONNECTING,
    SS_CONNECTED,
    SS_DISCONNECTING,
    SS_LISTENING,
    SS_CLOSED,
};

#define KOS_MAX_SOCKETS 32

/* Core Socket Structure */
struct socket {
    struct kos_object_header header;
    uint32_t id;
    int domain;
    int type;
    int protocol;
    enum socket_state state;
    uint32_t flags;

    kos_spinlock_t lock;
    struct wait_queue wait_queue;

    struct net_ipv4_endpoint local_endpoint;
    struct net_ipv4_endpoint remote_endpoint;

    uint32_t rcvtimeo_ms;
    uint32_t sndtimeo_ms;
    int last_error;
    bool reuse_addr;
    bool broadcast;
    bool nonblocking;

    /* Transport reference */
    int transport_handle;

    bool in_use;
};

/* Socket Subsystem APIs */
void socket_subsystem_init(void);
int kos_socket(int domain, int type, int protocol, struct socket **out_sock);
int kos_bind(struct socket *sock, const struct sockaddr *addr, uint32_t addrlen);
int kos_listen(struct socket *sock, int backlog);
int kos_accept(struct socket *sock, struct sockaddr *addr, uint32_t *addrlen, struct socket **out_client);
int kos_connect(struct socket *sock, const struct sockaddr *addr, uint32_t addrlen);
int kos_send(struct socket *sock, const void *buf, size_t len, int flags);
int kos_recv(struct socket *sock, void *buf, size_t len, int flags);
int kos_sendto(struct socket *sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, uint32_t addrlen);
int kos_recvfrom(struct socket *sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, uint32_t *addrlen);
int kos_shutdown(struct socket *sock, int how);
int kos_close(struct socket *sock);
int kos_getsockopt(struct socket *sock, int level, int optname, void *optval, uint32_t *optlen);
int kos_setsockopt(struct socket *sock, int level, int optname, const void *optval, uint32_t optlen);
int kos_poll(struct socket *sock, uint32_t events, uint32_t *revents);

void socket_ref(struct socket *sock);
void socket_unref(struct socket *sock);

bool socket_self_test(void);

#endif /* KOS_SOCKET_H */
