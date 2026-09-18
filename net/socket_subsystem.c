#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/socket.h>
#include <kos/object.h>
#include <kos/sync.h>
#include <kos/wait.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/memory.h>
#include <kos/net.h>

static struct socket socket_pool[KOS_MAX_SOCKETS];
static struct kos_spinlock pool_lock = KOS_SPINLOCK_INITIALIZER;
static bool subsystem_initialized = false;

static void socket_destroy(void *obj) {
    struct socket *sock = (struct socket *)obj;
    if (sock == 0) {
        return;
    }

    if (sock->type == SOCK_STREAM && sock->transport_handle >= 0) {
        tcp_close(sock->transport_handle);
        sock->transport_handle = -1;
    }
    else if (sock->type == SOCK_DGRAM && sock->transport_handle >= 0) {
        net_udp_close((uint16_t)sock->transport_handle);
        sock->transport_handle = -1;
    }

    uint64_t flags = spinlock_lock_irqsave(&pool_lock);
    sock->in_use = false;
    sock->state = SS_CLOSED;
    spinlock_unlock_irqrestore(&pool_lock, flags);
}

void socket_subsystem_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&pool_lock);
    if (subsystem_initialized) {
        spinlock_unlock_irqrestore(&pool_lock, flags);
        return;
    }

    for (uint32_t i = 0; i < KOS_MAX_SOCKETS; ++i) {
        socket_pool[i].in_use = false;
        socket_pool[i].id = i;
        socket_pool[i].state = SS_CLOSED;
        socket_pool[i].transport_handle = -1;
    }

    subsystem_initialized = true;
    spinlock_unlock_irqrestore(&pool_lock, flags);
}

void socket_ref(struct socket *sock) {
    if (sock != 0) {
        kos_object_ref(&sock->header);
    }
}

void socket_unref(struct socket *sock) {
    if (sock != 0) {
        kos_object_unref(&sock->header);
    }
}

static struct socket *allocate_socket_locked(void) {
    for (uint32_t i = 0; i < KOS_MAX_SOCKETS; ++i) {
        if (!socket_pool[i].in_use) {
            struct socket *sock = &socket_pool[i];
            sock->in_use = true;
            sock->id = i;
            sock->state = SS_UNCONNECTED;
            sock->flags = 0;
            sock->lock = (kos_spinlock_t)KOS_SPINLOCK_INITIALIZER;
            wait_queue_init(&sock->wait_queue);
            sock->local_endpoint = (struct net_ipv4_endpoint){ 0, 0 };
            sock->remote_endpoint = (struct net_ipv4_endpoint){ 0, 0 };
            sock->rcvtimeo_ms = 0;
            sock->sndtimeo_ms = 0;
            sock->last_error = 0;
            sock->reuse_addr = false;
            sock->broadcast = false;
            sock->nonblocking = false;
            sock->transport_handle = -1;

            kos_object_init(&sock->header, KOS_OBJ_SOCKET, socket_destroy);
            return sock;
        }
    }
    return 0;
}

int kos_socket(int domain, int type, int protocol, struct socket **out_sock) {
    if (out_sock == 0) {
        return -EINVAL;
    }
    if (domain != AF_INET && domain != AF_UNSPEC) {
        return -EAFNOSUPPORT;
    }

    bool nonblocking = (type & SOCK_NONBLOCK) != 0;
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM && base_type != SOCK_RAW) {
        return -EINVAL;
    }

    if (protocol == 0) {
        if (base_type == SOCK_STREAM) {
            protocol = IPPROTO_TCP;
        } else if (base_type == SOCK_DGRAM) {
            protocol = IPPROTO_UDP;
        }
    }

    uint64_t flags = spinlock_lock_irqsave(&pool_lock);
    struct socket *sock = allocate_socket_locked();
    if (sock == 0) {
        spinlock_unlock_irqrestore(&pool_lock, flags);
        return -ENOMEM;
    }

    sock->domain = domain;
    sock->type = base_type;
    sock->protocol = protocol;
    sock->nonblocking = nonblocking;

    if (base_type == SOCK_DGRAM) {
        uint16_t udp_id = 0;
        if (!net_udp_open(&udp_id)) {
            sock->in_use = false;
            spinlock_unlock_irqrestore(&pool_lock, flags);
            return -ENOMEM;
        }
        sock->transport_handle = (int)udp_id;
    }

    spinlock_unlock_irqrestore(&pool_lock, flags);
    *out_sock = sock;
    return 0;
}

int kos_bind(struct socket *sock, const struct sockaddr *addr, uint32_t addrlen) {
    if (sock == 0 || addr == 0 || addrlen < sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    if (sin->sin_family != AF_INET && sin->sin_family != AF_UNSPEC) {
        return -EAFNOSUPPORT;
    }

    uint32_t ip = ntohl(sin->sin_addr.s_addr);
    uint16_t port = ntohs(sin->sin_port);

    uint64_t flags = spinlock_lock_irqsave(&sock->lock);
    sock->local_endpoint.address = ip;
    sock->local_endpoint.port = port;

    if (sock->type == SOCK_DGRAM) {
        struct net_ipv4_endpoint ep = { .address = ip, .port = port };
        if (!net_udp_bind((uint16_t)sock->transport_handle, ep)) {
            spinlock_unlock_irqrestore(&sock->lock, flags);
            return -EADDRINUSE;
        }
    }

    spinlock_unlock_irqrestore(&sock->lock, flags);
    return 0;
}

int kos_listen(struct socket *sock, int backlog) {
    if (sock == 0 || sock->type != SOCK_STREAM) {
        return -EOPNOTSUPP;
    }

    uint64_t flags = spinlock_lock_irqsave(&sock->lock);
    if (sock->local_endpoint.port == 0) {
        spinlock_unlock_irqrestore(&sock->lock, flags);
        return -EINVAL;
    }

    int listen_sock = tcp_listen(sock->local_endpoint.port, backlog > 0 ? (uint16_t)backlog : 4);
    if (listen_sock < 0) {
        spinlock_unlock_irqrestore(&sock->lock, flags);
        return -EADDRINUSE;
    }

    sock->transport_handle = listen_sock;
    sock->state = SS_LISTENING;
    spinlock_unlock_irqrestore(&sock->lock, flags);
    return 0;
}

int kos_accept(struct socket *sock, struct sockaddr *addr, uint32_t *addrlen, struct socket **out_client) {
    if (sock == 0 || out_client == 0 || sock->type != SOCK_STREAM) {
        return -EINVAL;
    }
    if (sock->state != SS_LISTENING) {
        return -EINVAL;
    }

    struct net_ipv4_endpoint remote_ep = { 0, 0 };
    int child_tcp = -1;

    while (true) {
        child_tcp = tcp_accept(sock->transport_handle, &remote_ep);
        if (child_tcp >= 0) {
            break;
        }
        if (sock->nonblocking) {
            return -EAGAIN;
        }
        net_poll();
        if (task_is_multitasking_active()) {
            task_sleep(1);
        } else {
            cpu_wait_for_interrupt();
        }
    }

    uint64_t flags = spinlock_lock_irqsave(&pool_lock);
    struct socket *client = allocate_socket_locked();
    if (client == 0) {
        spinlock_unlock_irqrestore(&pool_lock, flags);
        tcp_close(child_tcp);
        return -ENOMEM;
    }

    client->domain = sock->domain;
    client->type = sock->type;
    client->protocol = sock->protocol;
    client->state = SS_CONNECTED;
    client->transport_handle = child_tcp;
    client->remote_endpoint = remote_ep;
    client->local_endpoint = sock->local_endpoint;
    spinlock_unlock_irqrestore(&pool_lock, flags);

    if (addr != 0 && addrlen != 0 && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(remote_ep.port);
        sin->sin_addr.s_addr = htonl(remote_ep.address);
        *addrlen = sizeof(struct sockaddr_in);
    }

    *out_client = client;
    return 0;
}

int kos_connect(struct socket *sock, const struct sockaddr *addr, uint32_t addrlen) {
    if (sock == 0 || addr == 0 || addrlen < sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    if (sin->sin_family != AF_INET && sin->sin_family != AF_UNSPEC) {
        return -EAFNOSUPPORT;
    }

    uint32_t ip = ntohl(sin->sin_addr.s_addr);
    uint16_t port = ntohs(sin->sin_port);

    uint64_t flags = spinlock_lock_irqsave(&sock->lock);
    sock->remote_endpoint.address = ip;
    sock->remote_endpoint.port = port;

    if (sock->type == SOCK_STREAM) {
        sock->state = SS_CONNECTING;
        spinlock_unlock_irqrestore(&sock->lock, flags);

        int tcp_id = tcp_connect(ip, port);
        flags = spinlock_lock_irqsave(&sock->lock);
        if (tcp_id < 0) {
            sock->state = SS_UNCONNECTED;
            spinlock_unlock_irqrestore(&sock->lock, flags);
            return -ECONNREFUSED;
        }
        sock->transport_handle = tcp_id;
        sock->state = SS_CONNECTED;
        spinlock_unlock_irqrestore(&sock->lock, flags);
        return 0;
    }

    if (sock->type == SOCK_DGRAM) {
        sock->state = SS_CONNECTED;
        spinlock_unlock_irqrestore(&sock->lock, flags);
        return 0;
    }

    spinlock_unlock_irqrestore(&sock->lock, flags);
    return -EOPNOTSUPP;
}

int kos_send(struct socket *sock, const void *buf, size_t len, int flags) {
    (void)flags;
    if (sock == 0 || buf == 0) {
        return -EINVAL;
    }

    if (sock->type == SOCK_STREAM) {
        if (sock->state != SS_CONNECTED || sock->transport_handle < 0) {
            return -ENOTCONN;
        }
        int sent = tcp_send(sock->transport_handle, (const uint8_t *)buf, len);
        return sent >= 0 ? sent : -EPIPE;
    }

    if (sock->type == SOCK_DGRAM) {
        if (sock->remote_endpoint.port == 0) {
            return -EDESTADDRREQ;
        }
        bool ok = net_udp_sendto((uint16_t)sock->transport_handle, sock->remote_endpoint,
            (const uint8_t *)buf, len);
        return ok ? (int)len : -EIO;
    }

    return -EOPNOTSUPP;
}

int kos_recv(struct socket *sock, void *buf, size_t len, int flags) {
    if (sock == 0 || buf == 0) {
        return -EINVAL;
    }

    if (sock->type == SOCK_STREAM) {
        if (sock->state != SS_CONNECTED || sock->transport_handle < 0) {
            return -ENOTCONN;
        }
        int recvd = tcp_receive(sock->transport_handle, (uint8_t *)buf, len);
        if (recvd < 0) {
            return sock->nonblocking ? -EAGAIN : -EIO;
        }
        return recvd;
    }

    if (sock->type == SOCK_DGRAM) {
        struct net_ipv4_endpoint src = { 0, 0 };
        uint64_t actual = 0;
        bool ok;
        if (sock->nonblocking || (flags & MSG_DONTWAIT)) {
            ok = net_udp_recvfrom((uint16_t)sock->transport_handle, &src, (uint8_t *)buf, len, &actual);
            if (!ok) {
                return -EAGAIN;
            }
        } else {
            uint32_t timeout_ms = sock->rcvtimeo_ms > 0 ? sock->rcvtimeo_ms : 5000;
            ok = net_udp_recvfrom_timeout((uint16_t)sock->transport_handle, &src,
                (uint8_t *)buf, len, &actual, timeout_ms);
            if (!ok) {
                return -EAGAIN;
            }
        }
        return (int)actual;
    }

    return -EOPNOTSUPP;
}

int kos_sendto(struct socket *sock, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, uint32_t addrlen) {
    if (dest_addr == 0) {
        return kos_send(sock, buf, len, flags);
    }
    if (sock == 0 || buf == 0 || addrlen < sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)dest_addr;
    struct net_ipv4_endpoint ep = {
        .address = ntohl(sin->sin_addr.s_addr),
        .port = ntohs(sin->sin_port)
    };

    if (sock->type == SOCK_DGRAM) {
        bool ok = net_udp_sendto((uint16_t)sock->transport_handle, ep, (const uint8_t *)buf, len);
        return ok ? (int)len : -EIO;
    }

    return kos_send(sock, buf, len, flags);
}

int kos_recvfrom(struct socket *sock, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, uint32_t *addrlen) {
    if (sock == 0 || buf == 0) {
        return -EINVAL;
    }

    if (sock->type == SOCK_DGRAM) {
        struct net_ipv4_endpoint src = { 0, 0 };
        uint64_t actual = 0;
        bool ok;
        if (sock->nonblocking || (flags & MSG_DONTWAIT)) {
            ok = net_udp_recvfrom((uint16_t)sock->transport_handle, &src, (uint8_t *)buf, len, &actual);
            if (!ok) {
                return -EAGAIN;
            }
        } else {
            uint32_t timeout_ms = sock->rcvtimeo_ms > 0 ? sock->rcvtimeo_ms : 5000;
            ok = net_udp_recvfrom_timeout((uint16_t)sock->transport_handle, &src,
                (uint8_t *)buf, len, &actual, timeout_ms);
            if (!ok) {
                return -EAGAIN;
            }
        }

        if (src_addr != 0 && addrlen != 0 && *addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(src.port);
            sin->sin_addr.s_addr = htonl(src.address);
            *addrlen = sizeof(struct sockaddr_in);
        }
        return (int)actual;
    }

    return kos_recv(sock, buf, len, flags);
}

int kos_shutdown(struct socket *sock, int how) {
    (void)how;
    if (sock == 0) {
        return -EINVAL;
    }
    sock->state = SS_DISCONNECTING;
    return 0;
}

int kos_close(struct socket *sock) {
    if (sock == 0) {
        return -EINVAL;
    }
    socket_unref(sock);
    return 0;
}

int kos_getsockopt(struct socket *sock, int level, int optname, void *optval, uint32_t *optlen) {
    if (sock == 0 || optval == 0 || optlen == 0) {
        return -EINVAL;
    }

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_TYPE:
            if (*optlen < sizeof(int)) return -EINVAL;
            *(int *)optval = sock->type;
            *optlen = sizeof(int);
            return 0;
        case SO_REUSEADDR:
            if (*optlen < sizeof(int)) return -EINVAL;
            *(int *)optval = sock->reuse_addr ? 1 : 0;
            *optlen = sizeof(int);
            return 0;
        case SO_BROADCAST:
            if (*optlen < sizeof(int)) return -EINVAL;
            *(int *)optval = sock->broadcast ? 1 : 0;
            *optlen = sizeof(int);
            return 0;
        case SO_ERROR:
            if (*optlen < sizeof(int)) return -EINVAL;
            *(int *)optval = sock->last_error;
            sock->last_error = 0;
            *optlen = sizeof(int);
            return 0;
        default:
            return -ENOPROTOOPT;
        }
    }
    return -ENOPROTOOPT;
}

int kos_setsockopt(struct socket *sock, int level, int optname, const void *optval, uint32_t optlen) {
    if (sock == 0 || optval == 0) {
        return -EINVAL;
    }

    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR:
            if (optlen < sizeof(int)) return -EINVAL;
            sock->reuse_addr = (*(const int *)optval != 0);
            return 0;
        case SO_BROADCAST:
            if (optlen < sizeof(int)) return -EINVAL;
            sock->broadcast = (*(const int *)optval != 0);
            return 0;
        case SO_RCVTIMEO:
            if (optlen < sizeof(uint32_t)) return -EINVAL;
            sock->rcvtimeo_ms = *(const uint32_t *)optval;
            return 0;
        case SO_SNDTIMEO:
            if (optlen < sizeof(uint32_t)) return -EINVAL;
            sock->sndtimeo_ms = *(const uint32_t *)optval;
            return 0;
        default:
            return -ENOPROTOOPT;
        }
    }
    return -ENOPROTOOPT;
}

int kos_poll(struct socket *sock, uint32_t events, uint32_t *revents) {
    if (sock == 0 || revents == 0) {
        return -EINVAL;
    }

    uint32_t ready = 0;

    if (sock->type == SOCK_DGRAM) {
        if (events & POLLOUT) {
            ready |= POLLOUT;
        }
        if (events & POLLIN) {
            uint8_t peek_buf[1];
            struct net_ipv4_endpoint ep;
            uint64_t actual = 0;
            if (net_udp_recvfrom((uint16_t)sock->transport_handle, &ep, peek_buf, 0, &actual)) {
                ready |= POLLIN;
            }
        }
    }
    else if (sock->type == SOCK_STREAM) {
        if (sock->state == SS_CONNECTED) {
            if (events & POLLOUT) {
                ready |= POLLOUT;
            }
            if (events & POLLIN) {
                struct net_tcp_socket_info info[1];
                if (net_tcp_get_sockets(info, 1) > 0 && info[0].rx_buffered_bytes > 0) {
                    ready |= POLLIN;
                }
            }
        }
        else if (sock->state == SS_LISTENING) {
            if (events & POLLIN) {
                ready |= POLLIN;
            }
        }
    }

    *revents = ready & events;
    return 0;
}

bool socket_self_test(void) {
    socket_subsystem_init();

    /* Test 1: UDP loopback through kos_socket APIs */
    struct socket *sender = 0;
    struct socket *receiver = 0;

    if (kos_socket(AF_INET, SOCK_DGRAM, 0, &sender) != 0 || sender == 0) {
        return false;
    }
    if (kos_socket(AF_INET, SOCK_DGRAM, 0, &receiver) != 0 || receiver == 0) {
        kos_close(sender);
        return false;
    }

    struct sockaddr_in r_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(42001),
        .sin_addr.s_addr = htonl(NET_IPV4_LOOPBACK),
    };
    struct sockaddr_in s_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(42000),
        .sin_addr.s_addr = htonl(NET_IPV4_LOOPBACK),
    };

    if (kos_bind(sender, (struct sockaddr *)&s_addr, sizeof(s_addr)) != 0) {
        kos_close(sender);
        kos_close(receiver);
        return false;
    }
    if (kos_bind(receiver, (struct sockaddr *)&r_addr, sizeof(r_addr)) != 0) {
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    const char msg[] = "KOS_SOCKET_SUBSYS_OK";
    int sent = kos_sendto(sender, msg, sizeof(msg), 0, (struct sockaddr *)&r_addr, sizeof(r_addr));
    if (sent != (int)sizeof(msg)) {
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    char recv_buf[64] = { 0 };
    struct sockaddr_in from_addr;
    uint32_t from_len = sizeof(from_addr);
    int recvd = kos_recvfrom(receiver, recv_buf, sizeof(recv_buf), 0,
        (struct sockaddr *)&from_addr, &from_len);
    if (recvd != (int)sizeof(msg)) {
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    for (size_t i = 0; i < sizeof(msg); ++i) {
        if (recv_buf[i] != msg[i]) {
            kos_close(sender);
            kos_close(receiver);
            return false;
        }
    }

    /* Test 2: Non-blocking EAGAIN */
    struct socket *nb_sock = 0;
    if (kos_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, &nb_sock) != 0) {
        kos_close(sender);
        kos_close(receiver);
        return false;
    }
    struct sockaddr_in nb_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(42002),
        .sin_addr.s_addr = htonl(NET_IPV4_LOOPBACK),
    };
    if (kos_bind(nb_sock, (struct sockaddr *)&nb_addr, sizeof(nb_addr)) != 0) {
        kos_close(nb_sock);
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    char dummy[16];
    int nb_res = kos_recv(nb_sock, dummy, sizeof(dummy), 0);
    if (nb_res != -EAGAIN) {
        kos_close(nb_sock);
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    /* Test 3: Refcounting */
    socket_ref(nb_sock);
    if (kos_object_get_refcount(&nb_sock->header) != 2) {
        socket_unref(nb_sock);
        kos_close(nb_sock);
        kos_close(sender);
        kos_close(receiver);
        return false;
    }
    socket_unref(nb_sock);

    /* Test 4: Poll readiness */
    uint32_t revents = 0;
    if (kos_poll(sender, POLLOUT, &revents) != 0 || (revents & POLLOUT) == 0) {
        kos_close(nb_sock);
        kos_close(sender);
        kos_close(receiver);
        return false;
    }

    kos_close(nb_sock);
    kos_close(sender);
    kos_close(receiver);
    return true;
}
