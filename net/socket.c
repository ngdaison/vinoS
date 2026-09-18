#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/net.h>
#include <kos/net_device.h>
#include <kos/sync.h>
#include <kos/wait.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    NET_UDP_QUEUE_DEPTH = 4,
    NET_UDP_HEADER_SIZE = 8,
    NET_EPHEMERAL_PORT_START = 49152,
    NET_EPHEMERAL_PORT_END = 65535,
};

struct udp_datagram {
    struct net_ipv4_endpoint source;
    uint8_t data[NET_UDP_PAYLOAD_MAX];
    uint64_t size;
};

struct udp_socket {
    bool open;
    bool bound;
    struct net_ipv4_endpoint endpoint;
    struct udp_datagram queue[NET_UDP_QUEUE_DEPTH];
    uint64_t queue_head;
    uint64_t queue_tail;
    uint64_t queue_count;
    struct wait_queue wait_queue;
};

static struct udp_socket sockets[NET_SOCKET_MAX];
static struct kos_spinlock network_lock = KOS_SPINLOCK_INITIALIZER;
static bool initialized;
static uint64_t datagrams_sent;
static uint64_t datagrams_received;
static uint64_t datagrams_dropped;
static uint16_t next_ephemeral_port = NET_EPHEMERAL_PORT_START;

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

static void write_u16_be(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static struct udp_socket *socket_at(uint16_t socket_id) {
    if (socket_id >= NET_SOCKET_MAX || !sockets[socket_id].open) {
        return 0;
    }
    return &sockets[socket_id];
}

static uint16_t allocate_ephemeral_port_locked(void) {
    for (uint32_t index = 0; index < 16384; ++index) {
        uint16_t port = next_ephemeral_port++;
        if (next_ephemeral_port > NET_EPHEMERAL_PORT_END) {
            next_ephemeral_port = NET_EPHEMERAL_PORT_START;
        }
        bool in_use = false;
        for (uint64_t slot = 0; slot < NET_SOCKET_MAX; ++slot) {
            if (sockets[slot].open && sockets[slot].bound && sockets[slot].endpoint.port == port) {
                in_use = true;
                break;
            }
        }
        if (!in_use) {
            return port;
        }
    }
    return 0;
}

static struct udp_socket *find_conflicting_socket(struct net_ipv4_endpoint endpoint) {
    for (uint64_t index = 0; index < NET_SOCKET_MAX; ++index) {
        if (sockets[index].open && sockets[index].bound
            && sockets[index].endpoint.port == endpoint.port) {
            if (sockets[index].endpoint.address == 0 || endpoint.address == 0
                || sockets[index].endpoint.address == endpoint.address) {
                return &sockets[index];
            }
        }
    }
    return 0;
}

static uint16_t udp_checksum(uint32_t source_ip, uint32_t dest_ip,
        const uint8_t *udp_header_and_payload, uint64_t length) {
    uint32_t sum = 0;
    sum += (source_ip >> 16) & 0xffffu;
    sum += source_ip & 0xffffu;
    sum += (dest_ip >> 16) & 0xffffu;
    sum += dest_ip & 0xffffu;
    sum += 17u; /* IPPROTO_UDP */
    sum += (uint16_t)length;

    for (uint64_t index = 0; index + 1 < length; index += 2) {
        sum += ((uint16_t)udp_header_and_payload[index] << 8) | udp_header_and_payload[index + 1];
    }
    if ((length & 1) != 0) {
        sum += (uint16_t)udp_header_and_payload[length - 1] << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    uint16_t result = (uint16_t)~sum;
    if (result == 0) {
        result = 0xffffu;
    }
    return result;
}

bool net_initialize(void) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    if (initialized) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    for (uint64_t index = 0; index < NET_SOCKET_MAX; ++index) {
        sockets[index] = (struct udp_socket){0};
        wait_queue_init(&sockets[index].wait_queue);
    }
    datagrams_sent = 0;
    datagrams_received = 0;
    datagrams_dropped = 0;
    next_ephemeral_port = NET_EPHEMERAL_PORT_START;
    struct net_device *dev = net_device_get_default();
    uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE];
    bool has_dev = false;
    if (dev != 0) {
        has_dev = true;
        for (int i = 0; i < NET_ETHERNET_ADDRESS_SIZE; ++i) {
            mac_address[i] = dev->mac_address[i];
        }
    }
    initialized = true;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return !has_dev || net_ipv4_initialize_interface(mac_address);
}

bool net_is_initialized(void) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    bool result = initialized;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return result;
}

bool net_e1000_detected(void) {
    return net_device_get_default() != 0;
}

uint64_t net_udp_datagrams_sent(void) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    uint64_t result = datagrams_sent;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return result;
}

uint64_t net_udp_datagrams_received(void) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    uint64_t result = datagrams_received;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return result;
}

uint64_t net_udp_datagrams_dropped(void) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    uint64_t result = datagrams_dropped;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return result;
}

bool net_udp_open(uint16_t *socket_id) {
    if (socket_id == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    if (!initialized) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    for (uint16_t index = 0; index < NET_SOCKET_MAX; ++index) {
        if (!sockets[index].open) {
            sockets[index] = (struct udp_socket){ .open = true };
            wait_queue_init(&sockets[index].wait_queue);
            *socket_id = index;
            spinlock_unlock_irqrestore(&network_lock, flags);
            return true;
        }
    }
    spinlock_unlock_irqrestore(&network_lock, flags);
    return false;
}

bool net_udp_close(uint16_t socket_id) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    struct udp_socket *socket = socket_at(socket_id);
    if (socket == 0) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    *socket = (struct udp_socket){0};
    spinlock_unlock_irqrestore(&network_lock, flags);
    return true;
}

bool net_udp_bind(uint16_t socket_id, struct net_ipv4_endpoint endpoint) {
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    struct udp_socket *socket = socket_at(socket_id);
    if (socket == 0 || socket->bound) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    if (endpoint.port == 0) {
        endpoint.port = allocate_ephemeral_port_locked();
        if (endpoint.port == 0) {
            spinlock_unlock_irqrestore(&network_lock, flags);
            return false;
        }
    }
    if (find_conflicting_socket(endpoint) != 0) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    socket->endpoint = endpoint;
    socket->bound = true;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return true;
}

bool net_udp_sendto(uint16_t socket_id, struct net_ipv4_endpoint destination,
        const uint8_t *data, uint64_t size) {
    if (data == 0 || size == 0 || size > NET_UDP_PAYLOAD_MAX) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    struct udp_socket *sender = socket_at(socket_id);
    if (sender == 0) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    if (!sender->bound) {
        sender->endpoint.port = allocate_ephemeral_port_locked();
        if (sender->endpoint.port == 0) {
            spinlock_unlock_irqrestore(&network_lock, flags);
            return false;
        }
        sender->bound = true;
    }
    uint16_t source_port = sender->endpoint.port;
    uint32_t source_address = sender->endpoint.address;

    if (destination.address == NET_IPV4_LOOPBACK) {
        struct udp_socket *receiver = 0;
        for (uint64_t index = 0; index < NET_SOCKET_MAX; ++index) {
            if (sockets[index].open && sockets[index].bound
                && sockets[index].endpoint.port == destination.port
                && (sockets[index].endpoint.address == NET_IPV4_LOOPBACK
                    || sockets[index].endpoint.address == 0)) {
                receiver = &sockets[index];
                break;
            }
        }
        if (receiver == 0 || receiver->queue_count == NET_UDP_QUEUE_DEPTH) {
            ++datagrams_dropped;
            spinlock_unlock_irqrestore(&network_lock, flags);
            return false;
        }
        struct udp_datagram *datagram = &receiver->queue[receiver->queue_tail];
        datagram->source = (struct net_ipv4_endpoint){
            .address = source_address != 0 ? source_address : NET_IPV4_LOOPBACK,
            .port = source_port,
        };
        datagram->size = size;
        for (uint64_t index = 0; index < size; ++index) {
            datagram->data[index] = data[index];
        }
        receiver->queue_tail = (receiver->queue_tail + 1) % NET_UDP_QUEUE_DEPTH;
        ++receiver->queue_count;
        ++datagrams_sent;
        wait_queue_wake_all(&receiver->wait_queue);
        spinlock_unlock_irqrestore(&network_lock, flags);
        return true;
    }

    ++datagrams_sent;
    spinlock_unlock_irqrestore(&network_lock, flags);

    struct net_interface_info interface;
    if (!net_interface_info(&interface) || !interface.available) {
        flags = spinlock_lock_irqsave(&network_lock);
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }

    uint32_t sender_ip = source_address;
    if (sender_ip == 0 && destination.address != 0xffffffffu) {
        sender_ip = interface.ipv4_address;
    }

    uint8_t packet[NET_UDP_HEADER_SIZE + NET_UDP_PAYLOAD_MAX];
    uint16_t total_length = (uint16_t)(NET_UDP_HEADER_SIZE + size);
    write_u16_be(&packet[0], source_port);
    write_u16_be(&packet[2], destination.port);
    write_u16_be(&packet[4], total_length);
    write_u16_be(&packet[6], 0);
    for (uint64_t index = 0; index < size; ++index) {
        packet[NET_UDP_HEADER_SIZE + index] = data[index];
    }
    uint16_t checksum = udp_checksum(sender_ip, destination.address, packet, total_length);
    write_u16_be(&packet[6], checksum);

    bool ok = net_ipv4_send_from(17, sender_ip, destination.address, packet, total_length);
    if (!ok) {
        flags = spinlock_lock_irqsave(&network_lock);
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    return true;
}

void net_udp_receive(uint32_t source, uint32_t destination, const uint8_t *packet,
        uint64_t size) {
    if (packet == 0 || size < NET_UDP_HEADER_SIZE) {
        uint64_t flags = spinlock_lock_irqsave(&network_lock);
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        return;
    }
    uint16_t source_port = read_u16_be(&packet[0]);
    uint16_t destination_port = read_u16_be(&packet[2]);
    uint16_t udp_length = read_u16_be(&packet[4]);
    uint16_t received_checksum = read_u16_be(&packet[6]);

    if (udp_length < NET_UDP_HEADER_SIZE || udp_length > size) {
        uint64_t flags = spinlock_lock_irqsave(&network_lock);
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        return;
    }

    uint64_t payload_size = udp_length - NET_UDP_HEADER_SIZE;
    if (payload_size > NET_UDP_PAYLOAD_MAX) {
        uint64_t flags = spinlock_lock_irqsave(&network_lock);
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        return;
    }

    if (received_checksum != 0) {
        uint8_t temp[NET_UDP_HEADER_SIZE + NET_UDP_PAYLOAD_MAX];
        for (uint64_t index = 0; index < udp_length; ++index) {
            temp[index] = packet[index];
        }
        temp[6] = 0;
        temp[7] = 0;
        uint16_t computed = udp_checksum(source, destination, temp, udp_length);
        if (computed != received_checksum) {
            uint64_t flags = spinlock_lock_irqsave(&network_lock);
            ++datagrams_dropped;
            spinlock_unlock_irqrestore(&network_lock, flags);
            return;
        }
    }

    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    struct udp_socket *receiver = 0;
    for (uint64_t index = 0; index < NET_SOCKET_MAX; ++index) {
        if (sockets[index].open && sockets[index].bound
            && sockets[index].endpoint.port == destination_port) {
            if (sockets[index].endpoint.address == 0
                || sockets[index].endpoint.address == destination
                || destination == 0xffffffffu
                || sockets[index].endpoint.address == NET_IPV4_LOOPBACK) {
                receiver = &sockets[index];
                break;
            }
        }
    }

    if (receiver == 0 || receiver->queue_count == NET_UDP_QUEUE_DEPTH) {
        ++datagrams_dropped;
        spinlock_unlock_irqrestore(&network_lock, flags);
        if (receiver == 0 && destination != 0xffffffffu && (destination >> 24) != 127) {
            (void)net_icmp_send_dest_unreachable(source, 3, packet, udp_length);
        }
        return;
    }

    struct udp_datagram *datagram = &receiver->queue[receiver->queue_tail];
    datagram->source = (struct net_ipv4_endpoint){
        .address = source,
        .port = source_port,
    };
    datagram->size = payload_size;
    const uint8_t *payload = &packet[NET_UDP_HEADER_SIZE];
    for (uint64_t index = 0; index < payload_size; ++index) {
        datagram->data[index] = payload[index];
    }
    receiver->queue_tail = (receiver->queue_tail + 1) % NET_UDP_QUEUE_DEPTH;
    ++receiver->queue_count;
    ++datagrams_received;
    wait_queue_wake_all(&receiver->wait_queue);
    spinlock_unlock_irqrestore(&network_lock, flags);
}

bool net_udp_recvfrom(uint16_t socket_id, struct net_ipv4_endpoint *source,
        uint8_t *data, uint64_t capacity, uint64_t *size) {
    if (source == 0 || data == 0 || size == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    struct udp_socket *socket = socket_at(socket_id);
    if (socket == 0 || socket->queue_count == 0) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    const struct udp_datagram *datagram = &socket->queue[socket->queue_head];
    if (capacity < datagram->size) {
        spinlock_unlock_irqrestore(&network_lock, flags);
        return false;
    }
    *source = datagram->source;
    *size = datagram->size;
    for (uint64_t index = 0; index < datagram->size; ++index) {
        data[index] = datagram->data[index];
    }
    socket->queue_head = (socket->queue_head + 1) % NET_UDP_QUEUE_DEPTH;
    --socket->queue_count;
    spinlock_unlock_irqrestore(&network_lock, flags);
    return true;
}

static bool udp_recv_cond(void *arg) {
    struct udp_socket *s = (struct udp_socket *)arg;
    if (s == 0 || !s->open) {
        return true;
    }
    return s->queue_count > 0;
}

bool net_udp_recvfrom_timeout(uint16_t socket_id, struct net_ipv4_endpoint *source,
        uint8_t *data, uint64_t capacity, uint64_t *size, uint64_t timeout_ms) {
    if (source == 0 || data == 0 || size == 0 || socket_id >= NET_SOCKET_MAX) {
        return false;
    }
    if (net_udp_recvfrom(socket_id, source, data, capacity, size)) {
        return true;
    }
    if (timeout_ms == 0) {
        return false;
    }
    struct udp_socket *s = 0;
    uint64_t flags = spinlock_lock_irqsave(&network_lock);
    s = socket_at(socket_id);
    spinlock_unlock_irqrestore(&network_lock, flags);
    if (s == 0) {
        return false;
    }
    uint64_t start_tick = timer_get_ticks();
    uint64_t timeout_ticks = timer_ms_to_ticks(timeout_ms);
    if (timeout_ticks == 0) {
        timeout_ticks = 1;
    }
    while (timer_get_ticks() - start_tick < timeout_ticks) {
        net_poll();
        if (net_udp_recvfrom(socket_id, source, data, capacity, size)) {
            return true;
        }
        uint64_t elapsed_ticks = timer_get_ticks() - start_tick;
        if (elapsed_ticks >= timeout_ticks) {
            break;
        }
        uint64_t remaining_ticks = timeout_ticks - elapsed_ticks;
        uint64_t slice_ticks = remaining_ticks < 10 ? remaining_ticks : 10;
        uint64_t slice_ms = timer_ticks_to_ms(slice_ticks);
        if (slice_ms == 0) {
            slice_ms = 1;
        }
        (void)wait_event_timeout(&s->wait_queue, udp_recv_cond, s, slice_ms);
    }
    net_poll();
    return net_udp_recvfrom(socket_id, source, data, capacity, size);
}

bool net_udp_loopback_self_test(void) {
    static const uint8_t payload[] = { 'K', 'O', 'S', '-', 'U', 'D', 'P' };
    uint8_t received[NET_UDP_PAYLOAD_MAX];
    struct net_ipv4_endpoint source;
    uint64_t received_size;
    uint16_t sender = UINT16_MAX;
    uint16_t receiver = UINT16_MAX;
    const struct net_ipv4_endpoint sender_endpoint = {
        .address = NET_IPV4_LOOPBACK,
        .port = 41000,
    };
    const struct net_ipv4_endpoint receiver_endpoint = {
        .address = NET_IPV4_LOOPBACK,
        .port = 41001,
    };
    if (!net_udp_open(&sender) || !net_udp_open(&receiver)
        || !net_udp_bind(sender, sender_endpoint) || !net_udp_bind(receiver, receiver_endpoint)
        || !net_udp_sendto(sender, receiver_endpoint, payload, sizeof(payload))
        || !net_udp_recvfrom(receiver, &source, received, sizeof(received), &received_size)) {
        (void)net_udp_close(sender);
        (void)net_udp_close(receiver);
        return false;
    }
    bool valid = source.address == sender_endpoint.address && source.port == sender_endpoint.port
        && received_size == sizeof(payload);
    for (uint64_t index = 0; index < sizeof(payload); ++index) {
        if (received[index] != payload[index]) {
            valid = false;
        }
    }
    (void)net_udp_close(sender);
    (void)net_udp_close(receiver);
    return valid;
}
