#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/log.h>
#include <kos/net.h>
#include <kos/sync.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    TCP_FLAG_FIN = 0x01,
    TCP_FLAG_SYN = 0x02,
    TCP_FLAG_RST = 0x04,
    TCP_FLAG_PSH = 0x08,
    TCP_FLAG_ACK = 0x10,
    TCP_FLAG_URG = 0x20,

    TCP_HEADER_MIN_SIZE = 20,
    TCP_OPT_END = 0,
    TCP_OPT_NOP = 1,
    TCP_OPT_MSS = 2,

    TCP_RX_BUFFER_CAPACITY = 8192,
    TCP_MAX_RETRIES = 5,
    TCP_EPHEMERAL_PORT_START = 49152,
    TCP_EPHEMERAL_PORT_END = 65535,
};

struct tcp_socket {
    bool in_use;
    bool is_listening;
    enum tcp_state state;
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;

    int parent_socket;
    uint16_t backlog;
    int accepted_queue[NET_TCP_SOCKET_MAX];
    uint8_t accepted_count;

    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_isn;
    uint32_t rcv_nxt;
    uint32_t rcv_isn;

    uint16_t snd_wnd;
    uint16_t rcv_wnd;
    uint16_t mss;

    /* Congestion control */
    uint32_t cwnd;
    uint32_t ssthresh;

    /* Dynamic RTO Jacobson/Karn */
    uint32_t srtt;
    uint32_t rttvar;
    uint32_t rtt_seq;
    uint64_t rtt_sent_tick;
    bool rtt_measuring;

    /* TIME_WAIT timer */
    uint64_t time_wait_start;

    bool retransmit_pending;
    uint64_t last_sent_tick;
    uint32_t rto_ticks;
    uint8_t retry_count;
    uint8_t pending_packet[NET_ETHERNET_FRAME_MAX];
    uint64_t pending_packet_size;

    uint8_t rx_buffer[TCP_RX_BUFFER_CAPACITY];
    uint64_t rx_head;
    uint64_t rx_tail;
    uint64_t rx_count;

    bool fin_received;
};

static struct tcp_socket tcp_sockets[NET_TCP_SOCKET_MAX];
static struct kos_spinlock tcp_lock = KOS_SPINLOCK_INITIALIZER;
static uint16_t next_tcp_port = TCP_EPHEMERAL_PORT_START;
static uint64_t segments_sent;
static uint64_t segments_received;
static uint64_t retransmissions;

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

static uint32_t read_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[2] << 8) | data[3];
}

static void write_u16_be(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static uint16_t tcp_checksum(uint32_t source_ip, uint32_t dest_ip,
        const uint8_t *tcp_header_and_payload, uint64_t length) {
    uint32_t sum = 0;
    sum += (source_ip >> 16) & 0xffffu;
    sum += source_ip & 0xffffu;
    sum += (dest_ip >> 16) & 0xffffu;
    sum += dest_ip & 0xffffu;
    sum += 6u; /* IPPROTO_TCP */
    sum += (uint16_t)length;

    for (uint64_t index = 0; index + 1 < length; index += 2) {
        sum += ((uint16_t)tcp_header_and_payload[index] << 8) | tcp_header_and_payload[index + 1];
    }
    if ((length & 1) != 0) {
        sum += (uint16_t)tcp_header_and_payload[length - 1] << 8;
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

static uint16_t allocate_tcp_port_locked(void) {
    for (uint32_t index = 0; index < 16384; ++index) {
        uint16_t port = next_tcp_port++;
        if (next_tcp_port > TCP_EPHEMERAL_PORT_END) {
            next_tcp_port = TCP_EPHEMERAL_PORT_START;
        }
        bool in_use = false;
        for (uint64_t slot = 0; slot < NET_TCP_SOCKET_MAX; ++slot) {
            if (tcp_sockets[slot].in_use && tcp_sockets[slot].local_port == port) {
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

static bool tcp_transmit_segment(uint32_t src_ip, uint16_t src_port,
        uint32_t dst_ip, uint16_t dst_port,
        uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window,
        const uint8_t *options, uint64_t options_len,
        const uint8_t *payload, uint64_t payload_len) {
    uint8_t packet[NET_ETHERNET_FRAME_MAX];
    uint8_t data_offset_words = (uint8_t)((TCP_HEADER_MIN_SIZE + options_len) / 4);
    uint64_t tcp_total_len = TCP_HEADER_MIN_SIZE + options_len + payload_len;
    if (tcp_total_len > sizeof(packet)) {
        return false;
    }

    write_u16_be(&packet[0], src_port);
    write_u16_be(&packet[2], dst_port);
    write_u32_be(&packet[4], seq);
    write_u32_be(&packet[8], ack);
    packet[12] = (uint8_t)(data_offset_words << 4);
    packet[13] = flags;
    write_u16_be(&packet[14], window);
    write_u16_be(&packet[16], 0);
    write_u16_be(&packet[18], 0);

    for (uint64_t index = 0; index < options_len; ++index) {
        packet[TCP_HEADER_MIN_SIZE + index] = options[index];
    }
    for (uint64_t index = 0; index < payload_len; ++index) {
        packet[TCP_HEADER_MIN_SIZE + options_len + index] = payload[index];
    }

    uint16_t checksum = tcp_checksum(src_ip, dst_ip, packet, tcp_total_len);
    write_u16_be(&packet[16], checksum);

    (void)__atomic_add_fetch(&segments_sent, 1, __ATOMIC_RELAXED);

    return net_ipv4_send_from(6, src_ip, dst_ip, packet, tcp_total_len);
}

static void tcp_send_ack(struct tcp_socket *s) {
    uint16_t window = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
    (void)tcp_transmit_segment(s->local_ip, s->local_port, s->remote_ip, s->remote_port,
        s->snd_nxt, s->rcv_nxt, TCP_FLAG_ACK, window, 0, 0, 0, 0);
}

static void tcp_send_rst(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
        uint32_t seq, uint32_t ack) {
    (void)tcp_transmit_segment(src_ip, src_port, dst_ip, dst_port, seq, ack,
        TCP_FLAG_RST | TCP_FLAG_ACK, 0, 0, 0, 0, 0);
}

int tcp_connect(uint32_t address, uint16_t port) {
    if (address == 0 || port == 0) {
        return -1;
    }
    struct net_interface_info info;
    if (!net_interface_info(&info) || !info.available) {
        return -1;
    }

    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    int socket_id = -1;
    for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
        if (!tcp_sockets[index].in_use) {
            socket_id = index;
            break;
        }
    }
    if (socket_id < 0) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    uint16_t local_port = allocate_tcp_port_locked();
    if (local_port == 0) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    struct tcp_socket *s = &tcp_sockets[socket_id];
    *s = (struct tcp_socket){
        .in_use = true,
        .state = TCP_STATE_SYN_SENT,
        .local_ip = info.ipv4_address,
        .local_port = local_port,
        .remote_ip = address,
        .remote_port = port,
        .snd_isn = (uint32_t)timer_ticks() * 65536u ^ 0x4b4f5354u,
        .rcv_wnd = TCP_RX_BUFFER_CAPACITY,
        .snd_wnd = NET_TCP_DEFAULT_WINDOW,
        .mss = NET_TCP_DEFAULT_MSS,
        .cwnd = 2 * NET_TCP_DEFAULT_MSS,
        .ssthresh = 65535,
        .rto_ticks = NET_TCP_RTO_TICKS,
        .retry_count = 0,
    };
    s->snd_nxt = s->snd_isn + 1;
    s->snd_una = s->snd_isn;

    /* Build SYN with MSS option */
    uint8_t mss_option[4] = {
        TCP_OPT_MSS, 4,
        (uint8_t)(NET_TCP_DEFAULT_MSS >> 8),
        (uint8_t)NET_TCP_DEFAULT_MSS
    };

    /* Save SYN segment for retransmission */
    uint8_t data_offset_words = (uint8_t)((TCP_HEADER_MIN_SIZE + sizeof(mss_option)) / 4);
    uint64_t total_len = TCP_HEADER_MIN_SIZE + sizeof(mss_option);
    write_u16_be(&s->pending_packet[0], s->local_port);
    write_u16_be(&s->pending_packet[2], s->remote_port);
    write_u32_be(&s->pending_packet[4], s->snd_isn);
    write_u32_be(&s->pending_packet[8], 0);
    s->pending_packet[12] = (uint8_t)(data_offset_words << 4);
    s->pending_packet[13] = TCP_FLAG_SYN;
    write_u16_be(&s->pending_packet[14], s->rcv_wnd);
    write_u16_be(&s->pending_packet[16], 0);
    write_u16_be(&s->pending_packet[18], 0);
    for (uint64_t i = 0; i < sizeof(mss_option); ++i) {
        s->pending_packet[TCP_HEADER_MIN_SIZE + i] = mss_option[i];
    }
    uint16_t cksum = tcp_checksum(s->local_ip, s->remote_ip, s->pending_packet, total_len);
    write_u16_be(&s->pending_packet[16], cksum);
    s->pending_packet_size = total_len;
    s->retransmit_pending = true;
    s->last_sent_tick = timer_ticks();
    s->rtt_seq = s->snd_isn;
    s->rtt_sent_tick = s->last_sent_tick;
    s->rtt_measuring = true;

    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

    /* Send initial SYN */
    (void)__atomic_add_fetch(&segments_sent, 1, __ATOMIC_RELAXED);
    (void)net_ipv4_send_from(6, s->local_ip, s->remote_ip, s->pending_packet, s->pending_packet_size);

    /* Check if already established (e.g. loopback) */
    lock_flags = spinlock_lock_irqsave(&tcp_lock);
    if (s->state == TCP_STATE_ESTABLISHED) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return socket_id;
    }
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

    /* Wait for ESTABLISHED */
    uint64_t timeout_ticks = timer_frequency_hz() * 5;
    uint64_t start = timer_ticks();
    while (timer_ticks() - start < timeout_ticks) {
        net_poll();
        lock_flags = spinlock_lock_irqsave(&tcp_lock);
        if (s->state == TCP_STATE_ESTABLISHED) {
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return socket_id;
        }
        if (s->state == TCP_STATE_CLOSED) {
            s->in_use = false;
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return -1;
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        if (task_is_multitasking_active()) {
            task_sleep(1);
        } else {
            cpu_wait_for_interrupt();
        }
    }

    lock_flags = spinlock_lock_irqsave(&tcp_lock);
    s->state = TCP_STATE_CLOSED;
    s->in_use = false;
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    return -1;
}

int tcp_send(int socket_id, const uint8_t *data, uint64_t size) {
    if (socket_id < 0 || socket_id >= NET_TCP_SOCKET_MAX || data == 0 || size == 0) {
        return -1;
    }

    uint64_t total_sent = 0;
    while (total_sent < size) {
        uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
        struct tcp_socket *s = &tcp_sockets[socket_id];
        if (!s->in_use || (s->state != TCP_STATE_ESTABLISHED && s->state != TCP_STATE_CLOSE_WAIT)) {
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return total_sent > 0 ? (int)total_sent : -1;
        }

        uint64_t chunk_size = size - total_sent;
        if (chunk_size > s->mss) {
            chunk_size = s->mss;
        }
        uint32_t eff_wnd = s->snd_wnd < s->cwnd ? s->snd_wnd : s->cwnd;
        if (eff_wnd < chunk_size && eff_wnd > 0) {
            chunk_size = eff_wnd;
        }

        uint32_t seq = s->snd_nxt;
        uint32_t ack = s->rcv_nxt;
        uint16_t window = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);

        uint64_t total_len = TCP_HEADER_MIN_SIZE + chunk_size;
        write_u16_be(&s->pending_packet[0], s->local_port);
        write_u16_be(&s->pending_packet[2], s->remote_port);
        write_u32_be(&s->pending_packet[4], seq);
        write_u32_be(&s->pending_packet[8], ack);
        s->pending_packet[12] = (uint8_t)(5 << 4); /* 5 words = 20 bytes */
        s->pending_packet[13] = TCP_FLAG_ACK | TCP_FLAG_PSH;
        write_u16_be(&s->pending_packet[14], window);
        write_u16_be(&s->pending_packet[16], 0);
        write_u16_be(&s->pending_packet[18], 0);

        for (uint64_t i = 0; i < chunk_size; ++i) {
            s->pending_packet[TCP_HEADER_MIN_SIZE + i] = data[total_sent + i];
        }

        uint16_t cksum = tcp_checksum(s->local_ip, s->remote_ip, s->pending_packet, total_len);
        write_u16_be(&s->pending_packet[16], cksum);
        s->pending_packet_size = total_len;
        s->retransmit_pending = true;
        s->retry_count = 0;
        s->last_sent_tick = timer_ticks();
        if (s->srtt == 0) {
            s->rto_ticks = NET_TCP_RTO_TICKS;
        }
        if (!s->rtt_measuring) {
            s->rtt_seq = seq + (uint32_t)chunk_size;
            s->rtt_sent_tick = s->last_sent_tick;
            s->rtt_measuring = true;
        }
        s->snd_nxt += (uint32_t)chunk_size;

        uint32_t src_ip = s->local_ip;
        uint32_t dst_ip = s->remote_ip;
        uint64_t pkt_size = s->pending_packet_size;
        uint8_t pkt_buf[NET_ETHERNET_FRAME_MAX];
        for (uint64_t i = 0; i < pkt_size; ++i) {
            pkt_buf[i] = s->pending_packet[i];
        }

        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        (void)__atomic_add_fetch(&segments_sent, 1, __ATOMIC_RELAXED);
        (void)net_ipv4_send_from(6, src_ip, dst_ip, pkt_buf, pkt_size);

        /* Fast check for immediate ACK (e.g. loopback) */
        lock_flags = spinlock_lock_irqsave(&tcp_lock);
        if (s->snd_una >= seq + chunk_size) {
            s->retransmit_pending = false;
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            total_sent += chunk_size;
            continue;
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        /* Wait for ACK */
        uint64_t wait_start = timer_ticks();
        uint64_t wait_timeout = timer_frequency_hz() * 5;
        bool acked = false;
        while (timer_ticks() - wait_start < wait_timeout) {
            net_poll();
            lock_flags = spinlock_lock_irqsave(&tcp_lock);
            if (s->snd_una >= seq + chunk_size) {
                acked = true;
                s->retransmit_pending = false;
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            if (s->state != TCP_STATE_ESTABLISHED) {
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            cpu_wait_for_interrupt();
        }

        if (!acked) {
            lock_flags = spinlock_lock_irqsave(&tcp_lock);
            s->retransmit_pending = false;
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return total_sent > 0 ? (int)total_sent : -1;
        }

        total_sent += chunk_size;
    }

    return (int)total_sent;
}

int tcp_receive(int socket_id, uint8_t *data, uint64_t capacity) {
    if (socket_id < 0 || socket_id >= NET_TCP_SOCKET_MAX || data == 0 || capacity == 0) {
        return -1;
    }
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    struct tcp_socket *s = &tcp_sockets[socket_id];
    if (!s->in_use) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    if (s->rx_count == 0) {
        if ((s->state != TCP_STATE_ESTABLISHED && s->state != TCP_STATE_CLOSE_WAIT) || s->fin_received) {
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return 0;
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        uint64_t timeout_ticks = timer_frequency_hz() * 5;
        uint64_t start = timer_ticks();
        while (timer_ticks() - start < timeout_ticks) {
            net_poll();
            lock_flags = spinlock_lock_irqsave(&tcp_lock);
            if (s->rx_count > 0) {
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            if ((s->state != TCP_STATE_ESTABLISHED && s->state != TCP_STATE_CLOSE_WAIT) || s->fin_received) {
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            cpu_wait_for_interrupt();
        }
    }
    else {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    }

    lock_flags = spinlock_lock_irqsave(&tcp_lock);
    if (!s->in_use) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }
    uint64_t bytes_to_read = capacity < s->rx_count ? capacity : s->rx_count;
    for (uint64_t index = 0; index < bytes_to_read; ++index) {
        data[index] = s->rx_buffer[s->rx_head];
        s->rx_head = (s->rx_head + 1) % TCP_RX_BUFFER_CAPACITY;
    }
    s->rx_count -= bytes_to_read;

    bool need_ack = (bytes_to_read > 0 && (s->state == TCP_STATE_ESTABLISHED || s->state == TCP_STATE_CLOSE_WAIT));
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

    if (need_ack) {
        tcp_send_ack(s);
    }

    return (int)bytes_to_read;
}

void tcp_close(int socket_id) {
    if (socket_id < 0 || socket_id >= NET_TCP_SOCKET_MAX) {
        return;
    }
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    struct tcp_socket *s = &tcp_sockets[socket_id];
    if (!s->in_use) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->is_listening) {
        s->is_listening = false;
        s->state = TCP_STATE_CLOSED;
        s->in_use = false;
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_CLOSE_WAIT) {
        s->state = TCP_STATE_LAST_ACK;
        uint32_t seq = s->snd_nxt;
        uint32_t ack = s->rcv_nxt;
        uint16_t window = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
        s->snd_nxt += 1;
        uint32_t local_ip = s->local_ip;
        uint16_t local_port = s->local_port;
        uint32_t remote_ip = s->remote_ip;
        uint16_t remote_port = s->remote_port;
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        (void)tcp_transmit_segment(local_ip, local_port, remote_ip, remote_port,
            seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK, window, 0, 0, 0, 0);

        uint64_t wait_start = timer_ticks();
        uint64_t wait_timeout = timer_frequency_hz();
        while (timer_ticks() - wait_start < wait_timeout) {
            net_poll();
            lock_flags = spinlock_lock_irqsave(&tcp_lock);
            if (s->state == TCP_STATE_CLOSED) {
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            cpu_wait_for_interrupt();
        }

        lock_flags = spinlock_lock_irqsave(&tcp_lock);
        s->state = TCP_STATE_CLOSED;
        s->in_use = false;
        s->retransmit_pending = false;
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_ESTABLISHED) {
        s->state = TCP_STATE_FIN_WAIT_1;
        uint32_t seq = s->snd_nxt;
        uint32_t ack = s->rcv_nxt;
        uint16_t window = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
        s->snd_nxt += 1;
        uint32_t local_ip = s->local_ip;
        uint16_t local_port = s->local_port;
        uint32_t remote_ip = s->remote_ip;
        uint16_t remote_port = s->remote_port;
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        (void)tcp_transmit_segment(local_ip, local_port, remote_ip, remote_port,
            seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK, window, 0, 0, 0, 0);

        uint64_t wait_start = timer_ticks();
        uint64_t wait_timeout = timer_frequency_hz() * 2;
        while (timer_ticks() - wait_start < wait_timeout) {
            net_poll();
            lock_flags = spinlock_lock_irqsave(&tcp_lock);
            if (s->state == TCP_STATE_CLOSED || s->state == TCP_STATE_FIN_WAIT_2) {
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
                break;
            }
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            cpu_wait_for_interrupt();
        }
    }
    else {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    }

    lock_flags = spinlock_lock_irqsave(&tcp_lock);
    s->state = TCP_STATE_CLOSED;
    s->in_use = false;
    s->retransmit_pending = false;
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
}

int tcp_listen(uint16_t port, uint16_t backlog) {
    if (port == 0) {
        return -1;
    }
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
        if (tcp_sockets[index].in_use && tcp_sockets[index].local_port == port) {
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return -1;
        }
    }
    int socket_id = -1;
    for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
        if (!tcp_sockets[index].in_use) {
            socket_id = index;
            break;
        }
    }
    if (socket_id < 0) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    struct tcp_socket *s = &tcp_sockets[socket_id];
    *s = (struct tcp_socket){
        .in_use = true,
        .is_listening = true,
        .state = TCP_STATE_LISTEN,
        .local_port = port,
        .backlog = backlog > 0 && backlog <= NET_TCP_SOCKET_MAX ? backlog : 4,
    };
    for (int i = 0; i < NET_TCP_SOCKET_MAX; ++i) {
        s->accepted_queue[i] = -1;
    }

    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    return socket_id;
}

int tcp_accept(int listen_socket, struct net_ipv4_endpoint *remote_endpoint) {
    if (listen_socket < 0 || listen_socket >= NET_TCP_SOCKET_MAX) {
        return -1;
    }
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    struct tcp_socket *ls = &tcp_sockets[listen_socket];
    if (!ls->in_use || !ls->is_listening || ls->state != TCP_STATE_LISTEN) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    if (ls->accepted_count == 0) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    int child_sock = -1;
    uint8_t found_index = 0;
    for (uint8_t i = 0; i < ls->accepted_count; ++i) {
        int candidate = ls->accepted_queue[i];
        if (candidate >= 0 && candidate < NET_TCP_SOCKET_MAX && tcp_sockets[candidate].in_use) {
            if (tcp_sockets[candidate].rx_count > 0 || tcp_sockets[candidate].fin_received
                || tcp_sockets[candidate].state != TCP_STATE_ESTABLISHED) {
                child_sock = candidate;
                found_index = i;
                break;
            }
        }
    }

    if (child_sock < 0) {
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return -1;
    }

    for (uint8_t i = found_index; i < ls->accepted_count - 1; ++i) {
        ls->accepted_queue[i] = ls->accepted_queue[i + 1];
    }
    ls->accepted_queue[ls->accepted_count - 1] = -1;
    ls->accepted_count -= 1;

    if (remote_endpoint != 0) {
        remote_endpoint->address = tcp_sockets[child_sock].remote_ip;
        remote_endpoint->port = tcp_sockets[child_sock].remote_port;
    }
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    return child_sock;

    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    return -1;
}

uint64_t net_tcp_get_sockets(struct net_tcp_socket_info *out_sockets, uint64_t max_count) {
    if (out_sockets == 0 || max_count == 0) {
        return 0;
    }
    uint64_t count = 0;
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    for (int index = 0; index < NET_TCP_SOCKET_MAX && count < max_count; ++index) {
        if (tcp_sockets[index].in_use) {
            out_sockets[count].in_use = true;
            out_sockets[count].state = tcp_sockets[index].state;
            out_sockets[count].local_ip = tcp_sockets[index].local_ip;
            out_sockets[count].local_port = tcp_sockets[index].local_port;
            out_sockets[count].remote_ip = tcp_sockets[index].remote_ip;
            out_sockets[count].remote_port = tcp_sockets[index].remote_port;
            out_sockets[count].rx_buffered_bytes = tcp_sockets[index].rx_count;
            out_sockets[count].tx_buffered_bytes = tcp_sockets[index].retransmit_pending
                ? tcp_sockets[index].pending_packet_size : 0;
            ++count;
        }
    }
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
    return count;
}

void net_tcp_receive(uint32_t source, uint32_t destination, const uint8_t *packet, uint64_t size) {
    if (packet == 0 || size < TCP_HEADER_MIN_SIZE) {
        return;
    }
    uint16_t src_port = read_u16_be(&packet[0]);
    uint16_t dst_port = read_u16_be(&packet[2]);
    uint32_t seq = read_u32_be(&packet[4]);
    uint32_t ack = read_u32_be(&packet[8]);
    uint8_t data_offset = (packet[12] >> 4) * 4;
    uint8_t flags = packet[13];
    uint16_t window = read_u16_be(&packet[14]);
    uint16_t received_cksum = read_u16_be(&packet[16]);

    if (data_offset < TCP_HEADER_MIN_SIZE || data_offset > size) {
        return;
    }

    uint8_t temp[NET_ETHERNET_FRAME_MAX];
    for (uint64_t i = 0; i < size; ++i) {
        temp[i] = packet[i];
    }
    temp[16] = 0;
    temp[17] = 0;
    uint16_t computed_cksum = tcp_checksum(source, destination, temp, size);
    if (computed_cksum != received_cksum) {
        return;
    }

    (void)__atomic_add_fetch(&segments_received, 1, __ATOMIC_RELAXED);

    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);

    struct tcp_socket *s = 0;
    for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
        if (tcp_sockets[index].in_use && !tcp_sockets[index].is_listening
            && tcp_sockets[index].local_port == dst_port
            && tcp_sockets[index].remote_port == src_port
            && (tcp_sockets[index].remote_ip == source || tcp_sockets[index].remote_ip == 0)) {
            s = &tcp_sockets[index];
            break;
        }
    }

    if (s == 0) {
        struct tcp_socket *ls = 0;
        int ls_index = -1;
        for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
            if (tcp_sockets[index].in_use && tcp_sockets[index].is_listening
                && tcp_sockets[index].local_port == dst_port) {
                ls = &tcp_sockets[index];
                ls_index = index;
                break;
            }
        }
        if (ls != 0) {
            if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_RST)) {
                int child_slot = -1;
                for (int i = 0; i < NET_TCP_SOCKET_MAX; ++i) {
                    if (!tcp_sockets[i].in_use) {
                        child_slot = i;
                        break;
                    }
                }
                if (child_slot >= 0 && ls->accepted_count < ls->backlog) {
                    struct tcp_socket *cs = &tcp_sockets[child_slot];
                    *cs = (struct tcp_socket){
                        .in_use = true,
                        .is_listening = false,
                        .parent_socket = ls_index,
                        .state = TCP_STATE_SYN_RECEIVED,
                        .local_ip = destination,
                        .local_port = dst_port,
                        .remote_ip = source,
                        .remote_port = src_port,
                        .rcv_isn = seq,
                        .rcv_nxt = seq + 1,
                        .snd_isn = (uint32_t)(timer_ticks() * 1103515245 + 12345 + child_slot * 1000),
                        .rcv_wnd = TCP_RX_BUFFER_CAPACITY,
                        .snd_wnd = window,
                        .mss = NET_TCP_DEFAULT_MSS,
                        .rto_ticks = NET_TCP_RTO_TICKS,
                    };
                    cs->snd_nxt = cs->snd_isn + 1;
                    cs->snd_una = cs->snd_isn;

                    /* Parse MSS option */
                    if (data_offset > TCP_HEADER_MIN_SIZE) {
                        uint64_t opt_offset = TCP_HEADER_MIN_SIZE;
                        while (opt_offset < data_offset) {
                            uint8_t kind = packet[opt_offset];
                            if (kind == TCP_OPT_END) break;
                            if (kind == TCP_OPT_NOP) { ++opt_offset; continue; }
                            if (opt_offset + 1 >= data_offset) break;
                            uint8_t len = packet[opt_offset + 1];
                            if (opt_offset + len > data_offset || len < 2) break;
                            if (kind == TCP_OPT_MSS && len == 4) {
                                uint16_t peer_mss = read_u16_be(&packet[opt_offset + 2]);
                                if (peer_mss > 0 && peer_mss < cs->mss) {
                                    cs->mss = peer_mss;
                                }
                            }
                            opt_offset += len;
                        }
                    }

                    uint32_t c_seq = cs->snd_isn;
                    uint32_t c_ack = cs->rcv_nxt;
                    uint16_t c_win = cs->rcv_wnd;
                    uint8_t mss_opt[4] = { TCP_OPT_MSS, 4, (uint8_t)(NET_TCP_DEFAULT_MSS >> 8), (uint8_t)NET_TCP_DEFAULT_MSS };

                    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

                    (void)__atomic_add_fetch(&segments_sent, 1, __ATOMIC_RELAXED);
                    (void)tcp_transmit_segment(destination, dst_port, source, src_port,
                        c_seq, c_ack, TCP_FLAG_SYN | TCP_FLAG_ACK, c_win, mss_opt, sizeof(mss_opt), 0, 0);
                    return;
                }
            }
            spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
            return;
        }

        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        if ((flags & TCP_FLAG_RST) == 0) {
            tcp_send_rst(destination, dst_port, source, src_port, ack, seq + 1);
        }
        return;
    }

    if (flags & TCP_FLAG_RST) {
        s->state = TCP_STATE_CLOSED;
        s->retransmit_pending = false;
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_SYN_SENT) {
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
            if (ack == s->snd_nxt) {
                s->rcv_isn = seq;
                s->rcv_nxt = seq + 1;
                s->snd_una = ack;
                s->snd_wnd = window;
                s->retransmit_pending = false;

                /* Parse TCP Options (e.g. MSS) */
                if (data_offset > TCP_HEADER_MIN_SIZE) {
                    uint64_t opt_offset = TCP_HEADER_MIN_SIZE;
                    while (opt_offset < data_offset) {
                        uint8_t kind = packet[opt_offset];
                        if (kind == TCP_OPT_END) {
                            break;
                        }
                        if (kind == TCP_OPT_NOP) {
                            ++opt_offset;
                            continue;
                        }
                        if (opt_offset + 1 >= data_offset) {
                            break;
                        }
                        uint8_t len = packet[opt_offset + 1];
                        if (opt_offset + len > data_offset || len < 2) {
                            break;
                        }
                        if (kind == TCP_OPT_MSS && len == 4) {
                            uint16_t peer_mss = read_u16_be(&packet[opt_offset + 2]);
                            if (peer_mss > 0 && peer_mss < s->mss) {
                                s->mss = peer_mss;
                            }
                        }
                        opt_offset += len;
                    }
                }

                s->state = TCP_STATE_ESTABLISHED;
                uint32_t a_src_ip = s->local_ip;
                uint16_t a_src_port = s->local_port;
                uint32_t a_dst_ip = s->remote_ip;
                uint16_t a_dst_port = s->remote_port;
                uint32_t a_seq = s->snd_nxt;
                uint32_t a_ack = s->rcv_nxt;
                uint16_t a_win = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
                spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

                (void)tcp_transmit_segment(a_src_ip, a_src_port, a_dst_ip, a_dst_port,
                    a_seq, a_ack, TCP_FLAG_ACK, a_win, 0, 0, 0, 0);
                return;
            }
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_SYN_RECEIVED) {
        if (flags & TCP_FLAG_ACK) {
            if (ack == s->snd_nxt) {
                s->snd_una = ack;
                s->state = TCP_STATE_ESTABLISHED;
                int p_idx = s->parent_socket;
                if (p_idx >= 0 && p_idx < NET_TCP_SOCKET_MAX && tcp_sockets[p_idx].in_use
                    && tcp_sockets[p_idx].is_listening) {
                    struct tcp_socket *parent = &tcp_sockets[p_idx];
                    if (parent->accepted_count < parent->backlog) {
                        int child_idx = (int)(s - tcp_sockets);
                        parent->accepted_queue[parent->accepted_count++] = child_idx;
                    }
                }
            }
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_ESTABLISHED) {
        if (flags & TCP_FLAG_ACK) {
            if (ack > s->snd_una && ack <= s->snd_nxt) {
                if (s->rtt_measuring && ack >= s->rtt_seq) {
                    uint64_t now_tick = timer_ticks();
                    uint32_t m = (uint32_t)(now_tick - s->rtt_sent_tick);
                    s->rtt_measuring = false;
                    if (s->srtt == 0) {
                        s->srtt = m;
                        s->rttvar = m / 2;
                    } else {
                        int32_t delta = (int32_t)m - (int32_t)s->srtt;
                        if (delta < 0) {
                            delta = -delta;
                        }
                        s->rttvar = (3 * s->rttvar + (uint32_t)delta) / 4;
                        s->srtt = (7 * s->srtt + m) / 8;
                    }
                    uint32_t rto = s->srtt + 4 * s->rttvar;
                    if (rto < 2) {
                        rto = 2;
                    }
                    if (rto > timer_frequency_hz() * 60) {
                        rto = (uint32_t)timer_frequency_hz() * 60;
                    }
                    s->rto_ticks = rto;
                }

                if (s->cwnd < s->ssthresh) {
                    s->cwnd += s->mss;
                } else {
                    s->cwnd += (s->mss * s->mss) / (s->cwnd > 0 ? s->cwnd : 1);
                }

                s->snd_una = ack;
                s->retransmit_pending = false;
            }
            s->snd_wnd = window;
        }

        bool need_ack = false;
        uint64_t payload_len = size - data_offset;
        if (payload_len > 0) {
            if (seq == s->rcv_nxt) {
                uint64_t free_space = TCP_RX_BUFFER_CAPACITY - s->rx_count;
                uint64_t copy_bytes = payload_len < free_space ? payload_len : free_space;
                for (uint64_t i = 0; i < copy_bytes; ++i) {
                    s->rx_buffer[s->rx_tail] = packet[data_offset + i];
                    s->rx_tail = (s->rx_tail + 1) % TCP_RX_BUFFER_CAPACITY;
                }
                s->rx_count += copy_bytes;
                s->rcv_nxt += (uint32_t)copy_bytes;
                need_ack = true;
            }
            else if (seq < s->rcv_nxt) {
                need_ack = true;
            }
        }

        if (flags & TCP_FLAG_FIN) {
            s->rcv_nxt += 1;
            s->fin_received = true;
            s->state = TCP_STATE_CLOSE_WAIT;
            need_ack = true;
        }

        uint32_t a_src_ip = s->local_ip;
        uint16_t a_src_port = s->local_port;
        uint32_t a_dst_ip = s->remote_ip;
        uint16_t a_dst_port = s->remote_port;
        uint32_t a_seq = s->snd_nxt;
        uint32_t a_ack = s->rcv_nxt;
        uint16_t a_win = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        if (need_ack) {
            (void)tcp_transmit_segment(a_src_ip, a_src_port, a_dst_ip, a_dst_port,
                a_seq, a_ack, TCP_FLAG_ACK, a_win, 0, 0, 0, 0);
        }
        return;
    }

    if (s->state == TCP_STATE_CLOSE_WAIT) {
        if (flags & TCP_FLAG_ACK) {
            if (ack > s->snd_una && ack <= s->snd_nxt) {
                s->snd_una = ack;
                s->retransmit_pending = false;
            }
            s->snd_wnd = window;
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_LAST_ACK) {
        if (flags & TCP_FLAG_ACK) {
            if (ack >= s->snd_nxt) {
                s->state = TCP_STATE_CLOSED;
                s->in_use = false;
            }
        }
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
        return;
    }

    if (s->state == TCP_STATE_FIN_WAIT_1) {
        bool need_ack = false;
        if (flags & TCP_FLAG_ACK) {
            if (ack >= s->snd_nxt) {
                s->state = TCP_STATE_FIN_WAIT_2;
            }
        }
        if (flags & TCP_FLAG_FIN) {
            s->rcv_nxt += 1;
            s->state = TCP_STATE_CLOSED;
            need_ack = true;
        }
        uint32_t a_src_ip = s->local_ip;
        uint16_t a_src_port = s->local_port;
        uint32_t a_dst_ip = s->remote_ip;
        uint16_t a_dst_port = s->remote_port;
        uint32_t a_seq = s->snd_nxt;
        uint32_t a_ack = s->rcv_nxt;
        uint16_t a_win = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        if (need_ack) {
            (void)tcp_transmit_segment(a_src_ip, a_src_port, a_dst_ip, a_dst_port,
                a_seq, a_ack, TCP_FLAG_ACK, a_win, 0, 0, 0, 0);
        }
        return;
    }

    if (s->state == TCP_STATE_FIN_WAIT_2) {
        bool need_ack = false;
        if (flags & TCP_FLAG_FIN) {
            s->rcv_nxt += 1;
            s->state = TCP_STATE_TIME_WAIT;
            s->time_wait_start = timer_ticks();
            need_ack = true;
        }
        uint32_t a_src_ip = s->local_ip;
        uint16_t a_src_port = s->local_port;
        uint32_t a_dst_ip = s->remote_ip;
        uint16_t a_dst_port = s->remote_port;
        uint32_t a_seq = s->snd_nxt;
        uint32_t a_ack = s->rcv_nxt;
        uint16_t a_win = (uint16_t)(TCP_RX_BUFFER_CAPACITY - s->rx_count);
        spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

        if (need_ack) {
            (void)tcp_transmit_segment(a_src_ip, a_src_port, a_dst_ip, a_dst_port,
                a_seq, a_ack, TCP_FLAG_ACK, a_win, 0, 0, 0, 0);
        }
        return;
    }

    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
}

void net_tcp_poll(void) {
    uint64_t lock_flags = spinlock_lock_irqsave(&tcp_lock);
    for (int index = 0; index < NET_TCP_SOCKET_MAX; ++index) {
        struct tcp_socket *s = &tcp_sockets[index];
        if (s->in_use && s->state == TCP_STATE_TIME_WAIT) {
            if (timer_ticks() - s->time_wait_start >= NET_TCP_RTO_TICKS * 2) {
                s->state = TCP_STATE_CLOSED;
                s->in_use = false;
            }
            continue;
        }
        if (s->in_use && s->retransmit_pending) {
            if (timer_ticks() - s->last_sent_tick >= s->rto_ticks) {
                if (s->retry_count < TCP_MAX_RETRIES) {
                    ++s->retry_count;
                    (void)__atomic_add_fetch(&retransmissions, 1, __ATOMIC_RELAXED);
                    (void)__atomic_add_fetch(&segments_sent, 1, __ATOMIC_RELAXED);
                    s->last_sent_tick = timer_ticks();
                    s->rto_ticks *= 2;
                    s->rtt_measuring = false;
                    s->ssthresh = s->cwnd / 2;
                    if (s->ssthresh < 2 * s->mss) {
                        s->ssthresh = 2 * s->mss;
                    }
                    s->cwnd = s->mss;
                    uint8_t packet_copy[NET_ETHERNET_FRAME_MAX];
                    uint64_t packet_size = s->pending_packet_size;
                    for (uint64_t i = 0; i < packet_size; ++i) {
                        packet_copy[i] = s->pending_packet[i];
                    }
                    uint32_t src_ip = s->local_ip;
                    uint32_t dst_ip = s->remote_ip;
                    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);

                    (void)net_ipv4_send_from(6, src_ip, dst_ip, packet_copy, packet_size);

                    lock_flags = spinlock_lock_irqsave(&tcp_lock);
                }
                else {
                    s->state = TCP_STATE_CLOSED;
                    s->retransmit_pending = false;
                }
            }
        }
    }
    spinlock_unlock_irqrestore(&tcp_lock, lock_flags);
}

uint64_t net_tcp_segments_sent(void) {
    return __atomic_load_n(&segments_sent, __ATOMIC_RELAXED);
}

uint64_t net_tcp_segments_received(void) {
    return __atomic_load_n(&segments_received, __ATOMIC_RELAXED);
}

uint64_t net_tcp_retransmissions(void) {
    return __atomic_load_n(&retransmissions, __ATOMIC_RELAXED);
}
