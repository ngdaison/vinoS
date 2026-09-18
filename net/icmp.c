#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/net.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/log.h>

enum {
    ICMP_PROTOCOL = 1,
    ICMP_ECHO_REPLY = 0,
    ICMP_DEST_UNREACHABLE = 3,
    ICMP_ECHO_REQUEST = 8,
    ICMP_TIME_EXCEEDED = 11,
    ICMP_HEADER_SIZE = 8,
    ICMP_PING_PAYLOAD_SIZE = 16,
    ICMP_IDENTIFIER = 0x4b4f,
};

struct icmp_ping_waiter {
    bool waiting;
    bool reply_received;
    uint32_t destination;
    uint16_t sequence;
    uint64_t sent_at_tick;
    uint64_t round_trip_ticks;
};

static struct icmp_ping_waiter ping_waiter;
static uint64_t echo_requests_sent;
static uint64_t echo_replies_received;
static uint64_t dest_unreach_sent;
static uint64_t time_exceeded_sent;

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

static void write_u16_be(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static void write_u64_be(uint8_t *data, uint64_t value) {
    for (uint64_t index = 0; index < 8; ++index) {
        data[index] = (uint8_t)(value >> (56 - index * 8));
    }
}

static uint16_t icmp_checksum(const uint8_t *data, uint64_t size) {
    uint32_t sum = 0;
    for (uint64_t index = 0; index + 1 < size; index += 2) {
        sum += ((uint16_t)data[index] << 8) | data[index + 1];
    }
    if ((size & 1) != 0) {
        sum += (uint16_t)data[size - 1] << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static bool icmp_send_echo_reply(uint32_t destination, const uint8_t *request, uint64_t size) {
    if (size < ICMP_HEADER_SIZE || size > NET_ETHERNET_FRAME_MAX - 14 - 20) {
        return false;
    }
    uint8_t reply[NET_ETHERNET_FRAME_MAX - 14 - 20];
    for (uint64_t index = 0; index < size; ++index) {
        reply[index] = request[index];
    }
    reply[0] = ICMP_ECHO_REPLY;
    reply[1] = 0;
    reply[2] = 0;
    reply[3] = 0;
    write_u16_be(&reply[2], icmp_checksum(reply, size));
    return net_ipv4_send(ICMP_PROTOCOL, destination, reply, size);
}

bool net_icmp_send_dest_unreachable(uint32_t destination, uint8_t code,
        const uint8_t *orig_ip_header, uint64_t orig_len) {
    if (destination == 0 || orig_ip_header == 0 || orig_len == 0) {
        return false;
    }
    /* RFC 792: ICMP error includes IPv4 header + 8 bytes of original payload */
    uint64_t include_len = orig_len < 28 ? orig_len : 28;
    uint8_t packet[ICMP_HEADER_SIZE + 28];
    uint64_t total_len = ICMP_HEADER_SIZE + include_len;

    packet[0] = ICMP_DEST_UNREACHABLE;
    packet[1] = code;
    packet[2] = 0;
    packet[3] = 0;
    packet[4] = 0;
    packet[5] = 0;
    packet[6] = 0;
    packet[7] = 0;

    for (uint64_t i = 0; i < include_len; ++i) {
        packet[ICMP_HEADER_SIZE + i] = orig_ip_header[i];
    }

    write_u16_be(&packet[2], icmp_checksum(packet, total_len));
    dest_unreach_sent++;
    return net_ipv4_send(ICMP_PROTOCOL, destination, packet, total_len);
}

bool net_icmp_send_time_exceeded(uint32_t destination, uint8_t code,
        const uint8_t *orig_ip_header, uint64_t orig_len) {
    if (destination == 0 || orig_ip_header == 0 || orig_len < 20) {
        return false;
    }
    uint64_t include_len = orig_len < 28 ? orig_len : 28;
    uint8_t packet[ICMP_HEADER_SIZE + 28];
    uint64_t total_len = ICMP_HEADER_SIZE + include_len;

    packet[0] = ICMP_TIME_EXCEEDED;
    packet[1] = code;
    packet[2] = 0;
    packet[3] = 0;
    packet[4] = 0;
    packet[5] = 0;
    packet[6] = 0;
    packet[7] = 0;

    for (uint64_t i = 0; i < include_len; ++i) {
        packet[ICMP_HEADER_SIZE + i] = orig_ip_header[i];
    }

    write_u16_be(&packet[2], icmp_checksum(packet, total_len));
    time_exceeded_sent++;
    return net_ipv4_send(ICMP_PROTOCOL, destination, packet, total_len);
}

void net_icmp_receive(uint32_t source, const uint8_t *packet, uint64_t size) {
    if (packet == 0 || size < ICMP_HEADER_SIZE || icmp_checksum(packet, size) != 0) {
        return;
    }
    uint8_t type = packet[0];
    uint8_t code = packet[1];

    if (type == ICMP_ECHO_REQUEST && code == 0) {
        (void)icmp_send_echo_reply(source, packet, size);
        return;
    }
    if (type == ICMP_ECHO_REPLY && code == 0) {
        if (read_u16_be(&packet[4]) == ICMP_IDENTIFIER && ping_waiter.waiting
            && source == ping_waiter.destination && read_u16_be(&packet[6]) == ping_waiter.sequence) {
            ping_waiter.round_trip_ticks = timer_ticks() - ping_waiter.sent_at_tick;
            ping_waiter.reply_received = true;
            ++echo_replies_received;
        }
        return;
    }
    if (type == ICMP_DEST_UNREACHABLE) {
        log_warn("ICMP Destination Unreachable received");
        return;
    }
    if (type == ICMP_TIME_EXCEEDED) {
        log_warn("ICMP Time Exceeded received");
        return;
    }
}

bool net_icmp_ping(uint32_t destination, uint16_t sequence, uint64_t timeout_ticks,
        uint64_t *round_trip_ticks) {
    if (round_trip_ticks == 0 || destination == 0 || ping_waiter.waiting) {
        return false;
    }
    uint8_t request[ICMP_HEADER_SIZE + ICMP_PING_PAYLOAD_SIZE] = { 0 };
    request[0] = ICMP_ECHO_REQUEST;
    write_u16_be(&request[4], ICMP_IDENTIFIER);
    write_u16_be(&request[6], sequence);
    request[8] = 'K'; request[9] = 'O'; request[10] = 'S'; request[11] = 'P';
    uint64_t sent_at = timer_ticks();
    write_u64_be(&request[12], sent_at);
    write_u16_be(&request[2], icmp_checksum(request, sizeof(request)));
    ping_waiter = (struct icmp_ping_waiter){
        .waiting = true,
        .destination = destination,
        .sequence = sequence,
        .sent_at_tick = sent_at,
    };
    if (!net_ipv4_send(ICMP_PROTOCOL, destination, request, sizeof(request))) {
        ping_waiter.waiting = false;
        return false;
    }
    ++echo_requests_sent;
    uint64_t started_at = timer_ticks();
    while (timer_ticks() - started_at < timeout_ticks) {
        net_poll();
        if (ping_waiter.reply_received) {
            *round_trip_ticks = ping_waiter.round_trip_ticks;
            ping_waiter.waiting = false;
            return true;
        }
        if (task_is_multitasking_active()) {
            task_sleep(1);
        } else {
            cpu_wait_for_interrupt();
        }
    }
    ping_waiter.waiting = false;
    return false;
}

uint64_t net_icmp_echo_requests_sent(void) { return echo_requests_sent; }
uint64_t net_icmp_echo_replies_received(void) { return echo_replies_received; }

bool net_icmp_self_test(void) {
    static const uint8_t test_packet[] = { 8, 0, 0xac, 0xaf, 0x4b, 0x4f, 0, 1 };
    return icmp_checksum(test_packet, sizeof(test_packet)) == 0;
}
