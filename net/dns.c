#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/net.h>
#include <kos/task.h>
#include <kos/task.h>
#include <kos/sync.h>
#include <kos/timer.h>

enum {
    DNS_HEADER_SIZE = 12,
    DNS_FLAG_RESPONSE = 0x8000,
    DNS_FLAG_RECURSION_DESIRED = 0x0100,
    DNS_RCODE_MASK = 0x000f,
    DNS_RCODE_NO_ERROR = 0,
    DNS_TYPE_A = 1,
    DNS_CLASS_IN = 1,
    DNS_MAX_HOSTNAME = 64,
    DNS_PACKET_MAX = 512,
    DNS_DEFAULT_TIMEOUT_TICKS = 300,
};

struct net_dns_cache_entry {
    bool valid;
    char hostname[DNS_MAX_HOSTNAME];
    uint32_t ipv4_address;
    uint64_t learned_at_tick;
    uint32_t ttl_seconds;
};

static struct net_dns_cache_entry dns_cache[NET_DNS_CACHE_MAX];
static struct kos_spinlock dns_lock = KOS_SPINLOCK_INITIALIZER;
static uint64_t dns_queries_sent;
static uint64_t dns_responses_received;
static uint16_t next_query_id = 0x2468;

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

static uint64_t str_len(const char *s) {
    if (s == 0) {
        return 0;
    }
    uint64_t len = 0;
    while (s[len] != '\0') {
        ++len;
    }
    return len;
}

static char to_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static bool str_case_equal(const char *a, const char *b) {
    if (a == 0 || b == 0) {
        return false;
    }
    while (*a != '\0' && *b != '\0') {
        if (to_lower(*a) != to_lower(*b)) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

static void str_copy(char *dest, const char *src, uint64_t max_capacity) {
    if (dest == 0 || max_capacity == 0) {
        return;
    }
    if (src == 0) {
        dest[0] = '\0';
        return;
    }
    uint64_t idx = 0;
    while (src[idx] != '\0' && idx + 1 < max_capacity) {
        dest[idx] = src[idx];
        ++idx;
    }
    dest[idx] = '\0';
}

static bool dns_cache_lookup(const char *hostname, uint32_t *out_address) {
    uint64_t flags = spinlock_lock_irqsave(&dns_lock);
    for (uint64_t i = 0; i < NET_DNS_CACHE_MAX; ++i) {
        if (dns_cache[i].valid && str_case_equal(dns_cache[i].hostname, hostname)) {
            *out_address = dns_cache[i].ipv4_address;
            spinlock_unlock_irqrestore(&dns_lock, flags);
            return true;
        }
    }
    spinlock_unlock_irqrestore(&dns_lock, flags);
    return false;
}

static void dns_cache_insert(const char *hostname, uint32_t address, uint32_t ttl) {
    uint64_t flags = spinlock_lock_irqsave(&dns_lock);
    uint64_t slot = 0;
    uint64_t oldest_tick = UINT64_MAX;
    for (uint64_t i = 0; i < NET_DNS_CACHE_MAX; ++i) {
        if (dns_cache[i].valid && str_case_equal(dns_cache[i].hostname, hostname)) {
            slot = i;
            oldest_tick = 0;
            break;
        }
        if (!dns_cache[i].valid) {
            slot = i;
            oldest_tick = 0;
            break;
        }
        if (dns_cache[i].learned_at_tick < oldest_tick) {
            oldest_tick = dns_cache[i].learned_at_tick;
            slot = i;
        }
    }
    dns_cache[slot].valid = true;
    str_copy(dns_cache[slot].hostname, hostname, sizeof(dns_cache[slot].hostname));
    dns_cache[slot].ipv4_address = address;
    dns_cache[slot].learned_at_tick = timer_ticks();
    dns_cache[slot].ttl_seconds = ttl > 0 ? ttl : 300;
    spinlock_unlock_irqrestore(&dns_lock, flags);
}

static uint64_t encode_qname(const char *hostname, uint8_t *buffer, uint64_t capacity) {
    uint64_t hlen = str_len(hostname);
    if (hlen == 0 || hlen + 2 > capacity) {
        return 0;
    }
    uint64_t read_idx = 0;
    uint64_t write_idx = 0;
    while (read_idx < hlen) {
        uint64_t label_len = 0;
        while (read_idx + label_len < hlen && hostname[read_idx + label_len] != '.') {
            ++label_len;
        }
        if (label_len == 0 || label_len > 63 || write_idx + 1 + label_len >= capacity) {
            return 0;
        }
        buffer[write_idx++] = (uint8_t)label_len;
        for (uint64_t i = 0; i < label_len; ++i) {
            buffer[write_idx++] = (uint8_t)hostname[read_idx + i];
        }
        read_idx += label_len;
        if (read_idx < hlen && hostname[read_idx] == '.') {
            ++read_idx;
        }
    }
    if (write_idx < capacity) {
        buffer[write_idx++] = 0;
        return write_idx;
    }
    return 0;
}

static uint64_t skip_dns_name(const uint8_t *packet, uint64_t size, uint64_t offset) {
    while (offset < size) {
        uint8_t len = packet[offset];
        if (len == 0) {
            return offset + 1;
        }
        if ((len & 0xc0) == 0xc0) {
            /* Pointer is 2 bytes */
            if (offset + 2 <= size) {
                return offset + 2;
            }
            return size + 1;
        }
        if (offset + 1 + len > size) {
            return size + 1;
        }
        offset += 1 + len;
    }
    return size + 1;
}

bool net_dns_resolve(const char *hostname, uint32_t *out_address, uint64_t timeout_ticks) {
    if (hostname == 0 || out_address == 0 || *hostname == '\0') {
        return false;
    }

    /* Fast path 1: Check cache */
    if (dns_cache_lookup(hostname, out_address)) {
        return true;
    }

    struct net_interface_info info;
    if (!net_interface_info(&info) || !info.available || info.dns_server == 0) {
        return false;
    }

    uint16_t query_id = (uint16_t)__atomic_add_fetch(&next_query_id, 1, __ATOMIC_RELAXED);
    uint8_t query_packet[DNS_PACKET_MAX];

    write_u16_be(&query_packet[0], query_id);
    write_u16_be(&query_packet[2], DNS_FLAG_RECURSION_DESIRED);
    write_u16_be(&query_packet[4], 1); /* QDCOUNT = 1 */
    write_u16_be(&query_packet[6], 0); /* ANCOUNT = 0 */
    write_u16_be(&query_packet[8], 0); /* NSCOUNT = 0 */
    write_u16_be(&query_packet[10], 0); /* ARCOUNT = 0 */

    uint64_t qname_len = encode_qname(hostname, &query_packet[DNS_HEADER_SIZE],
        sizeof(query_packet) - DNS_HEADER_SIZE - 4);
    if (qname_len == 0) {
        return false;
    }
    uint64_t offset = DNS_HEADER_SIZE + qname_len;
    write_u16_be(&query_packet[offset], DNS_TYPE_A);
    write_u16_be(&query_packet[offset + 2], DNS_CLASS_IN);
    uint64_t total_query_size = offset + 4;

    uint16_t socket_id;
    if (!net_udp_open(&socket_id)) {
        return false;
    }
    if (!net_udp_bind(socket_id, (struct net_ipv4_endpoint){ .address = 0, .port = 0 })) {
        (void)net_udp_close(socket_id);
        return false;
    }

    struct net_ipv4_endpoint dns_endpoint = {
        .address = info.dns_server,
        .port = NET_DNS_PORT,
    };

    (void)__atomic_add_fetch(&dns_queries_sent, 1, __ATOMIC_RELAXED);
    if (!net_udp_sendto(socket_id, dns_endpoint, query_packet, total_query_size)) {
        (void)net_udp_close(socket_id);
        return false;
    }

    uint64_t timeout = timeout_ticks > 0 ? timeout_ticks : DNS_DEFAULT_TIMEOUT_TICKS;
    uint64_t start = timer_ticks();
    uint8_t resp_packet[DNS_PACKET_MAX];
    bool resolved = false;

    while (timer_ticks() - start < timeout) {
        net_poll();
        struct net_ipv4_endpoint source_ep;
        uint64_t received_size = 0;
        if (net_udp_recvfrom(socket_id, &source_ep, resp_packet, sizeof(resp_packet), &received_size)) {
            if (received_size >= DNS_HEADER_SIZE) {
                uint16_t resp_id = read_u16_be(&resp_packet[0]);
                uint16_t flags = read_u16_be(&resp_packet[2]);
                uint16_t qdcount = read_u16_be(&resp_packet[4]);
                uint16_t ancount = read_u16_be(&resp_packet[6]);

                if (resp_id == query_id && (flags & DNS_FLAG_RESPONSE) != 0
                    && (flags & DNS_RCODE_MASK) == DNS_RCODE_NO_ERROR && ancount > 0) {
                    (void)__atomic_add_fetch(&dns_responses_received, 1, __ATOMIC_RELAXED);

                    uint64_t parse_offset = DNS_HEADER_SIZE;
                    /* Skip questions */
                    for (uint16_t q = 0; q < qdcount && parse_offset < received_size; ++q) {
                        parse_offset = skip_dns_name(resp_packet, received_size, parse_offset);
                        parse_offset += 4; /* QTYPE + QCLASS */
                    }

                    /* Parse answers */
                    for (uint16_t a = 0; a < ancount && parse_offset < received_size; ++a) {
                        parse_offset = skip_dns_name(resp_packet, received_size, parse_offset);
                        if (parse_offset + 10 > received_size) {
                            break;
                        }
                        uint16_t type = read_u16_be(&resp_packet[parse_offset]);
                        uint16_t class = read_u16_be(&resp_packet[parse_offset + 2]);
                        uint32_t ttl = read_u32_be(&resp_packet[parse_offset + 4]);
                        uint16_t rdlength = read_u16_be(&resp_packet[parse_offset + 8]);
                        parse_offset += 10;

                        if (type == DNS_TYPE_A && class == DNS_CLASS_IN && rdlength == 4) {
                            if (parse_offset + 4 <= received_size) {
                                uint32_t ip = read_u32_be(&resp_packet[parse_offset]);
                                *out_address = ip;
                                dns_cache_insert(hostname, ip, ttl);
                                resolved = true;
                                break;
                            }
                        }
                        parse_offset += rdlength;
                    }
                    if (resolved) {
                        break;
                    }
                }
            }
        }
        cpu_wait_for_interrupt();
    }

    (void)net_udp_close(socket_id);
    return resolved;
}

uint64_t net_dns_queries_sent(void) {
    return __atomic_load_n(&dns_queries_sent, __ATOMIC_RELAXED);
}

uint64_t net_dns_responses_received(void) {
    return __atomic_load_n(&dns_responses_received, __ATOMIC_RELAXED);
}
