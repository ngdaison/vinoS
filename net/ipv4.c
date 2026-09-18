#include <stdbool.h>
#include <stdint.h>

#include <kos/net.h>
#include <kos/net_device.h>
#include <kos/sync.h>
#include <kos/timer.h>

enum {
    IPV4_HEADER_SIZE = 20,
    IPV4_ETHERTYPE = 0x0800,
    IPV4_DEFAULT_TTL = 64,
    IPV4_MAX_FRAGMENT_PAYLOAD = 1480, /* 1500 MTU - 20 IP header */
    IPV4_REASM_SLOTS = 8,
    IPV4_REASM_MAX_SIZE = 65536,
    IPV4_REASM_TIMEOUT_TICKS = 3000, /* 30 seconds at 100 Hz */
};

struct ipv4_reasm_slot {
    bool active;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t id;
    uint8_t protocol;
    uint64_t created_tick;
    uint64_t total_size;
    uint64_t received_bytes;
    uint8_t buffer[IPV4_REASM_MAX_SIZE];
    bool block_present[IPV4_REASM_MAX_SIZE / 8];
};

static struct ipv4_reasm_slot reasm_slots[IPV4_REASM_SLOTS];
static struct net_interface_info interface;
static uint16_t next_identification;
static struct kos_spinlock ipv4_lock = KOS_SPINLOCK_INITIALIZER;

void net_icmp_receive(uint32_t source, const uint8_t *packet, uint64_t size);
void net_udp_receive(uint32_t source, uint32_t destination, const uint8_t *packet,
    uint64_t size);
void net_tcp_receive(uint32_t source, uint32_t destination, const uint8_t *packet,
    uint64_t size);
bool net_icmp_send_time_exceeded(uint32_t destination, uint8_t code,
    const uint8_t *orig_ip_header, uint64_t orig_len);

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | data[1];
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

static uint16_t ipv4_checksum(const uint8_t *data, uint64_t size) {
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

bool net_interface_info(struct net_interface_info *info) {
    if (info == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&ipv4_lock);
    *info = interface;
    spinlock_unlock_irqrestore(&ipv4_lock, flags);
    return true;
}

bool net_has_external_interface(void) {
    uint64_t flags = spinlock_lock_irqsave(&ipv4_lock);
    bool avail = interface.available;
    spinlock_unlock_irqrestore(&ipv4_lock, flags);
    return avail;
}

bool net_ipv4_initialize_interface(const uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE]) {
    if (mac_address == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&ipv4_lock);
    interface = (struct net_interface_info){
        .available = true,
        .ipv4_address = NET_QEMU_STATIC_ADDRESS,
        .subnet_mask = 0xffffff00u,
        .gateway = NET_QEMU_GATEWAY_ADDRESS,
        .dns_server = NET_QEMU_DNS_ADDRESS,
        .configuration_source = NET_CONFIGURATION_STATIC,
        .dhcp_state = NET_DHCP_IDLE,
    };
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        interface.mac_address[index] = mac_address[index];
    }
    next_identification = (uint16_t)timer_ticks();
    spinlock_unlock_irqrestore(&ipv4_lock, flags);
    return true;
}

bool net_ipv4_configure_dhcp(uint32_t address, uint32_t subnet_mask, uint32_t gateway,
        uint32_t dns_server, uint64_t lease_seconds) {
    uint64_t flags = spinlock_lock_irqsave(&ipv4_lock);
    if (!interface.available || address == 0 || subnet_mask == 0) {
        spinlock_unlock_irqrestore(&ipv4_lock, flags);
        return false;
    }
    interface.ipv4_address = address;
    interface.subnet_mask = subnet_mask;
    interface.gateway = gateway;
    interface.dns_server = dns_server;
    interface.configuration_source = NET_CONFIGURATION_DHCP;
    interface.dhcp_state = NET_DHCP_BOUND;
    interface.dhcp_lease_seconds = lease_seconds;
    spinlock_unlock_irqrestore(&ipv4_lock, flags);
    return true;
}

void net_ipv4_set_dhcp_state(enum net_dhcp_state state) {
    uint64_t flags = spinlock_lock_irqsave(&ipv4_lock);
    interface.dhcp_state = state;
    spinlock_unlock_irqrestore(&ipv4_lock, flags);
}

static void ipv4_dispatch_payload(uint8_t protocol, uint32_t source, uint32_t destination,
        const uint8_t *payload, uint64_t payload_size) {
    if (protocol == 1) {
        net_icmp_receive(source, payload, payload_size);
    }
    else if (protocol == 17) {
        net_udp_receive(source, destination, payload, payload_size);
    }
    else if (protocol == 6) {
        net_tcp_receive(source, destination, payload, payload_size);
    }
}

static void ipv4_handle_fragment(uint32_t source, uint32_t destination, uint8_t protocol,
        uint16_t id, uint16_t frag_offset, bool more_fragments,
        const uint8_t *payload, uint64_t payload_size, const uint8_t *orig_pkt, uint64_t orig_len) {
    uint64_t now = timer_ticks();
    int slot_idx = -1;

    for (int i = 0; i < IPV4_REASM_SLOTS; ++i) {
        if (reasm_slots[i].active) {
            if (now - reasm_slots[i].created_tick >= IPV4_REASM_TIMEOUT_TICKS) {
                /* Discard expired reassembly and send ICMP Time Exceeded */
                reasm_slots[i].active = false;
                (void)net_icmp_send_time_exceeded(reasm_slots[i].src_ip, 1, orig_pkt, orig_len);
                continue;
            }
            if (reasm_slots[i].src_ip == source && reasm_slots[i].dst_ip == destination
                && reasm_slots[i].id == id && reasm_slots[i].protocol == protocol) {
                slot_idx = i;
                break;
            }
        }
    }

    if (slot_idx < 0) {
        for (int i = 0; i < IPV4_REASM_SLOTS; ++i) {
            if (!reasm_slots[i].active) {
                slot_idx = i;
                break;
            }
        }
        if (slot_idx < 0) {
            return;
        }
        struct ipv4_reasm_slot *slot = &reasm_slots[slot_idx];
        slot->active = true;
        slot->src_ip = source;
        slot->dst_ip = destination;
        slot->id = id;
        slot->protocol = protocol;
        slot->created_tick = now;
        slot->total_size = 0;
        slot->received_bytes = 0;
        for (uint64_t b = 0; b < IPV4_REASM_MAX_SIZE / 8; ++b) {
            slot->block_present[b] = false;
        }
    }

    struct ipv4_reasm_slot *slot = &reasm_slots[slot_idx];
    if (frag_offset + payload_size > IPV4_REASM_MAX_SIZE) {
        slot->active = false;
        return;
    }

    for (uint64_t i = 0; i < payload_size; ++i) {
        slot->buffer[frag_offset + i] = payload[i];
    }
    uint64_t start_block = frag_offset / 8;
    uint64_t block_count = (payload_size + 7) / 8;
    for (uint64_t b = 0; b < block_count && (start_block + b) < (IPV4_REASM_MAX_SIZE / 8); ++b) {
        slot->block_present[start_block + b] = true;
    }
    slot->received_bytes += payload_size;

    if (!more_fragments) {
        slot->total_size = frag_offset + payload_size;
    }

    if (slot->total_size > 0) {
        uint64_t required_blocks = (slot->total_size + 7) / 8;
        bool complete = true;
        for (uint64_t b = 0; b < required_blocks; ++b) {
            if (!slot->block_present[b]) {
                complete = false;
                break;
            }
        }
        if (complete) {
            ipv4_dispatch_payload(slot->protocol, slot->src_ip, slot->dst_ip,
                slot->buffer, slot->total_size);
            slot->active = false;
        }
    }
}

void net_ipv4_receive(const uint8_t source_mac[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *packet,
        uint64_t size) {
    (void)source_mac;
    if (packet == 0 || size < IPV4_HEADER_SIZE || (packet[0] >> 4) != 4) {
        ++interface.ipv4_packets_dropped;
        return;
    }
    uint64_t header_size = (packet[0] & 0x0f) * 4u;
    uint64_t total_size = read_u16_be(&packet[2]);
    if (header_size < IPV4_HEADER_SIZE || header_size > size || total_size < header_size
        || total_size > size || ipv4_checksum(packet, header_size) != 0) {
        ++interface.ipv4_packets_dropped;
        return;
    }

    uint16_t identification = read_u16_be(&packet[4]);
    uint16_t flags_offset = read_u16_be(&packet[6]);
    bool more_fragments = (flags_offset & 0x2000) != 0;
    uint16_t frag_offset = (uint16_t)((flags_offset & 0x1fff) * 8);

    uint8_t protocol = packet[9];
    uint32_t source_address = ((uint32_t)packet[12] << 24) | ((uint32_t)packet[13] << 16)
        | ((uint32_t)packet[14] << 8) | packet[15];
    uint32_t destination = ((uint32_t)packet[16] << 24) | ((uint32_t)packet[17] << 16)
        | ((uint32_t)packet[18] << 8) | packet[19];

    bool in_dhcp_negotiation = (interface.dhcp_state == NET_DHCP_DISCOVERING
        || interface.dhcp_state == NET_DHCP_REQUESTING);
    if (!interface.available
        || (destination != interface.ipv4_address && destination != 0xffffffffu
            && (destination >> 24) != 127
            && !(in_dhcp_negotiation && protocol == 17))) {
        ++interface.ipv4_packets_dropped;
        return;
    }
    ++interface.ipv4_packets_received;

    const uint8_t *payload = &packet[header_size];
    uint64_t payload_size = total_size - header_size;

    if (!more_fragments && frag_offset == 0) {
        ipv4_dispatch_payload(protocol, source_address, destination, payload, payload_size);
    }
    else {
        ipv4_handle_fragment(source_address, destination, protocol, identification,
            frag_offset, more_fragments, payload, payload_size, packet, size);
    }
}

static bool ipv4_emit_fragment(uint8_t protocol, uint32_t source, uint32_t destination,
        uint16_t identification, uint16_t flags_offset,
        const uint8_t destination_mac[NET_ETHERNET_ADDRESS_SIZE],
        const uint8_t *chunk_data, uint64_t chunk_len) {
    uint8_t packet[NET_ETHERNET_FRAME_MAX - 14];
    packet[0] = 0x45;
    packet[1] = 0;
    write_u16_be(&packet[2], (uint16_t)(IPV4_HEADER_SIZE + chunk_len));
    write_u16_be(&packet[4], identification);
    write_u16_be(&packet[6], flags_offset);
    packet[8] = IPV4_DEFAULT_TTL;
    packet[9] = protocol;
    packet[10] = 0;
    packet[11] = 0;
    write_u32_be(&packet[12], source);
    write_u32_be(&packet[16], destination);
    write_u16_be(&packet[10], ipv4_checksum(packet, IPV4_HEADER_SIZE));
    for (uint64_t index = 0; index < chunk_len; ++index) {
        packet[IPV4_HEADER_SIZE + index] = chunk_data[index];
    }
    return net_ethernet_send(destination_mac, IPV4_ETHERTYPE, packet, IPV4_HEADER_SIZE + chunk_len);
}

bool net_ipv4_send_from(uint8_t protocol, uint32_t source, uint32_t destination,
        const uint8_t *payload, uint64_t payload_size) {
    if (!interface.available || payload == 0 || payload_size == 0
        || (source != 0 && source != interface.ipv4_address)) {
        return false;
    }

    /* Loopback routing */
    if (destination == interface.ipv4_address || (destination >> 24) == 127) {
        uint32_t loop_src = source != 0 ? source : interface.ipv4_address;
        ipv4_dispatch_payload(protocol, loop_src, destination, payload, payload_size);
        return true;
    }

    uint8_t destination_mac[NET_ETHERNET_ADDRESS_SIZE];
    if (destination == 0xffffffffu) {
        for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
            destination_mac[index] = 0xff;
        }
    }
    else {
        uint32_t next_hop = (destination & interface.subnet_mask)
                == (interface.ipv4_address & interface.subnet_mask) ? destination : interface.gateway;
        if (next_hop == 0 || !net_arp_resolve(next_hop, destination_mac,
                NET_ARP_DEFAULT_TIMEOUT_TICKS)) {
            return false;
        }
    }

    uint32_t src_ip = source != 0 ? source : interface.ipv4_address;
    uint16_t ident = next_identification++;

    /* Unfragmented path */
    if (payload_size <= IPV4_MAX_FRAGMENT_PAYLOAD) {
        return ipv4_emit_fragment(protocol, src_ip, destination, ident, 0x4000,
            destination_mac, payload, payload_size);
    }

    /* Fragmented transmission */
    uint64_t offset = 0;
    while (offset < payload_size) {
        uint64_t chunk_len = payload_size - offset;
        if (chunk_len > IPV4_MAX_FRAGMENT_PAYLOAD) {
            chunk_len = IPV4_MAX_FRAGMENT_PAYLOAD;
        }
        bool is_last = (offset + chunk_len >= payload_size);
        uint16_t frag_offset = (uint16_t)(offset / 8);
        uint16_t flags_offset = (uint16_t)((is_last ? 0 : 0x2000) | (frag_offset & 0x1fff));

        if (!ipv4_emit_fragment(protocol, src_ip, destination, ident, flags_offset,
                destination_mac, &payload[offset], chunk_len)) {
            return false;
        }
        offset += chunk_len;
    }
    return true;
}

bool net_ipv4_send(uint8_t protocol, uint32_t destination, const uint8_t *payload,
        uint64_t payload_size) {
    return net_ipv4_send_from(protocol, interface.ipv4_address, destination, payload, payload_size);
}

static char hex_digit(uint8_t value) {
    return value < 10 ? (char)('0' + value) : (char)('A' + value - 10);
}

static uint64_t write_decimal(char *text, uint8_t value) {
    if (value >= 100) {
        text[0] = (char)('0' + value / 100);
        text[1] = (char)('0' + (value / 10) % 10);
        text[2] = (char)('0' + value % 10);
        return 3;
    }
    if (value >= 10) {
        text[0] = (char)('0' + value / 10);
        text[1] = (char)('0' + value % 10);
        return 2;
    }
    text[0] = (char)('0' + value);
    return 1;
}

void net_format_ipv4(uint32_t address, char text[16]) {
    uint64_t position = 0;
    for (uint64_t index = 0; index < 4; ++index) {
        position += write_decimal(&text[position], (uint8_t)(address >> (24 - index * 8)));
        if (index != 3) {
            text[position++] = '.';
        }
    }
    text[position] = '\0';
}

void net_format_mac(const uint8_t address[NET_ETHERNET_ADDRESS_SIZE], char text[18]) {
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        text[index * 3] = hex_digit(address[index] >> 4);
        text[index * 3 + 1] = hex_digit(address[index] & 0x0f);
        if (index != NET_ETHERNET_ADDRESS_SIZE - 1) {
            text[index * 3 + 2] = ':';
        }
    }
    text[17] = '\0';
}
