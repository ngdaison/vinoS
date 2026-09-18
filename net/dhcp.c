#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/net.h>
#include <kos/task.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    DHCP_BOOTREQUEST = 1,
    DHCP_BOOTREPLY = 2,
    DHCP_HTYPE_ETHERNET = 1,
    DHCP_HLEN_ETHERNET = 6,
    DHCP_MAGIC_COOKIE = 0x63825363u,
    DHCP_CLIENT_PORT = 68,
    DHCP_SERVER_PORT = 67,
    DHCP_BROADCAST_FLAG = 0x8000,
    DHCP_FIXED_HEADER_SIZE = 236,
    DHCP_PACKET_MIN_SIZE = 300,
    DHCP_PACKET_BUFFER_SIZE = 576,

    DHCP_OPT_PAD = 0,
    DHCP_OPT_SUBNET_MASK = 1,
    DHCP_OPT_ROUTER = 3,
    DHCP_OPT_DNS = 6,
    DHCP_OPT_REQUESTED_IP = 50,
    DHCP_OPT_LEASE_TIME = 51,
    DHCP_OPT_MSG_TYPE = 53,
    DHCP_OPT_SERVER_ID = 54,
    DHCP_OPT_PARAM_REQUEST = 55,
    DHCP_OPT_END = 255,

    DHCP_MSG_DISCOVER = 1,
    DHCP_MSG_OFFER = 2,
    DHCP_MSG_REQUEST = 3,
    DHCP_MSG_DECLINE = 4,
    DHCP_MSG_ACK = 5,
    DHCP_MSG_NAK = 6,
    DHCP_MSG_RELEASE = 7,
    DHCP_MSG_INFORM = 8,
};

struct dhcp_parsed_offer {
    bool valid;
    uint8_t message_type;
    uint32_t offered_ip;
    uint32_t server_id;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t dns_server;
    uint32_t lease_seconds;
};

static uint64_t discovers_sent;
static uint64_t offers_received;
static uint64_t requests_sent;
static uint64_t acks_received;

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

static bool mac_equal(const uint8_t left[NET_ETHERNET_ADDRESS_SIZE],
        const uint8_t right[NET_ETHERNET_ADDRESS_SIZE]) {
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

static void parse_dhcp_options(const uint8_t *packet, uint64_t size,
        struct dhcp_parsed_offer *parsed) {
    if (size < 240) {
        return;
    }
    uint64_t offset = 240;
    while (offset < size) {
        uint8_t tag = packet[offset];
        if (tag == DHCP_OPT_END) {
            break;
        }
        if (tag == DHCP_OPT_PAD) {
            ++offset;
            continue;
        }
        if (offset + 1 >= size) {
            break;
        }
        uint8_t length = packet[offset + 1];
        if (offset + 2 + length > size) {
            break;
        }
        const uint8_t *value = &packet[offset + 2];
        if (tag == DHCP_OPT_MSG_TYPE && length == 1) {
            parsed->message_type = value[0];
        }
        else if (tag == DHCP_OPT_SERVER_ID && length == 4) {
            parsed->server_id = read_u32_be(value);
        }
        else if (tag == DHCP_OPT_SUBNET_MASK && length == 4) {
            parsed->subnet_mask = read_u32_be(value);
        }
        else if (tag == DHCP_OPT_ROUTER && length >= 4) {
            parsed->router = read_u32_be(value);
        }
        else if (tag == DHCP_OPT_DNS && length >= 4) {
            parsed->dns_server = read_u32_be(value);
        }
        else if (tag == DHCP_OPT_LEASE_TIME && length == 4) {
            parsed->lease_seconds = read_u32_be(value);
        }
        offset += 2 + length;
    }
}

static bool validate_dhcp_packet(const uint8_t *packet, uint64_t size, uint32_t expected_xid,
        const uint8_t expected_mac[NET_ETHERNET_ADDRESS_SIZE]) {
    if (packet == 0 || size < 240 || packet[0] != DHCP_BOOTREPLY
        || packet[1] != DHCP_HTYPE_ETHERNET || packet[2] != DHCP_HLEN_ETHERNET) {
        return false;
    }
    if (read_u32_be(&packet[4]) != expected_xid) {
        return false;
    }
    if (!mac_equal(&packet[28], expected_mac)) {
        return false;
    }
    if (read_u32_be(&packet[236]) != DHCP_MAGIC_COOKIE) {
        return false;
    }
    return true;
}

static uint64_t build_dhcp_discover(uint8_t *packet, uint64_t capacity, uint32_t xid,
        const uint8_t mac[NET_ETHERNET_ADDRESS_SIZE]) {
    if (capacity < DHCP_PACKET_MIN_SIZE) {
        return 0;
    }
    for (uint64_t index = 0; index < DHCP_PACKET_MIN_SIZE; ++index) {
        packet[index] = 0;
    }
    packet[0] = DHCP_BOOTREQUEST;
    packet[1] = DHCP_HTYPE_ETHERNET;
    packet[2] = DHCP_HLEN_ETHERNET;
    packet[3] = 0;
    write_u32_be(&packet[4], xid);
    write_u16_be(&packet[8], 0);
    write_u16_be(&packet[10], DHCP_BROADCAST_FLAG);
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        packet[28 + index] = mac[index];
    }
    write_u32_be(&packet[236], DHCP_MAGIC_COOKIE);

    uint64_t offset = 240;
    /* Option 53: DHCP Message Type = Discover */
    packet[offset++] = DHCP_OPT_MSG_TYPE;
    packet[offset++] = 1;
    packet[offset++] = DHCP_MSG_DISCOVER;
    /* Option 55: Parameter Request List */
    packet[offset++] = DHCP_OPT_PARAM_REQUEST;
    packet[offset++] = 3;
    packet[offset++] = DHCP_OPT_SUBNET_MASK;
    packet[offset++] = DHCP_OPT_ROUTER;
    packet[offset++] = DHCP_OPT_DNS;
    /* Option 255: End */
    packet[offset++] = DHCP_OPT_END;

    return offset > DHCP_PACKET_MIN_SIZE ? offset : DHCP_PACKET_MIN_SIZE;
}

static uint64_t build_dhcp_request(uint8_t *packet, uint64_t capacity, uint32_t xid,
        const uint8_t mac[NET_ETHERNET_ADDRESS_SIZE], uint32_t requested_ip, uint32_t server_id) {
    if (capacity < DHCP_PACKET_MIN_SIZE) {
        return 0;
    }
    for (uint64_t index = 0; index < DHCP_PACKET_MIN_SIZE; ++index) {
        packet[index] = 0;
    }
    packet[0] = DHCP_BOOTREQUEST;
    packet[1] = DHCP_HTYPE_ETHERNET;
    packet[2] = DHCP_HLEN_ETHERNET;
    packet[3] = 0;
    write_u32_be(&packet[4], xid);
    write_u16_be(&packet[8], 0);
    write_u16_be(&packet[10], DHCP_BROADCAST_FLAG);
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        packet[28 + index] = mac[index];
    }
    write_u32_be(&packet[236], DHCP_MAGIC_COOKIE);

    uint64_t offset = 240;
    /* Option 53: DHCP Message Type = Request */
    packet[offset++] = DHCP_OPT_MSG_TYPE;
    packet[offset++] = 1;
    packet[offset++] = DHCP_MSG_REQUEST;
    /* Option 50: Requested IP */
    packet[offset++] = DHCP_OPT_REQUESTED_IP;
    packet[offset++] = 4;
    write_u32_be(&packet[offset], requested_ip);
    offset += 4;
    /* Option 54: Server Identifier */
    packet[offset++] = DHCP_OPT_SERVER_ID;
    packet[offset++] = 4;
    write_u32_be(&packet[offset], server_id);
    offset += 4;
    /* Option 55: Parameter Request List */
    packet[offset++] = DHCP_OPT_PARAM_REQUEST;
    packet[offset++] = 3;
    packet[offset++] = DHCP_OPT_SUBNET_MASK;
    packet[offset++] = DHCP_OPT_ROUTER;
    packet[offset++] = DHCP_OPT_DNS;
    /* Option 255: End */
    packet[offset++] = DHCP_OPT_END;

    return offset > DHCP_PACKET_MIN_SIZE ? offset : DHCP_PACKET_MIN_SIZE;
}

bool net_dhcp_acquire(uint64_t timeout_ticks) {
    struct net_interface_info info;
    if (!net_interface_info(&info) || !info.available) {
        return false;
    }
    if (timeout_ticks == 0) {
        timeout_ticks = timer_frequency_hz() * 5;
    }

    uint16_t socket_id = UINT16_MAX;
    if (!net_udp_open(&socket_id)) {
        return false;
    }
    const struct net_ipv4_endpoint client_endpoint = {
        .address = 0,
        .port = DHCP_CLIENT_PORT,
    };
    if (!net_udp_bind(socket_id, client_endpoint)) {
        (void)net_udp_close(socket_id);
        return false;
    }

    uint32_t xid = (uint32_t)timer_ticks() ^ 0x4b4f5332u;
    net_ipv4_set_dhcp_state(NET_DHCP_DISCOVERING);

    uint8_t packet_buffer[DHCP_PACKET_BUFFER_SIZE];
    uint64_t discover_size = build_dhcp_discover(packet_buffer, sizeof(packet_buffer),
        xid, info.mac_address);
    if (discover_size == 0) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        (void)net_udp_close(socket_id);
        return false;
    }

    const struct net_ipv4_endpoint broadcast_server = {
        .address = 0xffffffffu,
        .port = DHCP_SERVER_PORT,
    };

    if (!net_udp_sendto(socket_id, broadcast_server, packet_buffer, discover_size)) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        (void)net_udp_close(socket_id);
        return false;
    }
    ++discovers_sent;

    /* Wait for DHCPOFFER */
    struct dhcp_parsed_offer offer = { 0 };
    uint64_t phase_timeout = timeout_ticks / 2;
    if (phase_timeout == 0) {
        phase_timeout = 1;
    }
    uint64_t start_tick = timer_ticks();
    while (timer_ticks() - start_tick < phase_timeout) {
        net_poll();
        struct net_ipv4_endpoint sender;
        uint64_t received_size;
        if (net_udp_recvfrom(socket_id, &sender, packet_buffer, sizeof(packet_buffer),
                &received_size)) {
            if (validate_dhcp_packet(packet_buffer, received_size, xid, info.mac_address)) {
                offer.offered_ip = read_u32_be(&packet_buffer[16]);
                parse_dhcp_options(packet_buffer, received_size, &offer);
                if (offer.message_type == DHCP_MSG_OFFER && offer.offered_ip != 0) {
                    offer.valid = true;
                    ++offers_received;
                    break;
                }
            }
        }
        cpu_wait_for_interrupt();
    }

    if (!offer.valid) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        (void)net_udp_close(socket_id);
        return false;
    }

    /* Send DHCPREQUEST */
    net_ipv4_set_dhcp_state(NET_DHCP_REQUESTING);
    uint64_t request_size = build_dhcp_request(packet_buffer, sizeof(packet_buffer),
        xid, info.mac_address, offer.offered_ip, offer.server_id);
    if (request_size == 0) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        (void)net_udp_close(socket_id);
        return false;
    }

    if (!net_udp_sendto(socket_id, broadcast_server, packet_buffer, request_size)) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        (void)net_udp_close(socket_id);
        return false;
    }
    ++requests_sent;

    /* Wait for DHCPACK */
    bool ack_received = false;
    start_tick = timer_ticks();
    while (timer_ticks() - start_tick < phase_timeout) {
        net_poll();
        struct net_ipv4_endpoint sender;
        uint64_t received_size;
        if (net_udp_recvfrom(socket_id, &sender, packet_buffer, sizeof(packet_buffer),
                &received_size)) {
            if (validate_dhcp_packet(packet_buffer, received_size, xid, info.mac_address)) {
                struct dhcp_parsed_offer ack_data = { 0 };
                ack_data.offered_ip = read_u32_be(&packet_buffer[16]);
                parse_dhcp_options(packet_buffer, received_size, &ack_data);
                if (ack_data.message_type == DHCP_MSG_ACK) {
                    uint32_t final_ip = ack_data.offered_ip != 0 ? ack_data.offered_ip : offer.offered_ip;
                    uint32_t final_subnet = ack_data.subnet_mask != 0 ? ack_data.subnet_mask : offer.subnet_mask;
                    uint32_t final_router = ack_data.router != 0 ? ack_data.router : offer.router;
                    uint32_t final_dns = ack_data.dns_server != 0 ? ack_data.dns_server : offer.dns_server;
                    uint64_t final_lease = ack_data.lease_seconds != 0 ? ack_data.lease_seconds : offer.lease_seconds;
                    if (final_subnet == 0) {
                        final_subnet = 0xffffff00u;
                    }
                    if (final_lease == 0) {
                        final_lease = 86400;
                    }
                    (void)net_ipv4_configure_dhcp(final_ip, final_subnet, final_router, final_dns, final_lease);
                    ++acks_received;
                    ack_received = true;
                    break;
                }
                else if (ack_data.message_type == DHCP_MSG_NAK) {
                    break;
                }
            }
        }
        cpu_wait_for_interrupt();
    }

    (void)net_udp_close(socket_id);
    if (!ack_received) {
        net_ipv4_set_dhcp_state(NET_DHCP_FAILED);
        return false;
    }
    return true;
}

bool net_dhcp_renew(uint64_t timeout_ticks) {
    return net_dhcp_acquire(timeout_ticks);
}

enum net_dhcp_state net_dhcp_current_state(void) {
    struct net_interface_info info;
    if (!net_interface_info(&info)) {
        return NET_DHCP_FAILED;
    }
    return info.dhcp_state;
}

uint64_t net_dhcp_discovers_sent(void) { return discovers_sent; }
uint64_t net_dhcp_offers_received(void) { return offers_received; }
uint64_t net_dhcp_requests_sent(void) { return requests_sent; }
uint64_t net_dhcp_acks_received(void) { return acks_received; }
