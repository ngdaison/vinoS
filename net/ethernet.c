#include <stdbool.h>
#include <stdint.h>

#include <kos/net.h>
#include <kos/net_device.h>

enum {
    ETHERNET_HEADER_SIZE = 14,
    ETHER_TYPE_ARP = 0x0806,
    ETHER_TYPE_IPV4 = 0x0800,
    ETHERNET_POLL_BUDGET = 32,
};

void net_arp_receive(const uint8_t source[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *payload,
    uint64_t size);
void net_ipv4_receive(const uint8_t source[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *payload,
    uint64_t size);

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

static uint64_t frames_sent;
static uint64_t frames_received;
static uint64_t frames_dropped;

bool net_ethernet_send(const uint8_t destination[NET_ETHERNET_ADDRESS_SIZE], uint16_t ether_type,
        const uint8_t *payload, uint64_t payload_size) {
    if (destination == 0 || payload == 0 || payload_size == 0
        || payload_size > NET_ETHERNET_FRAME_MAX - ETHERNET_HEADER_SIZE) {
        return false;
    }
    struct net_device *dev = net_device_get_default();
    if (dev == 0 || dev->ops == 0 || dev->ops->transmit == 0) {
        return false;
    }

    uint8_t frame[NET_ETHERNET_FRAME_MAX];
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        frame[index] = destination[index];
        frame[NET_ETHERNET_ADDRESS_SIZE + index] = dev->mac_address[index];
    }
    frame[12] = (uint8_t)(ether_type >> 8);
    frame[13] = (uint8_t)ether_type;
    for (uint64_t index = 0; index < payload_size; ++index) {
        frame[ETHERNET_HEADER_SIZE + index] = payload[index];
    }

    if (!dev->ops->transmit(dev, frame, ETHERNET_HEADER_SIZE + payload_size)) {
        ++frames_dropped;
        return false;
    }
    ++frames_sent;
    return true;
}

bool net_ethernet_wait_for_transmit(uint64_t timeout_ticks) {
    struct net_device *dev = net_device_get_default();
    if (dev == 0 || dev->ops == 0 || dev->ops->wait_transmit == 0) {
        return false;
    }
    return dev->ops->wait_transmit(dev, timeout_ticks);
}

uint64_t net_ethernet_frames_sent(void) { return frames_sent; }
uint64_t net_ethernet_frames_received(void) { return frames_received; }
uint64_t net_ethernet_frames_dropped(void) { return frames_dropped; }

void net_poll(void) {
    struct net_device *dev = net_device_get_default();
    if (dev != 0 && dev->ops != 0) {
        if (dev->ops->receive != 0) {
            uint8_t frame[NET_ETHERNET_FRAME_MAX];
            for (uint64_t packet = 0; packet < ETHERNET_POLL_BUDGET; ++packet) {
                uint64_t size = 0;
                if (!dev->ops->receive(dev, frame, sizeof(frame), &size)) {
                    break;
                }
                if (size < ETHERNET_HEADER_SIZE) {
                    ++frames_dropped;
                    continue;
                }
                ++frames_received;
                uint16_t ether_type = read_u16_be(&frame[12]);
                const uint8_t *source = &frame[NET_ETHERNET_ADDRESS_SIZE];
                const uint8_t *payload = &frame[ETHERNET_HEADER_SIZE];
                uint64_t payload_size = size - ETHERNET_HEADER_SIZE;
                if (ether_type == ETHER_TYPE_ARP) {
                    net_arp_receive(source, payload, payload_size);
                }
                else if (ether_type == ETHER_TYPE_IPV4) {
                    net_ipv4_receive(source, payload, payload_size);
                }
            }
        }
        if (dev->ops->poll != 0) {
            dev->ops->poll(dev);
        }
    }
    net_tcp_poll();
    httpd_poll();
}
