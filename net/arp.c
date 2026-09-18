#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/net.h>
#include <kos/timer.h>
#include <kos/sync.h>
#include <kos/task.h>

enum {
    ARP_PACKET_SIZE = 28,
    ARP_HARDWARE_ETHERNET = 1,
    ARP_PROTOCOL_IPV4 = 0x0800,
    ARP_OPERATION_REQUEST = 1,
    ARP_OPERATION_REPLY = 2,
    ARP_ETHERTYPE = 0x0806,
    ARP_ENTRY_TTL_TICKS = 6000, /* 60 seconds at 100 Hz */
};

static struct net_arp_cache_entry arp_cache[NET_ARP_CACHE_MAX];
static struct kos_spinlock arp_lock = KOS_SPINLOCK_INITIALIZER;
static uint64_t arp_requests;
static uint64_t arp_replies;

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

static bool mac_equal(const uint8_t left[NET_ETHERNET_ADDRESS_SIZE],
        const uint8_t right[NET_ETHERNET_ADDRESS_SIZE]) {
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

void net_arp_cache_prune(void) {
    uint64_t flags = spinlock_lock_irqsave(&arp_lock);
    uint64_t now = timer_ticks();
    for (uint64_t index = 0; index < NET_ARP_CACHE_MAX; ++index) {
        if (arp_cache[index].valid && arp_cache[index].expires_at_tick > 0 && now >= arp_cache[index].expires_at_tick) {
            arp_cache[index].valid = false;
        }
    }
    spinlock_unlock_irqrestore(&arp_lock, flags);
}

static bool arp_lookup(uint32_t ipv4_address, uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE]) {
    uint64_t flags = spinlock_lock_irqsave(&arp_lock);
    uint64_t now = timer_ticks();
    for (uint64_t index = 0; index < NET_ARP_CACHE_MAX; ++index) {
        if (arp_cache[index].valid) {
            if (arp_cache[index].expires_at_tick > 0 && now >= arp_cache[index].expires_at_tick) {
                arp_cache[index].valid = false;
                continue;
            }
            if (arp_cache[index].ipv4_address == ipv4_address) {
                for (uint64_t byte = 0; byte < NET_ETHERNET_ADDRESS_SIZE; ++byte) {
                    mac_address[byte] = arp_cache[index].mac_address[byte];
                }
                spinlock_unlock_irqrestore(&arp_lock, flags);
                return true;
            }
        }
    }
    spinlock_unlock_irqrestore(&arp_lock, flags);
    return false;
}

static void arp_remember(uint32_t ipv4_address, const uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE]) {
    uint64_t flags = spinlock_lock_irqsave(&arp_lock);
    uint64_t slot = 0;
    uint64_t oldest_tick = UINT64_MAX;
    uint64_t now = timer_ticks();

    for (uint64_t index = 0; index < NET_ARP_CACHE_MAX; ++index) {
        if (arp_cache[index].valid && arp_cache[index].expires_at_tick > 0 && now >= arp_cache[index].expires_at_tick) {
            arp_cache[index].valid = false;
        }
        if (arp_cache[index].valid && arp_cache[index].ipv4_address == ipv4_address) {
            slot = index;
            oldest_tick = 0;
            break;
        }
        if (!arp_cache[index].valid) {
            slot = index;
            oldest_tick = 0;
            break;
        }
        if (arp_cache[index].learned_at_tick < oldest_tick) {
            oldest_tick = arp_cache[index].learned_at_tick;
            slot = index;
        }
    }
    arp_cache[slot].valid = true;
    arp_cache[slot].ipv4_address = ipv4_address;
    arp_cache[slot].learned_at_tick = now;
    arp_cache[slot].expires_at_tick = now + ARP_ENTRY_TTL_TICKS;
    for (uint64_t byte = 0; byte < NET_ETHERNET_ADDRESS_SIZE; ++byte) {
        arp_cache[slot].mac_address[byte] = mac_address[byte];
    }
    spinlock_unlock_irqrestore(&arp_lock, flags);
}

static bool arp_send(uint16_t operation, const uint8_t destination_mac[NET_ETHERNET_ADDRESS_SIZE],
        uint32_t target_address, const uint8_t target_mac[NET_ETHERNET_ADDRESS_SIZE]) {
    struct net_interface_info interface;
    if (!net_interface_info(&interface) || !interface.available) {
        return false;
    }
    uint8_t packet[ARP_PACKET_SIZE];
    write_u16_be(&packet[0], ARP_HARDWARE_ETHERNET);
    write_u16_be(&packet[2], ARP_PROTOCOL_IPV4);
    packet[4] = NET_ETHERNET_ADDRESS_SIZE;
    packet[5] = 4;
    write_u16_be(&packet[6], operation);
    for (uint64_t index = 0; index < NET_ETHERNET_ADDRESS_SIZE; ++index) {
        packet[8 + index] = interface.mac_address[index];
        packet[18 + index] = target_mac[index];
    }
    write_u32_be(&packet[14], interface.ipv4_address);
    write_u32_be(&packet[24], target_address);
    return net_ethernet_send(destination_mac, ARP_ETHERTYPE, packet, sizeof(packet));
}

static bool arp_send_request(uint32_t target_address) {
    static const uint8_t broadcast[NET_ETHERNET_ADDRESS_SIZE] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    static const uint8_t unknown[NET_ETHERNET_ADDRESS_SIZE] = { 0, 0, 0, 0, 0, 0 };
    if (!arp_send(ARP_OPERATION_REQUEST, broadcast, target_address, unknown)) {
        return false;
    }
    ++arp_requests;
    return true;
}

void net_arp_receive(const uint8_t source[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *payload,
        uint64_t size) {
    if (source == 0 || payload == 0 || size < ARP_PACKET_SIZE
        || read_u16_be(&payload[0]) != ARP_HARDWARE_ETHERNET
        || read_u16_be(&payload[2]) != ARP_PROTOCOL_IPV4 || payload[4] != NET_ETHERNET_ADDRESS_SIZE
        || payload[5] != 4) {
        return;
    }
    uint16_t operation = read_u16_be(&payload[6]);
    const uint8_t *sender_mac = &payload[8];
    uint32_t sender_address = read_u32_be(&payload[14]);
    const uint8_t *target_mac = &payload[18];
    uint32_t target_address = read_u32_be(&payload[24]);
    if (!mac_equal(source, sender_mac) || sender_address == 0) {
        return;
    }
    arp_remember(sender_address, sender_mac);
    if (operation == ARP_OPERATION_REPLY) {
        ++arp_replies;
    }
    struct net_interface_info interface;
    if (operation == ARP_OPERATION_REQUEST && net_interface_info(&interface)
        && interface.available && target_address == interface.ipv4_address) {
        (void)arp_send(ARP_OPERATION_REPLY, sender_mac, sender_address, sender_mac);
    }
    (void)target_mac;
}

bool net_arp_resolve(uint32_t ipv4_address, uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE],
        uint64_t timeout_ticks) {
    if (mac_address == 0 || ipv4_address == 0) {
        return false;
    }
    if (arp_lookup(ipv4_address, mac_address)) {
        return true;
    }
    const uint64_t attempts = 3;
    uint64_t per_attempt = timeout_ticks / attempts;
    if (per_attempt == 0) {
        per_attempt = 1;
    }
    for (uint64_t attempt = 0; attempt < attempts; ++attempt) {
        if (!arp_send_request(ipv4_address)) {
            continue;
        }
        uint64_t start = timer_ticks();
        while (timer_ticks() - start < per_attempt) {
            net_poll();
            if (arp_lookup(ipv4_address, mac_address)) {
                return true;
            }
            if (task_is_multitasking_active()) {
                task_sleep(1);
            } else {
                cpu_wait_for_interrupt();
            }
        }
    }
    return false;
}

uint64_t net_arp_requests_sent(void) { return arp_requests; }
uint64_t net_arp_replies_received(void) { return arp_replies; }

uint64_t net_arp_cache_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&arp_lock);
    uint64_t count = 0;
    uint64_t now = timer_ticks();
    for (uint64_t index = 0; index < NET_ARP_CACHE_MAX; ++index) {
        if (arp_cache[index].valid) {
            if (arp_cache[index].expires_at_tick > 0 && now >= arp_cache[index].expires_at_tick) {
                arp_cache[index].valid = false;
                continue;
            }
            ++count;
        }
    }
    spinlock_unlock_irqrestore(&arp_lock, flags);
    return count;
}

bool net_arp_cache_at(uint64_t index, struct net_arp_cache_entry *entry) {
    if (entry == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&arp_lock);
    uint64_t seen = 0;
    uint64_t now = timer_ticks();
    for (uint64_t slot = 0; slot < NET_ARP_CACHE_MAX; ++slot) {
        if (arp_cache[slot].valid) {
            if (arp_cache[slot].expires_at_tick > 0 && now >= arp_cache[slot].expires_at_tick) {
                arp_cache[slot].valid = false;
                continue;
            }
            if (seen == index) {
                *entry = arp_cache[slot];
                spinlock_unlock_irqrestore(&arp_lock, flags);
                return true;
            }
            ++seen;
        }
    }
    spinlock_unlock_irqrestore(&arp_lock, flags);
    return false;
}
