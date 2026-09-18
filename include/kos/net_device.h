#ifndef KOS_NET_DEVICE_H
#define KOS_NET_DEVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <kos/spinlock.h>
#include <kos/list.h>

#define NET_DEVICE_NAME_MAX 32
#define NET_MAX_DEVICES 8
#define NET_DEFAULT_MTU 1500

enum net_device_state {
    NET_DEV_DOWN  = 0,
    NET_DEV_UP    = 1,
    NET_DEV_ERROR = 2,
};

enum net_device_flags {
    NET_DEV_FLAG_BROADCAST    = (1u << 0),
    NET_DEV_FLAG_LOOPBACK     = (1u << 1),
    NET_DEV_FLAG_POINTTOPOINT = (1u << 2),
    NET_DEV_FLAG_RUNNING      = (1u << 3),
    NET_DEV_FLAG_LINK_UP      = (1u << 4),
};

struct net_device_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t tx_timeouts;
    uint64_t interrupts;
};

struct net_device;

struct net_device_ops {
    bool (*open)(struct net_device *dev);
    void (*stop)(struct net_device *dev);
    bool (*transmit)(struct net_device *dev, const uint8_t *frame, uint64_t size);
    bool (*receive)(struct net_device *dev, uint8_t *frame, uint64_t capacity, uint64_t *size);
    bool (*wait_transmit)(struct net_device *dev, uint64_t timeout_ticks);
    void (*poll)(struct net_device *dev);
    bool (*get_stats)(struct net_device *dev, struct net_device_stats *stats);
    bool (*reset)(struct net_device *dev);
};

struct net_device {
    uint32_t id;
    char name[NET_DEVICE_NAME_MAX];
    uint8_t mac_address[6];
    uint16_t mtu;
    enum net_device_state state;
    uint32_t flags;
    struct net_device_stats stats;

    const struct net_device_ops *ops;
    void *priv;
    kos_spinlock_t lock;
    struct list_head list_node;
};

void net_device_subsystem_init(void);
bool net_device_register(struct net_device *dev);
bool net_device_unregister(struct net_device *dev);
struct net_device *net_device_get_default(void);
bool net_device_set_default(struct net_device *dev);
struct net_device *net_device_find_by_name(const char *name);
uint64_t net_device_count(void);
struct net_device *net_device_at(uint64_t index);

#endif /* KOS_NET_DEVICE_H */
