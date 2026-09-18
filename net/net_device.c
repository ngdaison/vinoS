#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/net_device.h>
#include <kos/spinlock.h>
#include <kos/memory.h>
#include <kos/log.h>

static struct list_head device_list = LIST_HEAD_INIT(device_list);
static kos_spinlock_t dev_lock = KOS_SPINLOCK_INITIALIZER;
static struct net_device *default_device = 0;
static uint32_t next_device_id = 1;
static uint64_t registered_count = 0;

void net_device_subsystem_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    list_init(&device_list);
    default_device = 0;
    next_device_id = 1;
    registered_count = 0;
    spinlock_unlock_irqrestore(&dev_lock, flags);
}

static bool str_equals(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (*a != *b) return false;
        a++;
        b++;
    }
    return *a == *b;
}

bool net_device_register(struct net_device *dev) {
    if (!dev || !dev->ops) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&dev_lock);

    struct net_device *entry;
    list_for_each_entry(entry, &device_list, list_node) {
        if (entry == dev || str_equals(entry->name, dev->name)) {
            spinlock_unlock_irqrestore(&dev_lock, flags);
            return false;
        }
    }

    dev->id = next_device_id++;
    spinlock_init(&dev->lock);
    list_add_tail(&dev->list_node, &device_list);
    registered_count++;

    if (!default_device && !(dev->flags & NET_DEV_FLAG_LOOPBACK)) {
        default_device = dev;
    } else if (!default_device) {
        default_device = dev;
    }

    dev->state = NET_DEV_UP;
    dev->flags |= NET_DEV_FLAG_RUNNING;

    spinlock_unlock_irqrestore(&dev_lock, flags);

    log_info("net_device: registered network interface");
    log_info(dev->name);
    return true;
}

bool net_device_unregister(struct net_device *dev) {
    if (!dev) return false;

    uint64_t flags = spinlock_lock_irqsave(&dev_lock);

    bool found = false;
    struct net_device *entry;
    list_for_each_entry(entry, &device_list, list_node) {
        if (entry == dev) {
            found = true;
            break;
        }
    }

    if (!found) {
        spinlock_unlock_irqrestore(&dev_lock, flags);
        return false;
    }

    list_del(&dev->list_node);
    registered_count--;

    if (default_device == dev) {
        if (!list_empty(&device_list)) {
            default_device = list_first_entry(&device_list, struct net_device, list_node);
        } else {
            default_device = 0;
        }
    }

    dev->state = NET_DEV_DOWN;
    dev->flags &= ~NET_DEV_FLAG_RUNNING;

    spinlock_unlock_irqrestore(&dev_lock, flags);
    return true;
}

struct net_device *net_device_get_default(void) {
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    struct net_device *dev = default_device;
    spinlock_unlock_irqrestore(&dev_lock, flags);
    return dev;
}

bool net_device_set_default(struct net_device *dev) {
    if (!dev) return false;
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    default_device = dev;
    spinlock_unlock_irqrestore(&dev_lock, flags);
    return true;
}

struct net_device *net_device_find_by_name(const char *name) {
    if (!name) return 0;
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    struct net_device *entry;
    list_for_each_entry(entry, &device_list, list_node) {
        if (str_equals(entry->name, name)) {
            spinlock_unlock_irqrestore(&dev_lock, flags);
            return entry;
        }
    }
    spinlock_unlock_irqrestore(&dev_lock, flags);
    return 0;
}

uint64_t net_device_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    uint64_t count = registered_count;
    spinlock_unlock_irqrestore(&dev_lock, flags);
    return count;
}

struct net_device *net_device_at(uint64_t index) {
    uint64_t flags = spinlock_lock_irqsave(&dev_lock);
    uint64_t current = 0;
    struct net_device *entry;
    list_for_each_entry(entry, &device_list, list_node) {
        if (current == index) {
            spinlock_unlock_irqrestore(&dev_lock, flags);
            return entry;
        }
        current++;
    }
    spinlock_unlock_irqrestore(&dev_lock, flags);
    return 0;
}
