#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/e1000.h>
#include <kos/heap.h>
#include <kos/memory.h>
#include <kos/pci.h>
#include <kos/pic.h>
#include <kos/interrupts.h>
#include <kos/sync.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/vmm.h>
#include <kos/net_device.h>
#include <kos/log.h>

enum {
    E1000_VENDOR_ID = 0x8086,
    E1000_DEVICE_82540EM = 0x100e,
    E1000_DEVICE_82545EM = 0x100f,
    E1000_DEVICE_82544GC = 0x1008,
    E1000_DEVICE_82541GI = 0x107c,
    E1000_BAR_MEMORY_MASK = 0xfffffff0u,
    E1000_MMIO_SIZE = 0x20000,
    E1000_MMIO_VIRTUAL_BASE = 0xffffc10000000000ull,

    E1000_REGISTER_CTRL    = 0x0000,
    E1000_REGISTER_STATUS  = 0x0008,
    E1000_REGISTER_ICR     = 0x00C0,
    E1000_REGISTER_ICS     = 0x00C8,
    E1000_REGISTER_IMS     = 0x00D0,
    E1000_REGISTER_IMC     = 0x00D8,
    E1000_REGISTER_RCTL    = 0x0100,
    E1000_REGISTER_TCTL    = 0x0400,
    E1000_REGISTER_TIPG    = 0x0410,
    E1000_REGISTER_RDBAL   = 0x2800,
    E1000_REGISTER_RDBAH   = 0x2804,
    E1000_REGISTER_RDLEN   = 0x2808,
    E1000_REGISTER_RDH     = 0x2810,
    E1000_REGISTER_RDT     = 0x2818,
    E1000_REGISTER_TDBAL   = 0x3800,
    E1000_REGISTER_TDBAH   = 0x3804,
    E1000_REGISTER_TDLEN   = 0x3808,
    E1000_REGISTER_TDH     = 0x3810,
    E1000_REGISTER_TDT     = 0x3818,
    E1000_REGISTER_RAL     = 0x5400,
    E1000_REGISTER_RAH     = 0x5404,

    E1000_CTRL_RESET       = 1u << 26,
    E1000_STATUS_LU        = 1u << 1,

    E1000_ICR_TXDW         = 1u << 0,
    E1000_ICR_TXQE         = 1u << 1,
    E1000_ICR_LSC          = 1u << 2,
    E1000_ICR_RXSEQ        = 1u << 3,
    E1000_ICR_RXDMT0       = 1u << 4,
    E1000_ICR_RXO          = 1u << 6,
    E1000_ICR_RXT0         = 1u << 7,

    E1000_RCTL_ENABLE      = 1u << 1,
    E1000_RCTL_BROADCAST_ACCEPT = 1u << 15,
    E1000_RCTL_STRIP_CRC   = 1u << 26,

    E1000_TCTL_ENABLE      = 1u << 1,
    E1000_TCTL_PAD_SHORT   = 1u << 3,

    E1000_TX_COMMAND_END_OF_PACKET = 1u << 0,
    E1000_TX_COMMAND_INSERT_FCS    = 1u << 1,
    E1000_TX_COMMAND_REPORT_STATUS = 1u << 3,
    E1000_TX_STATUS_DONE   = 1u << 0,

    E1000_RX_STATUS_DONE   = 1u << 0,
    E1000_RX_ERR_CE        = 1u << 0,
    E1000_RX_ERR_SE        = 1u << 1,
    E1000_RX_ERR_SEQ       = 1u << 2,
    E1000_RX_ERR_CXE       = 1u << 4,
    E1000_RX_ERR_RXE       = 1u << 7,

    E1000_DESCRIPTOR_COUNT = 32,
    E1000_FRAME_BUFFER_SIZE = 2048,
    E1000_RESET_SPINS = 100000,
};

struct e1000_tx_descriptor {
    uint64_t address;
    uint16_t length;
    uint8_t checksum_offset;
    uint8_t command;
    uint8_t status;
    uint8_t checksum_start;
    uint16_t special;
} __attribute__((packed));

struct e1000_rx_descriptor {
    uint64_t address;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} __attribute__((packed));

_Static_assert(sizeof(struct e1000_tx_descriptor) == 16, "e1000 TX descriptor must be 16 bytes");
_Static_assert(sizeof(struct e1000_rx_descriptor) == 16, "e1000 RX descriptor must be 16 bytes");

struct e1000_dma_allocation {
    void *raw;
    uint8_t *address;
    uint64_t physical;
};

struct e1000_state {
    volatile uint32_t *registers;
    struct e1000_dma_allocation tx_ring_memory;
    struct e1000_dma_allocation rx_ring_memory;
    struct e1000_dma_allocation tx_buffer_memory[E1000_DESCRIPTOR_COUNT];
    struct e1000_dma_allocation rx_buffer_memory[E1000_DESCRIPTOR_COUNT];
    struct e1000_tx_descriptor *tx_ring;
    struct e1000_rx_descriptor *rx_ring;
    uint8_t mac_address[6];
    uint16_t tx_next;
    uint16_t tx_last_submitted;
    uint16_t rx_next;
    uint64_t transmitted_frames;
    uint64_t received_frames;
    uint64_t transmit_timeouts;
    uint64_t receive_errors;
    uint64_t resets;
    uint64_t interrupts_handled;
    bool transmit_pending;
    bool link_up;
    bool initialized;
    uint8_t irq_line;
    bool irq_registered;
};

static struct e1000_state e1000;
static struct kos_spinlock e1000_lock = KOS_SPINLOCK_INITIALIZER;
static struct net_device e1000_net_device;

static bool e1000_device_id_supported(uint16_t device_id) {
    return device_id == E1000_DEVICE_82540EM || device_id == E1000_DEVICE_82545EM
        || device_id == E1000_DEVICE_82544GC || device_id == E1000_DEVICE_82541GI;
}

static const struct pci_device *e1000_find_pci_device(void) {
    for (uint64_t index = 0; index < pci_device_count(); ++index) {
        const struct pci_device *device = pci_device_at(index);
        if (device != 0 && device->vendor_id == E1000_VENDOR_ID
            && e1000_device_id_supported(device->device_id)) {
            return device;
        }
    }
    return 0;
}

static uint32_t e1000_read(uint32_t offset) {
    return e1000.registers[offset / sizeof(uint32_t)];
}

static void e1000_write(uint32_t offset, uint32_t value) {
    e1000.registers[offset / sizeof(uint32_t)] = value;
    (void)e1000_read(E1000_REGISTER_STATUS);
}

static bool e1000_map_mmio(uint64_t physical_base) {
    if (physical_base % KOS_PAGE_SIZE != 0) {
        return false;
    }
    for (uint64_t offset = 0; offset < E1000_MMIO_SIZE; offset += KOS_PAGE_SIZE) {
        if (!vmm_map_page(E1000_MMIO_VIRTUAL_BASE + offset, physical_base + offset,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE)) {
            return false;
        }
    }
    e1000.registers = (volatile uint32_t *)(uintptr_t)E1000_MMIO_VIRTUAL_BASE;
    return true;
}

static bool e1000_allocate_dma(uint64_t size, struct e1000_dma_allocation *allocation) {
    if (allocation == 0 || size == 0 || size > KOS_PAGE_SIZE) {
        return false;
    }
    uint8_t *raw = kmalloc(size + KOS_PAGE_SIZE);
    if (raw == 0) {
        return false;
    }
    uint64_t aligned = ((uint64_t)(uintptr_t)raw + KOS_PAGE_SIZE - 1) & ~(KOS_PAGE_SIZE - 1);
    uint64_t first_physical;
    uint64_t last_physical;
    if (!vmm_query_page(aligned, &first_physical, 0)
        || !vmm_query_page(aligned + size - 1, &last_physical, 0)
        || first_physical + size - 1 != last_physical) {
        (void)kfree(raw);
        return false;
    }
    allocation->raw = raw;
    allocation->address = (uint8_t *)(uintptr_t)aligned;
    allocation->physical = first_physical;
    for (uint64_t index = 0; index < size; ++index) {
        allocation->address[index] = 0;
    }
    return true;
}

static void e1000_release_dma(struct e1000_dma_allocation *allocation) {
    if (allocation != 0 && allocation->raw != 0) {
        (void)kfree(allocation->raw);
        *allocation = (struct e1000_dma_allocation){0};
    }
}

static void e1000_release_resources(void) {
    for (uint64_t index = 0; index < E1000_DESCRIPTOR_COUNT; ++index) {
        e1000_release_dma(&e1000.tx_buffer_memory[index]);
        e1000_release_dma(&e1000.rx_buffer_memory[index]);
    }
    e1000_release_dma(&e1000.tx_ring_memory);
    e1000_release_dma(&e1000.rx_ring_memory);
    e1000.tx_ring = 0;
    e1000.rx_ring = 0;
}

static bool e1000_allocate_rings(void) {
    if (!e1000_allocate_dma(sizeof(struct e1000_tx_descriptor) * E1000_DESCRIPTOR_COUNT,
            &e1000.tx_ring_memory)
        || !e1000_allocate_dma(sizeof(struct e1000_rx_descriptor) * E1000_DESCRIPTOR_COUNT,
            &e1000.rx_ring_memory)) {
        e1000_release_resources();
        return false;
    }
    e1000.tx_ring = (struct e1000_tx_descriptor *)e1000.tx_ring_memory.address;
    e1000.rx_ring = (struct e1000_rx_descriptor *)e1000.rx_ring_memory.address;
    for (uint64_t index = 0; index < E1000_DESCRIPTOR_COUNT; ++index) {
        if (!e1000_allocate_dma(E1000_FRAME_BUFFER_SIZE, &e1000.tx_buffer_memory[index])
            || !e1000_allocate_dma(E1000_FRAME_BUFFER_SIZE, &e1000.rx_buffer_memory[index])) {
            e1000_release_resources();
            return false;
        }
        e1000.tx_ring[index].address = e1000.tx_buffer_memory[index].physical;
        e1000.tx_ring[index].status = E1000_TX_STATUS_DONE;
        e1000.rx_ring[index].address = e1000.rx_buffer_memory[index].physical;
        e1000.rx_ring[index].status = 0;
    }
    return true;
}

static bool e1000_reset(void) {
    e1000_write(E1000_REGISTER_IMC, 0xffffffffu);
    e1000_write(E1000_REGISTER_CTRL, e1000_read(E1000_REGISTER_CTRL) | E1000_CTRL_RESET);
    for (uint64_t index = 0; index < E1000_RESET_SPINS; ++index) {
        if ((e1000_read(E1000_REGISTER_CTRL) & E1000_CTRL_RESET) == 0) {
            return true;
        }
        cpu_pause();
    }
    return false;
}

static void e1000_read_mac_address(void) {
    uint32_t low = e1000_read(E1000_REGISTER_RAL);
    uint32_t high = e1000_read(E1000_REGISTER_RAH);
    e1000.mac_address[0] = (uint8_t)low;
    e1000.mac_address[1] = (uint8_t)(low >> 8);
    e1000.mac_address[2] = (uint8_t)(low >> 16);
    e1000.mac_address[3] = (uint8_t)(low >> 24);
    e1000.mac_address[4] = (uint8_t)high;
    e1000.mac_address[5] = (uint8_t)(high >> 8);
}

static void e1000_configure_rings(void) {
    e1000_write(E1000_REGISTER_RDBAL, (uint32_t)e1000.rx_ring_memory.physical);
    e1000_write(E1000_REGISTER_RDBAH, (uint32_t)(e1000.rx_ring_memory.physical >> 32));
    e1000_write(E1000_REGISTER_RDLEN, sizeof(struct e1000_rx_descriptor) * E1000_DESCRIPTOR_COUNT);
    e1000_write(E1000_REGISTER_RDH, 0);
    e1000_write(E1000_REGISTER_RDT, E1000_DESCRIPTOR_COUNT - 1);
    e1000_write(E1000_REGISTER_RCTL, E1000_RCTL_ENABLE | E1000_RCTL_BROADCAST_ACCEPT
        | E1000_RCTL_STRIP_CRC);

    e1000_write(E1000_REGISTER_TDBAL, (uint32_t)e1000.tx_ring_memory.physical);
    e1000_write(E1000_REGISTER_TDBAH, (uint32_t)(e1000.tx_ring_memory.physical >> 32));
    e1000_write(E1000_REGISTER_TDLEN, sizeof(struct e1000_tx_descriptor) * E1000_DESCRIPTOR_COUNT);
    e1000_write(E1000_REGISTER_TDH, 0);
    e1000_write(E1000_REGISTER_TDT, 0);
    e1000_write(E1000_REGISTER_TIPG, 0x0060200au);
    e1000_write(E1000_REGISTER_TCTL, E1000_TCTL_ENABLE | E1000_TCTL_PAD_SHORT
        | (15u << 4) | (64u << 12));

    e1000_write(E1000_REGISTER_IMS, E1000_ICR_TXDW | E1000_ICR_LSC | E1000_ICR_RXO | E1000_ICR_RXT0);
}

static void e1000_irq_handler(uint8_t irq, void *context) {
    (void)irq;
    (void)context;
    uint32_t icr = e1000_read(E1000_REGISTER_ICR);
    if (icr == 0) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    e1000.interrupts_handled++;
    if (icr & E1000_ICR_LSC) {
        uint32_t status = e1000_read(E1000_REGISTER_STATUS);
        e1000.link_up = (status & E1000_STATUS_LU) != 0;
    }
    if (icr & E1000_ICR_RXO) {
        e1000_net_device.stats.rx_dropped++;
    }
    spinlock_unlock_irqrestore(&e1000_lock, flags);
}

bool e1000_send_frame(const uint8_t *frame, uint64_t size) {
    if (frame == 0 || size < 14 || size > E1000_FRAME_BUFFER_SIZE) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    if (!e1000.initialized) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }

    if ((e1000.tx_ring[e1000.tx_next].status & E1000_TX_STATUS_DONE) == 0) {
        e1000_net_device.stats.tx_dropped++;
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }

    uint16_t descriptor_index = e1000.tx_next;
    for (uint64_t index = 0; index < size; ++index) {
        e1000.tx_buffer_memory[descriptor_index].address[index] = frame[index];
    }
    struct e1000_tx_descriptor *descriptor = &e1000.tx_ring[descriptor_index];
    descriptor->length = (uint16_t)size;
    descriptor->command = E1000_TX_COMMAND_END_OF_PACKET | E1000_TX_COMMAND_INSERT_FCS
        | E1000_TX_COMMAND_REPORT_STATUS;
    descriptor->status = 0;
    e1000.tx_next = (uint16_t)((e1000.tx_next + 1) % E1000_DESCRIPTOR_COUNT);
    e1000.tx_last_submitted = descriptor_index;
    e1000.transmit_pending = true;
    e1000_write(E1000_REGISTER_TDT, e1000.tx_next);
    ++e1000.transmitted_frames;
    e1000_net_device.stats.tx_packets++;
    e1000_net_device.stats.tx_bytes += size;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return true;
}

bool e1000_wait_for_transmit(uint64_t timeout_ticks) {
    uint64_t started_at = timer_ticks();
    for (;;) {
        uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
        if (!e1000.initialized) {
            spinlock_unlock_irqrestore(&e1000_lock, flags);
            return false;
        }
        if (!e1000.transmit_pending
            || (e1000.tx_ring[e1000.tx_last_submitted].status & E1000_TX_STATUS_DONE) != 0) {
            e1000.transmit_pending = false;
            spinlock_unlock_irqrestore(&e1000_lock, flags);
            return true;
        }
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        if (timer_ticks() - started_at >= timeout_ticks) {
            flags = spinlock_lock_irqsave(&e1000_lock);
            ++e1000.transmit_timeouts;
            e1000_net_device.stats.tx_timeouts++;
            spinlock_unlock_irqrestore(&e1000_lock, flags);
            return false;
        }
        if (task_is_multitasking_active()) {
            task_sleep(1);
        } else {
            cpu_wait_for_interrupt();
        }
    }
}

bool e1000_receive_frame(uint8_t *frame, uint64_t capacity, uint64_t *size) {
    if (frame == 0 || size == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    if (!e1000.initialized || (e1000.rx_ring[e1000.rx_next].status & E1000_RX_STATUS_DONE) == 0) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }
    struct e1000_rx_descriptor *descriptor = &e1000.rx_ring[e1000.rx_next];

    if (descriptor->errors & (E1000_RX_ERR_CE | E1000_RX_ERR_SE | E1000_RX_ERR_SEQ | E1000_RX_ERR_CXE | E1000_RX_ERR_RXE)) {
        e1000.receive_errors++;
        e1000_net_device.stats.rx_errors++;
        descriptor->status = 0;
        e1000_write(E1000_REGISTER_RDT, e1000.rx_next);
        e1000.rx_next = (uint16_t)((e1000.rx_next + 1) % E1000_DESCRIPTOR_COUNT);
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }

    if (descriptor->length > capacity || descriptor->length > E1000_FRAME_BUFFER_SIZE) {
        descriptor->status = 0;
        e1000_write(E1000_REGISTER_RDT, e1000.rx_next);
        e1000.rx_next = (uint16_t)((e1000.rx_next + 1) % E1000_DESCRIPTOR_COUNT);
        e1000_net_device.stats.rx_dropped++;
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }
    *size = descriptor->length;
    for (uint64_t index = 0; index < *size; ++index) {
        frame[index] = e1000.rx_buffer_memory[e1000.rx_next].address[index];
    }
    descriptor->status = 0;
    e1000_write(E1000_REGISTER_RDT, e1000.rx_next);
    e1000.rx_next = (uint16_t)((e1000.rx_next + 1) % E1000_DESCRIPTOR_COUNT);
    ++e1000.received_frames;
    e1000_net_device.stats.rx_packets++;
    e1000_net_device.stats.rx_bytes += *size;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return true;
}

void e1000_service(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    if (!e1000.initialized) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return;
    }
    uint32_t status = e1000_read(E1000_REGISTER_STATUS);
    e1000.link_up = (status & E1000_STATUS_LU) != 0;
    if (e1000.link_up) {
        e1000_net_device.flags |= NET_DEV_FLAG_LINK_UP;
    } else {
        e1000_net_device.flags &= ~NET_DEV_FLAG_LINK_UP;
    }
    spinlock_unlock_irqrestore(&e1000_lock, flags);
}

static bool dev_ops_open(struct net_device *dev) {
    (void)dev;
    e1000_configure_rings();
    return true;
}

static void dev_ops_stop(struct net_device *dev) {
    (void)dev;
    e1000_write(E1000_REGISTER_RCTL, 0);
    e1000_write(E1000_REGISTER_TCTL, 0);
}

static bool dev_ops_transmit(struct net_device *dev, const uint8_t *frame, uint64_t size) {
    (void)dev;
    return e1000_send_frame(frame, size);
}

static bool dev_ops_receive(struct net_device *dev, uint8_t *frame, uint64_t capacity, uint64_t *size) {
    (void)dev;
    return e1000_receive_frame(frame, capacity, size);
}

static bool dev_ops_wait_transmit(struct net_device *dev, uint64_t timeout_ticks) {
    (void)dev;
    return e1000_wait_for_transmit(timeout_ticks);
}

static void dev_ops_poll(struct net_device *dev) {
    (void)dev;
    e1000_service();
}

static bool dev_ops_get_stats(struct net_device *dev, struct net_device_stats *stats) {
    if (!stats || !dev) return false;
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    *stats = dev->stats;
    stats->interrupts = e1000.interrupts_handled;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return true;
}

static bool dev_ops_reset(struct net_device *dev) {
    (void)dev;
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    bool ok = e1000_reset();
    if (ok) {
        e1000_configure_rings();
        e1000.tx_next = 0;
        e1000.rx_next = 0;
        e1000.resets++;
    }
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return ok;
}

static const struct net_device_ops e1000_ops = {
    .open = dev_ops_open,
    .stop = dev_ops_stop,
    .transmit = dev_ops_transmit,
    .receive = dev_ops_receive,
    .wait_transmit = dev_ops_wait_transmit,
    .poll = dev_ops_poll,
    .get_stats = dev_ops_get_stats,
    .reset = dev_ops_reset,
};

bool e1000_initialize(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    if (e1000.initialized) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return true;
    }
    const struct pci_device *device = e1000_find_pci_device();
    if (device == 0) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return true;
    }
    if ((device->bars[0] & 1u) != 0 || (device->bars[0] & E1000_BAR_MEMORY_MASK) == 0
        || !pci_enable_memory_bus_mastering(device)) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }
    if (!e1000_map_mmio(device->bars[0] & E1000_BAR_MEMORY_MASK)
        || !e1000_reset() || !e1000_allocate_rings()) {
        e1000_release_resources();
        e1000.registers = 0;
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }
    e1000_read_mac_address();
    e1000_configure_rings();
    e1000.tx_next = 0;
    e1000.rx_next = 0;
    e1000.transmitted_frames = 0;
    e1000.received_frames = 0;
    e1000.transmit_timeouts = 0;
    e1000.receive_errors = 0;
    e1000.resets = 0;
    e1000.interrupts_handled = 0;
    e1000.transmit_pending = false;
    e1000.link_up = (e1000_read(E1000_REGISTER_STATUS) & E1000_STATUS_LU) != 0;
    e1000.initialized = true;

    e1000.irq_line = device->interrupt_line;
    if (e1000.irq_line < 16) {
        if (irq_register_handler(e1000.irq_line, e1000_irq_handler)) {
            pic_unmask_irq(e1000.irq_line);
            e1000.irq_registered = true;
        }
    }

    e1000_net_device = (struct net_device){
        .mtu = NET_DEFAULT_MTU,
        .state = NET_DEV_UP,
        .flags = NET_DEV_FLAG_BROADCAST | (e1000.link_up ? NET_DEV_FLAG_LINK_UP : 0),
        .ops = &e1000_ops,
        .priv = &e1000,
    };
    for (int i = 0; i < 6; ++i) {
        e1000_net_device.mac_address[i] = e1000.mac_address[i];
    }
    char name_buf[NET_DEVICE_NAME_MAX] = "eth0";
    for (int i = 0; name_buf[i] != '\0'; ++i) {
        e1000_net_device.name[i] = name_buf[i];
    }

    spinlock_unlock_irqrestore(&e1000_lock, flags);

    net_device_register(&e1000_net_device);

    return true;
}

bool e1000_is_initialized(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    bool result = e1000.initialized;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return result;
}

bool e1000_link_is_up(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    bool result = e1000.link_up;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return result;
}

bool e1000_get_info(struct e1000_info *info) {
    if (!info) return false;
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    info->initialized = e1000.initialized;
    info->link_up = e1000.link_up;
    info->tx_pending = e1000.transmit_pending;
    info->transmitted_frames = e1000.transmitted_frames;
    info->received_frames = e1000.received_frames;
    info->transmit_timeouts = e1000.transmit_timeouts;
    info->receive_errors = e1000.receive_errors;
    info->resets = e1000.resets;
    info->recovery_failures = 0;
    info->link_changes = 0;
    info->last_activity_tick = timer_ticks();
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return true;
}

bool e1000_get_mac_address(uint8_t address[6]) {
    if (address == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    if (!e1000.initialized) {
        spinlock_unlock_irqrestore(&e1000_lock, flags);
        return false;
    }
    for (uint64_t index = 0; index < 6; ++index) {
        address[index] = e1000.mac_address[index];
    }
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return true;
}

uint64_t e1000_transmitted_frame_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    uint64_t result = e1000.transmitted_frames;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return result;
}

uint64_t e1000_received_frame_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    uint64_t result = e1000.received_frames;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return result;
}

uint64_t e1000_transmit_timeout_count(void) {
    uint64_t flags = spinlock_lock_irqsave(&e1000_lock);
    uint64_t result = e1000.transmit_timeouts;
    spinlock_unlock_irqrestore(&e1000_lock, flags);
    return result;
}
