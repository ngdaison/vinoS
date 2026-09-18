#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/heap.h>
#include <kos/io.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/partition.h>
#include <kos/pci.h>
#include <kos/spinlock.h>
#include <kos/timer.h>
#include <kos/virtio_blk.h>
#include <kos/vmm.h>

/* VirtIO PCI Vendor / Device IDs */
#define VIRTIO_PCI_VENDOR_ID         0x1AF4
#define VIRTIO_PCI_DEVICE_BLK_TRANS  0x1001
#define VIRTIO_PCI_DEVICE_BLK_MODERN 0x1042

/* VirtIO Status Bits */
#define VIRTIO_STATUS_ACK            1
#define VIRTIO_STATUS_DRIVER         2
#define VIRTIO_STATUS_DRIVER_OK      4
#define VIRTIO_STATUS_FAILED         128

/* VirtIO Legacy I/O Registers (offsets from I/O base) */
#define VIRTIO_REG_DEVICE_FEATURES   0x00
#define VIRTIO_REG_GUEST_FEATURES    0x04
#define VIRTIO_REG_QUEUE_ADDRESS     0x08
#define VIRTIO_REG_QUEUE_SIZE        0x0C
#define VIRTIO_REG_QUEUE_SELECT      0x0E
#define VIRTIO_REG_QUEUE_NOTIFY      0x10
#define VIRTIO_REG_DEVICE_STATUS     0x12
#define VIRTIO_REG_ISR_STATUS        0x13
#define VIRTIO_REG_CONFIG            0x14

/* VirtIO Block Request Types */
#define VIRTIO_BLK_T_IN              0
#define VIRTIO_BLK_T_OUT             1
#define VIRTIO_BLK_T_FLUSH           4

/* VirtIO Block Status */
#define VIRTIO_BLK_S_OK              0
#define VIRTIO_BLK_S_IOERR           1
#define VIRTIO_BLK_S_UNSUPP          2

/* Virtqueue Descriptor Flags */
#define VRING_DESC_F_NEXT            1
#define VRING_DESC_F_WRITE           2

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} KOS_PACKED;

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[128];
} KOS_PACKED;

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} KOS_PACKED;

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[128];
} KOS_PACKED;

struct virtio_blk_req_hdr {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} KOS_PACKED;

struct virtio_blk_device {
    uint16_t io_base;
    uint16_t queue_size;
    uint16_t last_used_idx;

    /* 2 contiguous pages (8192 bytes) DMA queue structures */
    void *queue_virt;
    uint64_t queue_phys;

    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;

    /* Request header and status DMA memory (1 page) */
    void *req_virt;
    struct virtio_blk_req_hdr *req_hdr;
    uint64_t req_hdr_phys;
    volatile uint8_t *status_byte;
    uint64_t status_byte_phys;

    /* Bounce buffer for aligned DMA transfers (16 pages = 64 KiB = 128 sectors) */
    void *bounce_virt;
    uint8_t *bounce_buffer;
    uint64_t bounce_phys;
    uint32_t bounce_capacity_blocks;

    struct block_device *bdev;
    kos_spinlock_t lock;
};

#define VIRTIO_BLK_MAX_DEVICES 4
static struct virtio_blk_device virtio_devices[VIRTIO_BLK_MAX_DEVICES];
static uint32_t virtio_device_count = 0;

static bool virtio_blk_submit_io(struct virtio_blk_device *vdev, uint32_t type, uint64_t lba, uint32_t count, void *buffer) {
    uint64_t flags = spinlock_lock_irqsave(&vdev->lock);
    uint32_t byte_count = count * BLOCK_DEFAULT_SECTOR_SIZE;

    /* Set up request header */
    vdev->req_hdr->type = type;
    vdev->req_hdr->reserved = 0;
    vdev->req_hdr->sector = lba;
    *vdev->status_byte = 0xFF;

    /* If write, copy to DMA bounce buffer */
    if (type == VIRTIO_BLK_T_OUT) {
        kmemcpy(vdev->bounce_buffer, buffer, byte_count);
    }

    /* Setup Descriptor 0: Request Header */
    vdev->desc[0].addr = vdev->req_hdr_phys;
    vdev->desc[0].len = sizeof(struct virtio_blk_req_hdr);
    vdev->desc[0].flags = VRING_DESC_F_NEXT;
    vdev->desc[0].next = 1;

    /* Setup Descriptor 1: Data Buffer */
    vdev->desc[1].addr = vdev->bounce_phys;
    vdev->desc[1].len = byte_count;
    vdev->desc[1].flags = VRING_DESC_F_NEXT | (type == VIRTIO_BLK_T_IN ? VRING_DESC_F_WRITE : 0);
    vdev->desc[1].next = 2;

    /* Setup Descriptor 2: Status Byte */
    vdev->desc[2].addr = vdev->status_byte_phys;
    vdev->desc[2].len = 1;
    vdev->desc[2].flags = VRING_DESC_F_WRITE;
    vdev->desc[2].next = 0;

    /* Put descriptor head (0) into available ring */
    uint16_t avail_idx = vdev->avail->idx;
    vdev->avail->ring[avail_idx % vdev->queue_size] = 0;
    smp_wmb();
    vdev->avail->idx = avail_idx + 1;
    smp_wmb();

    /* Notify device of new request in queue 0 */
    io_out16(vdev->io_base + VIRTIO_REG_QUEUE_NOTIFY, 0);

    /* Poll used ring with timeout */
    uint64_t timeout_tick = timer_get_ticks() + timer_ms_to_ticks(3000);
    bool completed = false;

    while (timer_get_ticks() < timeout_tick) {
        smp_rmb();
        if (vdev->used->idx != vdev->last_used_idx) {
            vdev->last_used_idx = vdev->used->idx;
            completed = true;
            break;
        }
        cpu_relax();
    }

    if (!completed) {
        log_errorf("[virtio-blk] Timeout waiting for I/O completion on %s (LBA %llu)",
                   vdev->bdev ? vdev->bdev->name : "virtio-blk", (unsigned long long)lba);
        spinlock_unlock_irqrestore(&vdev->lock, flags);
        return false;
    }

    uint8_t status = *vdev->status_byte;
    if (status != VIRTIO_BLK_S_OK) {
        log_errorf("[virtio-blk] Device reported I/O error status %u on LBA %llu",
                   (unsigned int)status, (unsigned long long)lba);
        spinlock_unlock_irqrestore(&vdev->lock, flags);
        return false;
    }

    /* If read, copy from bounce buffer to caller buffer */
    if (type == VIRTIO_BLK_T_IN) {
        kmemcpy(buffer, vdev->bounce_buffer, byte_count);
    }

    spinlock_unlock_irqrestore(&vdev->lock, flags);
    return true;
}

static bool virtio_blk_read_blocks(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL || count == 0) {
        return false;
    }
    struct virtio_blk_device *vdev = (struct virtio_blk_device *)dev->private_data;

    /* Break transfers larger than bounce buffer into chunks */
    uint8_t *dst = (uint8_t *)buffer;
    while (count > 0) {
        uint32_t chunk = count > vdev->bounce_capacity_blocks ? vdev->bounce_capacity_blocks : count;
        if (!virtio_blk_submit_io(vdev, VIRTIO_BLK_T_IN, lba, chunk, dst)) {
            return false;
        }
        lba += chunk;
        count -= chunk;
        dst += chunk * BLOCK_DEFAULT_SECTOR_SIZE;
    }
    return true;
}

static bool virtio_blk_write_blocks(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL || count == 0) {
        return false;
    }
    struct virtio_blk_device *vdev = (struct virtio_blk_device *)dev->private_data;

    const uint8_t *src = (const uint8_t *)buffer;
    while (count > 0) {
        uint32_t chunk = count > vdev->bounce_capacity_blocks ? vdev->bounce_capacity_blocks : count;
        if (!virtio_blk_submit_io(vdev, VIRTIO_BLK_T_OUT, lba, chunk, (void *)src)) {
            return false;
        }
        lba += chunk;
        count -= chunk;
        src += chunk * BLOCK_DEFAULT_SECTOR_SIZE;
    }
    return true;
}

static bool virtio_blk_flush(struct block_device *dev) {
    if (dev == NULL || dev->private_data == NULL) return false;
    struct virtio_blk_device *vdev = (struct virtio_blk_device *)dev->private_data;
    /* Flush command */
    return virtio_blk_submit_io(vdev, VIRTIO_BLK_T_FLUSH, 0, 0, vdev->bounce_buffer);
}

static const struct block_device_ops virtio_blk_ops = {
    .read_blocks = virtio_blk_read_blocks,
    .write_blocks = virtio_blk_write_blocks,
    .flush = virtio_blk_flush,
    .destroy = NULL,
};

static bool virtio_blk_probe_pci(const struct pci_device *pci) {
    if (virtio_device_count >= VIRTIO_BLK_MAX_DEVICES) {
        return false;
    }

    if (!pci_enable_memory_bus_mastering(pci)) {
        log_error("[virtio-blk] Failed to enable PCI bus mastering");
        return false;
    }

    /* In legacy VirtIO, BAR0 is I/O space */
    uint16_t io_base = (uint16_t)(pci->bars[0] & ~3U);
    if (io_base == 0) {
        log_error("[virtio-blk] Invalid I/O base in BAR0");
        return false;
    }

    struct virtio_blk_device *vdev = &virtio_devices[virtio_device_count];
    vdev->io_base = io_base;
    spinlock_init(&vdev->lock);

    /* 1. Reset device */
    io_out8(io_base + VIRTIO_REG_DEVICE_STATUS, 0);

    /* 2. Set ACKNOWLEDGE bit */
    io_out8(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);

    /* 3. Set DRIVER bit */
    io_out8(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    /* 4. Select queue 0 and read size */
    io_out16(io_base + VIRTIO_REG_QUEUE_SELECT, 0);
    uint16_t qsize = io_in16(io_base + VIRTIO_REG_QUEUE_SIZE);
    if (qsize == 0) {
        log_error("[virtio-blk] Queue size is 0!");
        io_out8(io_base + VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return false;
    }
    vdev->queue_size = qsize > 128 ? 128 : qsize;
    vdev->last_used_idx = 0;

    /* 5. Allocate 2 DMA pages for Virtqueue (8192 bytes) */
    if (!block_alloc_dma_pages(2, &vdev->queue_virt, &vdev->queue_phys)) {
        log_error("[virtio-blk] Failed to allocate virtqueue DMA pages");
        return false;
    }

    vdev->desc = (struct vring_desc *)vdev->queue_virt;
    vdev->avail = (struct vring_avail *)((uint8_t *)vdev->queue_virt + (16 * vdev->queue_size));
    vdev->used = (struct vring_used *)((uint8_t *)vdev->queue_virt + 4096);

    /* Program queue address into PFN */
    io_out32(io_base + VIRTIO_REG_QUEUE_ADDRESS, (uint32_t)(vdev->queue_phys >> 12));

    /* 6. Allocate DMA memory for request header and status (1 page) */
    if (!block_alloc_dma_pages(1, &vdev->req_virt, &vdev->req_hdr_phys)) {
        log_error("[virtio-blk] Failed to allocate request DMA memory");
        block_free_dma_pages(vdev->queue_virt, vdev->queue_phys, 2);
        return false;
    }
    vdev->req_hdr = (struct virtio_blk_req_hdr *)vdev->req_virt;
    vdev->status_byte = (volatile uint8_t *)((uint8_t *)vdev->req_hdr + 256);
    vdev->status_byte_phys = vdev->req_hdr_phys + 256;

    /* 7. Allocate 64 KiB bounce buffer (16 pages = 128 sectors) */
    vdev->bounce_capacity_blocks = 128;
    if (!block_alloc_dma_pages(16, &vdev->bounce_virt, &vdev->bounce_phys)) {
        log_error("[virtio-blk] Failed to allocate bounce buffer DMA memory");
        block_free_dma_pages(vdev->req_virt, vdev->req_hdr_phys, 1);
        block_free_dma_pages(vdev->queue_virt, vdev->queue_phys, 2);
        return false;
    }
    vdev->bounce_buffer = (uint8_t *)vdev->bounce_virt;

    /* 8. Set DRIVER_OK status */
    io_out8(io_base + VIRTIO_REG_DEVICE_STATUS,
            VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK);

    /* 9. Read disk capacity in 512-byte sectors */
    uint32_t cap_low = io_in32(io_base + VIRTIO_REG_CONFIG);
    uint32_t cap_high = io_in32(io_base + VIRTIO_REG_CONFIG + 4);
    uint64_t capacity_sectors = ((uint64_t)cap_high << 32) | cap_low;

    char dev_name[32];
    dev_name[0] = 'v'; dev_name[1] = 'i'; dev_name[2] = 'r';
    dev_name[3] = 't'; dev_name[4] = 'i'; dev_name[5] = 'o';
    dev_name[6] = (char)('0' + virtio_device_count);
    dev_name[7] = '\0';

    vdev->bdev = block_device_register(
        dev_name,
        BLOCK_TYPE_VIRTIO,
        BLOCK_DEFAULT_SECTOR_SIZE,
        capacity_sectors,
        &virtio_blk_ops,
        vdev
    );

    if (vdev->bdev == NULL) {
        log_error("[virtio-blk] Failed to register block device");
        return false;
    }

    log_infof("[virtio-blk] VirtIO block device %s initialized (%llu sectors, %llu MiB)",
              vdev->bdev->name, (unsigned long long)capacity_sectors,
              (unsigned long long)((capacity_sectors * 512) / (1024 * 1024)));

    /* Scan for MBR / GPT partitions */
    partition_scan(vdev->bdev);

    virtio_device_count++;
    return true;
}

bool virtio_blk_initialize(void) {
    bool found_any = false;
    for (uint64_t i = 0; i < pci_device_count(); i++) {
        const struct pci_device *pci = pci_device_at(i);
        if (pci != NULL && pci->vendor_id == VIRTIO_PCI_VENDOR_ID &&
            (pci->device_id == VIRTIO_PCI_DEVICE_BLK_TRANS || pci->device_id == VIRTIO_PCI_DEVICE_BLK_MODERN)) {
            if (virtio_blk_probe_pci(pci)) {
                found_any = true;
            }
        }
    }
    return found_any;
}

uint32_t virtio_blk_device_count(void) {
    return virtio_device_count;
}
