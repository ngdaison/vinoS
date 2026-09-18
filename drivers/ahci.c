#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/ahci.h>
#include <kos/block.h>
#include <kos/cpu.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/partition.h>
#include <kos/pci.h>
#include <kos/spinlock.h>
#include <kos/timer.h>
#include <kos/vmm.h>

struct ahci_port_device {
    struct ahci_port *port;
    uint32_t port_number;

    /* DMA structures */
    void *clb_raw;
    struct ahci_cmd_header *cmd_headers;
    uint64_t cmd_headers_phys;

    void *fb_raw;
    uint8_t *received_fis;
    uint64_t received_fis_phys;

    void *cmd_table_raw;
    struct ahci_cmd_table *cmd_tables[32];
    uint64_t cmd_tables_phys[32];

    /* Bounce buffer for DMA transfers (64 KiB = 128 sectors) */
    void *bounce_raw;
    uint8_t *bounce_buffer;
    uint64_t bounce_phys;
    uint32_t bounce_capacity_blocks;

    struct block_device *bdev;
    kos_spinlock_t lock;
};

#define AHCI_MAX_DEV_INSTANCES 8
static struct ahci_port_device ahci_devices[AHCI_MAX_DEV_INSTANCES];
static uint32_t ahci_device_num = 0;

static bool ahci_alloc_dma(uint64_t size, uint64_t alignment, void **raw_out, uint8_t **virt_out, uint64_t *phys_out) {
    (void)alignment;
    if (raw_out == NULL || virt_out == NULL || phys_out == NULL || size == 0) {
        return false;
    }
    uint32_t pages = (uint32_t)((size + 4095) / 4096);
    void *virt = NULL;
    uint64_t phys = 0;
    if (!block_alloc_dma_pages(pages, &virt, &phys)) {
        return false;
    }
    *raw_out = virt;
    *virt_out = (uint8_t *)virt;
    *phys_out = phys;
    return true;
}

static bool ahci_port_stop(struct ahci_port *port) {
    port->cmd &= ~HBA_PORT_CMD_ST;
    port->cmd &= ~HBA_PORT_CMD_FRE;

    uint64_t timeout = timer_get_ticks() + timer_ms_to_ticks(500);
    while (timer_get_ticks() < timeout) {
        if ((port->cmd & (HBA_PORT_CMD_FR | HBA_PORT_CMD_CR)) == 0) {
            return true;
        }
        cpu_relax();
    }
    log_warn("[ahci] Port stop timed out waiting for CR/FR to clear");
    return false;
}

static void ahci_port_start(struct ahci_port *port) {
    while (port->cmd & HBA_PORT_CMD_CR) {
        cpu_relax();
    }
    port->cmd |= HBA_PORT_CMD_FRE;
    port->cmd |= HBA_PORT_CMD_ST;
}

static int32_t ahci_find_cmdslot(struct ahci_port *port) {
    uint32_t slots = (port->sact | port->ci);
    for (int32_t i = 0; i < 32; i++) {
        if ((slots & (1U << i)) == 0) {
            return i;
        }
    }
    return -1;
}

static bool ahci_port_send_cmd(struct ahci_port_device *adev, uint8_t ata_cmd, uint64_t lba, uint32_t sector_count, bool is_write) {
    struct ahci_port *port = adev->port;

    port->is = (uint32_t)-1; /* Clear pending interrupt bits */
    int32_t slot = ahci_find_cmdslot(port);
    if (slot < 0) {
        log_error("[ahci] No free command slots available");
        return false;
    }

    struct ahci_cmd_header *cmdheader = &adev->cmd_headers[slot];
    /* Command FIS length is 5 DWORDS (20 bytes) = CFL 5 */
    cmdheader->cfl_a_w = 5 | (is_write ? (1 << 6) : 0);
    cmdheader->prdtl = 1;
    cmdheader->prdbc = 0;
    cmdheader->ctba = (uint32_t)(adev->cmd_tables_phys[slot] & 0xFFFFFFFF);
    cmdheader->ctbau = (uint32_t)(adev->cmd_tables_phys[slot] >> 32);

    struct ahci_cmd_table *cmdtbl = adev->cmd_tables[slot];
    kmemset(cmdtbl, 0, sizeof(struct ahci_cmd_table));

    uint32_t byte_count = sector_count * BLOCK_DEFAULT_SECTOR_SIZE;
    if (ata_cmd == ATA_CMD_IDENTIFY) {
        byte_count = 512;
    }

    if (byte_count > 0) {
        cmdtbl->prdt_entry[0].dba = (uint32_t)(adev->bounce_phys & 0xFFFFFFFF);
        cmdtbl->prdt_entry[0].dbau = (uint32_t)(adev->bounce_phys >> 32);
        cmdtbl->prdt_entry[0].dbc_i = (byte_count - 1) | (1U << 31); /* Interrupt bit */
    } else {
        cmdheader->prdtl = 0;
    }

    /* Build Command FIS */
    struct fis_reg_h2d *cmdfis = (struct fis_reg_h2d *)(&cmdtbl->cfis[0]);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->pmport_c = (1 << 7); /* Command bit */
    cmdfis->command = ata_cmd;
    cmdfis->device = (1 << 6);   /* LBA mode */

    if (ata_cmd != ATA_CMD_IDENTIFY && ata_cmd != ATA_CMD_FLUSH_CACHE_EX) {
        cmdfis->lba0 = (uint8_t)(lba & 0xFF);
        cmdfis->lba1 = (uint8_t)((lba >> 8) & 0xFF);
        cmdfis->lba2 = (uint8_t)((lba >> 16) & 0xFF);
        cmdfis->lba3 = (uint8_t)((lba >> 24) & 0xFF);
        cmdfis->lba4 = (uint8_t)((lba >> 32) & 0xFF);
        cmdfis->lba5 = (uint8_t)((lba >> 40) & 0xFF);

        cmdfis->countl = (uint8_t)(sector_count & 0xFF);
        cmdfis->counth = (uint8_t)((sector_count >> 8) & 0xFF);
    }

    /* Wait until port is not busy */
    uint64_t spin_wait = 0;
    while ((port->tfd & (0x80 | 0x08)) && spin_wait < 1000000) {
        spin_wait++;
        cpu_relax();
    }
    if (port->tfd & (0x80 | 0x08)) {
        log_error("[ahci] Port is hung busy before issuing command");
        return false;
    }

    /* Issue command */
    port->ci = (1U << slot);

    /* Poll for completion with 3s timeout */
    uint64_t timeout = timer_get_ticks() + timer_ms_to_ticks(3000);
    while (timer_get_ticks() < timeout) {
        if ((port->ci & (1U << slot)) == 0) {
            break;
        }
        if (port->is & HBA_PORT_IS_TFES) {
            log_errorf("[ahci] Task file error on command 0x%02X LBA %llu",
                       (unsigned int)ata_cmd, (unsigned long long)lba);
            return false;
        }
        cpu_relax();
    }

    if (port->ci & (1U << slot)) {
        log_errorf("[ahci] Command timeout on 0x%02X LBA %llu",
                   (unsigned int)ata_cmd, (unsigned long long)lba);
        return false;
    }

    if (port->is & HBA_PORT_IS_TFES) {
        log_error("[ahci] Task file error during command execution");
        return false;
    }

    return true;
}

static bool ahci_read_blocks(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL || count == 0) {
        return false;
    }
    struct ahci_port_device *adev = (struct ahci_port_device *)dev->private_data;

    uint8_t *dst = (uint8_t *)buffer;
    uint64_t flags = spinlock_lock_irqsave(&adev->lock);

    while (count > 0) {
        uint32_t chunk = count > adev->bounce_capacity_blocks ? adev->bounce_capacity_blocks : count;
        if (!ahci_port_send_cmd(adev, ATA_CMD_READ_DMA_EX, lba, chunk, false)) {
            spinlock_unlock_irqrestore(&adev->lock, flags);
            return false;
        }
        kmemcpy(dst, adev->bounce_buffer, chunk * BLOCK_DEFAULT_SECTOR_SIZE);
        lba += chunk;
        count -= chunk;
        dst += chunk * BLOCK_DEFAULT_SECTOR_SIZE;
    }

    spinlock_unlock_irqrestore(&adev->lock, flags);
    return true;
}

static bool ahci_write_blocks(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer) {
    if (dev == NULL || dev->private_data == NULL || buffer == NULL || count == 0) {
        return false;
    }
    struct ahci_port_device *adev = (struct ahci_port_device *)dev->private_data;

    const uint8_t *src = (const uint8_t *)buffer;
    uint64_t flags = spinlock_lock_irqsave(&adev->lock);

    while (count > 0) {
        uint32_t chunk = count > adev->bounce_capacity_blocks ? adev->bounce_capacity_blocks : count;
        kmemcpy(adev->bounce_buffer, src, chunk * BLOCK_DEFAULT_SECTOR_SIZE);
        if (!ahci_port_send_cmd(adev, ATA_CMD_WRITE_DMA_EX, lba, chunk, true)) {
            spinlock_unlock_irqrestore(&adev->lock, flags);
            return false;
        }
        lba += chunk;
        count -= chunk;
        src += chunk * BLOCK_DEFAULT_SECTOR_SIZE;
    }

    spinlock_unlock_irqrestore(&adev->lock, flags);
    return true;
}

static bool ahci_flush(struct block_device *dev) {
    if (dev == NULL || dev->private_data == NULL) return false;
    struct ahci_port_device *adev = (struct ahci_port_device *)dev->private_data;

    uint64_t flags = spinlock_lock_irqsave(&adev->lock);
    bool ok = ahci_port_send_cmd(adev, ATA_CMD_FLUSH_CACHE_EX, 0, 0, false);
    spinlock_unlock_irqrestore(&adev->lock, flags);
    return ok;
}

static const struct block_device_ops ahci_ops = {
    .read_blocks = ahci_read_blocks,
    .write_blocks = ahci_write_blocks,
    .flush = ahci_flush,
    .destroy = NULL,
};

static bool ahci_probe_port(struct ahci_hba_mem *abar, uint32_t port_num) {
    struct ahci_port *port = &abar->ports[port_num];

    uint32_t ssts = port->ssts;
    uint8_t det = (uint8_t)(ssts & 0x0F);
    uint8_t ipm = (uint8_t)((ssts >> 8) & 0x0F);

    if (det != 0x03 || ipm != 0x01) {
        return false; /* No active device or power not active */
    }

    if (port->sig != SATA_SIG_ATA) {
        log_infof("[ahci] Port %u device present with non-ATA signature 0x%08X (skipped)",
                  (unsigned int)port_num, (unsigned int)port->sig);
        return false;
    }

    if (ahci_device_num >= AHCI_MAX_DEV_INSTANCES) {
        return false;
    }

    struct ahci_port_device *adev = &ahci_devices[ahci_device_num];
    adev->port = port;
    adev->port_number = port_num;
    spinlock_init(&adev->lock);

    /* 1. Stop port DMA engine */
    ahci_port_stop(port);

    /* 2. Allocate Command List (1024 bytes aligned to 1024) */
    if (!ahci_alloc_dma(sizeof(struct ahci_cmd_header) * 32, 1024,
                        &adev->clb_raw, (uint8_t **)&adev->cmd_headers, &adev->cmd_headers_phys)) {
        log_error("[ahci] Failed to allocate Command List DMA");
        return false;
    }
    port->clb = (uint32_t)(adev->cmd_headers_phys & 0xFFFFFFFF);
    port->clbu = (uint32_t)(adev->cmd_headers_phys >> 32);

    /* 3. Allocate Received FIS (256 bytes aligned to 256) */
    if (!ahci_alloc_dma(256, 256, &adev->fb_raw, &adev->received_fis, &adev->received_fis_phys)) {
        log_error("[ahci] Failed to allocate Received FIS DMA");
        return false;
    }
    port->fb = (uint32_t)(adev->received_fis_phys & 0xFFFFFFFF);
    port->fbu = (uint32_t)(adev->received_fis_phys >> 32);

    /* 4. Allocate 32 Command Tables (each 128-byte aligned) */
    for (int32_t i = 0; i < 32; i++) {
        if (!ahci_alloc_dma(sizeof(struct ahci_cmd_table), 128,
                            &adev->cmd_table_raw, (uint8_t **)&adev->cmd_tables[i], &adev->cmd_tables_phys[i])) {
            log_error("[ahci] Failed to allocate Command Table DMA");
            return false;
        }
        adev->cmd_headers[i].ctba = (uint32_t)(adev->cmd_tables_phys[i] & 0xFFFFFFFF);
        adev->cmd_headers[i].ctbau = (uint32_t)(adev->cmd_tables_phys[i] >> 32);
    }

    /* 5. Allocate bounce buffer (64 KiB) */
    adev->bounce_capacity_blocks = 128;
    if (!ahci_alloc_dma(adev->bounce_capacity_blocks * BLOCK_DEFAULT_SECTOR_SIZE, 4096,
                        &adev->bounce_raw, &adev->bounce_buffer, &adev->bounce_phys)) {
        log_error("[ahci] Failed to allocate bounce buffer DMA");
        return false;
    }

    /* 6. Clear errors & start port */
    port->serr = (uint32_t)-1;
    port->is = (uint32_t)-1;
    ahci_port_start(port);

    /* 7. Send IDENTIFY DEVICE */
    if (!ahci_port_send_cmd(adev, ATA_CMD_IDENTIFY, 0, 1, false)) {
        log_errorf("[ahci] Port %u IDENTIFY failed", (unsigned int)port_num);
        return false;
    }

    /* Extract capacity from identify response */
    uint16_t *ident = (uint16_t *)adev->bounce_buffer;
    uint64_t sectors = 0;

    /* Check LBA48 support (word 83 bit 10) */
    if (ident[83] & (1 << 10)) {
        sectors = ((uint64_t)ident[103] << 48) | ((uint64_t)ident[102] << 32) |
                  ((uint64_t)ident[101] << 16) | ident[100];
    } else {
        sectors = ((uint32_t)ident[61] << 16) | ident[60];
    }

    if (sectors == 0) {
        log_errorf("[ahci] Port %u reported 0 sectors", (unsigned int)port_num);
        return false;
    }

    char name[32];
    name[0] = 'a'; name[1] = 'h'; name[2] = 'c'; name[3] = 'i';
    name[4] = (char)('0' + ahci_device_num);
    name[5] = '\0';

    adev->bdev = block_device_register(
        name,
        BLOCK_TYPE_AHCI,
        BLOCK_DEFAULT_SECTOR_SIZE,
        sectors,
        &ahci_ops,
        adev
    );

    if (adev->bdev == NULL) {
        log_error("[ahci] Failed to register block device");
        return false;
    }

    log_infof("[ahci] AHCI SATA drive %s (Port %u) registered (%llu sectors, %llu MiB)",
              adev->bdev->name, (unsigned int)port_num, (unsigned long long)sectors,
              (unsigned long long)((sectors * 512) / (1024 * 1024)));

    /* Scan partitions */
    partition_scan(adev->bdev);

    ahci_device_num++;
    return true;
}

bool ahci_initialize(void) {
    bool found_any = false;

    for (uint64_t i = 0; i < pci_device_count(); i++) {
        const struct pci_device *pci = pci_device_at(i);
        if (pci != NULL && pci->class_code == 0x01 && pci->subclass == 0x06) {
            /* Enable Bus Master & Memory Space */
            if (!pci_enable_memory_bus_mastering(pci)) {
                log_error("[ahci] Failed to enable PCI bus mastering on SATA controller");
                continue;
            }

            uint64_t abar_phys = (uint64_t)(pci->bars[5] & ~0xFFFU);
            if (abar_phys == 0) {
                log_error("[ahci] Invalid ABAR in BAR5");
                continue;
            }

            /* Map ABAR MMIO */
            struct ahci_hba_mem *abar = (struct ahci_hba_mem *)vmm_physical_to_virtual(abar_phys);
            if (abar == NULL) {
                log_error("[ahci] Failed to map ABAR virtual address");
                continue;
            }

            /* Enable AHCI Mode (GHC.AE = 1) */
            abar->ghc |= (1U << 31);

            /* Check implemented ports bitmask */
            uint32_t pi = abar->pi;
            for (uint32_t p = 0; p < AHCI_MAX_PORTS; p++) {
                if (pi & (1U << p)) {
                    if (ahci_probe_port(abar, p)) {
                        found_any = true;
                    }
                }
            }
        }
    }

    return found_any;
}

uint32_t ahci_device_count(void) {
    return ahci_device_num;
}
