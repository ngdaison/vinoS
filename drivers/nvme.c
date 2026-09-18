#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/block.h>
#include <kos/cpu.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/nvme.h>
#include <kos/pci.h>
#include <kos/pmm.h>
#include <kos/timer.h>
#include <kos/vmm.h>

static struct nvme_controller g_nvme_controllers[NVME_MAX_CONTROLLERS];
static uint32_t g_nvme_count = 0;

static struct nvme_namespace g_namespaces[NVME_MAX_NAMESPACES];
static uint32_t g_namespace_count = 0;

static inline uint32_t nvme_read32(volatile uint8_t *base, uint32_t offset) {
    return *(volatile uint32_t *)(base + offset);
}

static inline void nvme_write32(volatile uint8_t *base, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(base + offset) = value;
}

static inline uint64_t nvme_read64(volatile uint8_t *base, uint32_t offset) {
    uint32_t low = *(volatile uint32_t *)(base + offset);
    uint32_t high = *(volatile uint32_t *)(base + offset + 4);
    return ((uint64_t)high << 32) | low;
}

static inline void nvme_write64(volatile uint8_t *base, uint32_t offset, uint64_t value) {
    *(volatile uint32_t *)(base + offset) = (uint32_t)value;
    *(volatile uint32_t *)(base + offset + 4) = (uint32_t)(value >> 32);
}

static bool init_queue(struct nvme_queue *q, uint16_t size, volatile uint32_t *sq_db, volatile uint32_t *cq_db) {
    uint64_t sq_phys = pmm_allocate_frame();
    uint64_t cq_phys = pmm_allocate_frame();
    if (sq_phys == 0 || cq_phys == 0) return false;

    q->sq = (struct nvme_sqe *)vmm_physical_to_virtual(sq_phys);
    q->sq_phys = sq_phys;
    q->cq = (struct nvme_cqe *)vmm_physical_to_virtual(cq_phys);
    q->cq_phys = cq_phys;

    q->size = size;
    q->sq_tail = 0;
    q->cq_head = 0;
    q->cq_phase = 1;
    q->sq_doorbell = sq_db;
    q->cq_doorbell = cq_db;

    for (uint32_t i = 0; i < size; ++i) {
        q->cq[i].status = 0;
    }
    return true;
}

static bool nvme_submit_cmd(struct nvme_queue *q, const struct nvme_sqe *cmd, struct nvme_cqe *out_cqe) {
    uint16_t tail = q->sq_tail;
    q->sq[tail] = *cmd;
    q->sq[tail].command_id = tail;

    q->sq_tail = (uint16_t)((tail + 1) % q->size);
    *q->sq_doorbell = q->sq_tail;

    /* Poll CQ for completion */
    uint16_t head = q->cq_head;
    uint8_t expected_phase = q->cq_phase;
    uint64_t start_tick = timer_ticks();

    while (1) {
        volatile struct nvme_cqe *cqe = &q->cq[head];
        uint8_t phase = (uint8_t)(cqe->status & 1);
        if (phase == expected_phase) {
            if (out_cqe != 0) {
                *out_cqe = *cqe;
            }
            q->cq_head = (uint16_t)((head + 1) % q->size);
            if (q->cq_head == 0) {
                q->cq_phase ^= 1;
            }
            *q->cq_doorbell = q->cq_head;
            uint16_t status_code = (cqe->status >> 1) & 0x7FF;
            return status_code == 0;
        }

        if (timer_ticks() - start_tick > timer_frequency_hz() * 2) {
            log_error("NVMe: Command execution timed out.");
            return false;
        }
        cpu_pause();
    }
}

static void clean_string(char *dest, const char *src, uint64_t len) {
    while (len > 0 && src[len - 1] == ' ') len--;
    for (uint64_t i = 0; i < len; ++i) dest[i] = src[i];
    dest[len] = '\0';
}

static bool init_nvme_controller(struct nvme_controller *ctrl, const struct pci_device *pci) {
    ctrl->pci_dev = pci;
    pci_enable_memory_bus_mastering(pci);

    uint64_t bar0 = (uint64_t)(pci->bars[0] & ~0xFull);
    if ((pci->bars[0] & 0x04) != 0) {
        bar0 |= ((uint64_t)pci->bars[1] << 32);
    }
    if (bar0 == 0) return false;

    ctrl->mmio_base = (volatile uint8_t *)vmm_map_mmio(bar0, 0x4000);
    if (ctrl->mmio_base == 0) return false;

    /* 1. Read Capabilities */
    uint64_t cap = nvme_read64(ctrl->mmio_base, NVME_REG_CAP);
    ctrl->doorbell_stride = 4 << ((cap >> 32) & 0x0F);

    /* 2. Reset Controller if enabled */
    uint32_t cc = nvme_read32(ctrl->mmio_base, NVME_REG_CC);
    if ((cc & NVME_CC_EN) != 0) {
        nvme_write32(ctrl->mmio_base, NVME_REG_CC, 0);
        uint64_t wait_start = timer_ticks();
        while ((nvme_read32(ctrl->mmio_base, NVME_REG_CSTS) & NVME_CSTS_RDY) != 0) {
            if (timer_ticks() - wait_start > timer_frequency_hz()) break;
            cpu_pause();
        }
    }

    /* 3. Setup Admin Queue */
    volatile uint32_t *asq_db = (volatile uint32_t *)(ctrl->mmio_base + 0x1000);
    volatile uint32_t *acq_db = (volatile uint32_t *)(ctrl->mmio_base + 0x1000 + ctrl->doorbell_stride);
    if (!init_queue(&ctrl->admin_queue, NVME_QUEUE_SIZE, asq_db, acq_db)) {
        return false;
    }

    nvme_write32(ctrl->mmio_base, NVME_REG_AQA, ((NVME_QUEUE_SIZE - 1) << 16) | (NVME_QUEUE_SIZE - 1));
    nvme_write64(ctrl->mmio_base, NVME_REG_ASQ, ctrl->admin_queue.sq_phys);
    nvme_write64(ctrl->mmio_base, NVME_REG_ACQ, ctrl->admin_queue.cq_phys);

    /* 4. Enable Controller */
    uint32_t new_cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_MPS_4K | NVME_CC_IOSQES_64B | NVME_CC_IOCQES_16B;
    nvme_write32(ctrl->mmio_base, NVME_REG_CC, new_cc);

    uint64_t rdy_start = timer_ticks();
    while ((nvme_read32(ctrl->mmio_base, NVME_REG_CSTS) & NVME_CSTS_RDY) == 0) {
        if (timer_ticks() - rdy_start > timer_frequency_hz() * 2) {
            log_error("NVMe: Controller ready transition timed out.");
            return false;
        }
        cpu_pause();
    }

    /* 5. Identify Controller (Admin Opcode 0x06, CNS=1) */
    uint64_t id_phys = pmm_allocate_frame();
    if (id_phys == 0) return false;
    uint8_t *id_buf = (uint8_t *)vmm_physical_to_virtual(id_phys);
    for (int i = 0; i < 4096; ++i) id_buf[i] = 0;

    struct nvme_sqe id_cmd = {
        .opcode = NVME_ADMIN_OP_IDENTIFY,
        .nsid = 0,
        .prp1 = id_phys,
        .cdw10 = 1, /* CNS = 1 (Identify Controller) */
    };
    if (!nvme_submit_cmd(&ctrl->admin_queue, &id_cmd, 0)) {
        log_error("NVMe: Identify Controller command failed.");
        pmm_free_frame(id_phys);
        return false;
    }

    clean_string(ctrl->serial_number, (const char *)&id_buf[4], 20);
    clean_string(ctrl->model_number, (const char *)&id_buf[24], 40);
    clean_string(ctrl->firmware_rev, (const char *)&id_buf[64], 8);
    ctrl->num_namespaces = *(const uint32_t *)&id_buf[516];
    if (ctrl->num_namespaces == 0) ctrl->num_namespaces = 1;

    log_infof("NVMe: Model: '%s' | Serial: '%s' | Firmware: '%s' | Namespaces: %u",
              ctrl->model_number, ctrl->serial_number, ctrl->firmware_rev, (unsigned)ctrl->num_namespaces);

    /* 6. Create I/O Completion Queue (Admin Opcode 0x03) */
    volatile uint32_t *iosq_db = (volatile uint32_t *)(ctrl->mmio_base + 0x1000 + 2 * ctrl->doorbell_stride);
    volatile uint32_t *iocq_db = (volatile uint32_t *)(ctrl->mmio_base + 0x1000 + 3 * ctrl->doorbell_stride);
    if (!init_queue(&ctrl->io_queue, NVME_QUEUE_SIZE, iosq_db, iocq_db)) {
        pmm_free_frame(id_phys);
        return false;
    }

    struct nvme_sqe create_cq_cmd = {
        .opcode = NVME_ADMIN_OP_CREATE_CQ,
        .prp1 = ctrl->io_queue.cq_phys,
        .cdw10 = ((NVME_QUEUE_SIZE - 1) << 16) | 1, /* QID = 1 */
        .cdw11 = 1, /* PC = 1 (Physically Contiguous), IEN = 0 (Interrupts Disabled) */
    };
    if (!nvme_submit_cmd(&ctrl->admin_queue, &create_cq_cmd, 0)) {
        log_error("NVMe: Create I/O CQ failed.");
        pmm_free_frame(id_phys);
        return false;
    }

    /* 7. Create I/O Submission Queue (Admin Opcode 0x01) */
    struct nvme_sqe create_sq_cmd = {
        .opcode = NVME_ADMIN_OP_CREATE_SQ,
        .prp1 = ctrl->io_queue.sq_phys,
        .cdw10 = ((NVME_QUEUE_SIZE - 1) << 16) | 1, /* QID = 1 */
        .cdw11 = (1 << 16) | 1, /* CQID = 1, Physically Contiguous */
    };
    if (!nvme_submit_cmd(&ctrl->admin_queue, &create_sq_cmd, 0)) {
        log_error("NVMe: Create I/O SQ failed.");
        pmm_free_frame(id_phys);
        return false;
    }

    /* 8. Identify Namespace 1 (Admin Opcode 0x06, CNS=0, NSID=1) */
    for (int i = 0; i < 4096; ++i) id_buf[i] = 0;
    struct nvme_sqe id_ns_cmd = {
        .opcode = NVME_ADMIN_OP_IDENTIFY,
        .nsid = 1,
        .prp1 = id_phys,
        .cdw10 = 0, /* CNS = 0 (Identify Namespace) */
    };
    if (!nvme_submit_cmd(&ctrl->admin_queue, &id_ns_cmd, 0)) {
        log_error("NVMe: Identify Namespace 1 failed.");
        pmm_free_frame(id_phys);
        return false;
    }

    uint64_t nsze = *(const uint64_t *)&id_buf[0]; /* Size in LBA blocks */
    uint8_t flbas = id_buf[26] & 0x0F;
    uint32_t lbaf = *(const uint32_t *)&id_buf[128 + flbas * 4];
    uint8_t ds = (uint8_t)((lbaf >> 16) & 0xFF);
    uint64_t lba_size = (ds >= 9 && ds <= 16) ? (1ULL << ds) : 512;

    pmm_free_frame(id_phys);

    if (nsze == 0) nsze = 2097152; /* Fallback: 1GB */

    if (g_namespace_count < NVME_MAX_NAMESPACES) {
        struct nvme_namespace *ns = &g_namespaces[g_namespace_count++];
        ns->controller = ctrl;
        ns->nsid = 1;
        ns->block_size = lba_size;
        ns->total_blocks = nsze;
        ns->capacity_bytes = nsze * lba_size;

        static const struct block_device_ops nvme_ops = {
            .read_blocks = nvme_read_blocks,
            .write_blocks = nvme_write_blocks,
            .flush = nvme_flush,
            .destroy = 0,
        };

        ns->bdev = block_device_register("nvme0n1", BLOCK_TYPE_NVME, lba_size, nsze, &nvme_ops, ns);
        if (ns->bdev != 0) {
            log_infof("NVMe: Registered block device 'nvme0n1' (%lu MB, %lu blocks of %u B)",
                      (unsigned long)(ns->capacity_bytes / (1024 * 1024)), (unsigned long)nsze, (unsigned)lba_size);
        }
    }

    ctrl->initialized = true;
    return true;
}

bool nvme_initialize(void) {
    g_nvme_count = 0;
    g_namespace_count = 0;
    uint64_t dev_count = pci_device_count();

    for (uint64_t i = 0; i < dev_count; ++i) {
        const struct pci_device *pci = pci_device_at(i);
        if (pci != 0 && pci->class_code == 0x01 && pci->subclass == 0x08 && pci->programming_interface == 0x02) {
            if (g_nvme_count < NVME_MAX_CONTROLLERS) {
                if (init_nvme_controller(&g_nvme_controllers[g_nvme_count], pci)) {
                    g_nvme_count++;
                }
            }
        }
    }

    if (g_nvme_count == 0) {
        log_info("NVMe: No NVMe controllers detected on PCI bus.");
    }
    return true;
}

bool nvme_read_blocks(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer) {
    if (dev == 0 || buffer == 0 || count == 0) return false;
    struct nvme_namespace *ns = (struct nvme_namespace *)dev->private_data;
    if (ns == 0 || ns->controller == 0 || !ns->controller->initialized) return false;

    uint64_t dma_phys = vmm_virtual_to_physical(buffer);
    bool use_temp = false;
    uint64_t temp_phys = 0;
    void *temp_virt = 0;

    if (dma_phys == 0) {
        temp_phys = pmm_allocate_frame();
        if (temp_phys == 0) return false;
        temp_virt = vmm_physical_to_virtual(temp_phys);
        dma_phys = temp_phys;
        use_temp = true;
    }

    struct nvme_sqe read_cmd = {
        .opcode = NVME_NVM_OP_READ,
        .nsid = ns->nsid,
        .prp1 = dma_phys,
        .cdw10 = (uint32_t)lba,
        .cdw11 = (uint32_t)(lba >> 32),
        .cdw12 = (count - 1) & 0xFFFF,
    };

    bool ok = nvme_submit_cmd(&ns->controller->io_queue, &read_cmd, 0);
    if (ok && use_temp) {
        uint64_t bytes = (uint64_t)count * ns->block_size;
        uint8_t *dst = (uint8_t *)buffer;
        uint8_t *src = (uint8_t *)temp_virt;
        for (uint64_t i = 0; i < bytes; ++i) dst[i] = src[i];
    }

    if (use_temp) {
        pmm_free_frame(temp_phys);
    }
    return ok;
}

bool nvme_write_blocks(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer) {
    if (dev == 0 || buffer == 0 || count == 0) return false;
    struct nvme_namespace *ns = (struct nvme_namespace *)dev->private_data;
    if (ns == 0 || ns->controller == 0 || !ns->controller->initialized) return false;

    uint64_t dma_phys = vmm_virtual_to_physical(buffer);
    bool use_temp = false;
    uint64_t temp_phys = 0;
    void *temp_virt = 0;

    if (dma_phys == 0) {
        temp_phys = pmm_allocate_frame();
        if (temp_phys == 0) return false;
        temp_virt = vmm_physical_to_virtual(temp_phys);
        uint64_t bytes = (uint64_t)count * ns->block_size;
        uint8_t *dst = (uint8_t *)temp_virt;
        const uint8_t *src = (const uint8_t *)buffer;
        for (uint64_t i = 0; i < bytes; ++i) dst[i] = src[i];
        dma_phys = temp_phys;
        use_temp = true;
    }

    struct nvme_sqe write_cmd = {
        .opcode = NVME_NVM_OP_WRITE,
        .nsid = ns->nsid,
        .prp1 = dma_phys,
        .cdw10 = (uint32_t)lba,
        .cdw11 = (uint32_t)(lba >> 32),
        .cdw12 = (count - 1) & 0xFFFF,
    };

    bool ok = nvme_submit_cmd(&ns->controller->io_queue, &write_cmd, 0);
    if (use_temp) {
        pmm_free_frame(temp_phys);
    }
    return ok;
}

bool nvme_flush(struct block_device *dev) {
    if (dev == 0) return false;
    struct nvme_namespace *ns = (struct nvme_namespace *)dev->private_data;
    if (ns == 0 || ns->controller == 0 || !ns->controller->initialized) return false;

    struct nvme_sqe flush_cmd = {
        .opcode = NVME_NVM_OP_FLUSH,
        .nsid = ns->nsid,
    };
    return nvme_submit_cmd(&ns->controller->io_queue, &flush_cmd, 0);
}

uint32_t nvme_get_controller_count(void) { return g_nvme_count; }
const struct nvme_controller *nvme_get_controller(uint32_t index) {
    return index < g_nvme_count ? &g_nvme_controllers[index] : 0;
}
