#ifndef KOS_NVME_H
#define KOS_NVME_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/block.h>
#include <kos/compiler.h>
#include <kos/pci.h>

#define NVME_MAX_CONTROLLERS 4
#define NVME_MAX_NAMESPACES 4
#define NVME_QUEUE_SIZE 64

/* NVMe Registers */
#define NVME_REG_CAP         0x0000 /* Controller Capabilities (64-bit) */
#define NVME_REG_VS          0x0008 /* Version (32-bit) */
#define NVME_REG_INTMS       0x000C /* Interrupt Mask Set */
#define NVME_REG_INTMC       0x0010 /* Interrupt Mask Clear */
#define NVME_REG_CC          0x0014 /* Controller Configuration */
#define NVME_REG_CSTS        0x001C /* Controller Status */
#define NVME_REG_NSSR        0x0020 /* NVM Subsystem Reset */
#define NVME_REG_AQA         0x0024 /* Admin Queue Attributes */
#define NVME_REG_ASQ         0x0028 /* Admin Submission Queue Base (64-bit) */
#define NVME_REG_ACQ         0x0030 /* Admin Completion Queue Base (64-bit) */

/* CC Flags */
#define NVME_CC_EN           (1 << 0)
#define NVME_CC_CSS_NVM      (0 << 4)
#define NVME_CC_MPS_4K       (0 << 7)
#define NVME_CC_IOSQES_64B   (6 << 16)
#define NVME_CC_IOCQES_16B   (4 << 20)

/* CSTS Flags */
#define NVME_CSTS_RDY        (1 << 0)
#define NVME_CSTS_CFS        (1 << 1)

/* Admin Opcodes */
#define NVME_ADMIN_OP_DELETE_SQ   0x00
#define NVME_ADMIN_OP_CREATE_SQ   0x01
#define NVME_ADMIN_OP_DELETE_CQ   0x04
#define NVME_ADMIN_OP_CREATE_CQ   0x05
#define NVME_ADMIN_OP_IDENTIFY    0x06

/* NVM Opcodes */
#define NVME_NVM_OP_FLUSH         0x00
#define NVME_NVM_OP_WRITE         0x01
#define NVME_NVM_OP_READ          0x02

/* 64-byte Submission Queue Entry (SQE) */
struct nvme_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t command_id;
    uint32_t nsid;
    uint64_t reserved;
    uint64_t metadata;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed));

/* 16-byte Completion Queue Entry (CQE) */
struct nvme_cqe {
    uint32_t result;
    uint32_t reserved;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t command_id;
    uint16_t status;
} __attribute__((packed));

struct nvme_queue {
    struct nvme_sqe *sq;
    uint64_t sq_phys;
    struct nvme_cqe *cq;
    uint64_t cq_phys;
    uint16_t sq_tail;
    uint16_t cq_head;
    uint8_t cq_phase;
    uint16_t size;
    volatile uint32_t *sq_doorbell;
    volatile uint32_t *cq_doorbell;
};

struct nvme_namespace;

struct nvme_controller {
    const struct pci_device *pci_dev;
    volatile uint8_t *mmio_base;
    uint32_t doorbell_stride;

    struct nvme_queue admin_queue;
    struct nvme_queue io_queue;

    char serial_number[21];
    char model_number[41];
    char firmware_rev[9];
    uint32_t num_namespaces;

    bool initialized;
};

struct nvme_namespace {
    struct nvme_controller *controller;
    uint32_t nsid;
    uint64_t block_size;
    uint64_t total_blocks;
    uint64_t capacity_bytes;
    struct block_device *bdev;
};

/* Core NVMe Driver API */
bool nvme_initialize(void);
uint32_t nvme_get_controller_count(void);
const struct nvme_controller *nvme_get_controller(uint32_t index);

bool nvme_read_blocks(struct block_device *dev, uint64_t lba, uint32_t count, void *buffer);
bool nvme_write_blocks(struct block_device *dev, uint64_t lba, uint32_t count, const void *buffer);
bool nvme_flush(struct block_device *dev);

#endif /* KOS_NVME_H */
