#ifndef KOS_XHCI_H
#define KOS_XHCI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/pci.h>

#define XHCI_MAX_SLOTS 32
#define XHCI_RING_SIZE 64

/* xHCI Capability Registers */
#define XHCI_CAP_CAPLENGTH     0x00
#define XHCI_CAP_HCIVERSION    0x02
#define XHCI_CAP_HCSPARAMS1    0x04
#define XHCI_CAP_HCSPARAMS2    0x08
#define XHCI_CAP_HCSPARAMS3    0x0C
#define XHCI_CAP_HCCPARAMS1    0x10
#define XHCI_CAP_DBOFF         0x14
#define XHCI_CAP_RTSOFF        0x18
#define XHCI_CAP_HCCPARAMS2    0x1C

/* xHCI Operational Registers */
#define XHCI_OP_USBCMD         0x00
#define XHCI_OP_USBSTS         0x04
#define XHCI_OP_PAGESIZE       0x08
#define XHCI_OP_DNCTRL         0x14
#define XHCI_OP_CRCR           0x18
#define XHCI_OP_DCBAAP         0x30
#define XHCI_OP_CONFIG         0x38
#define XHCI_OP_PORTSC_BASE    0x400

/* USBCMD Flags */
#define XHCI_CMD_RS            (1 << 0)  /* Run / Stop */
#define XHCI_CMD_HCRST         (1 << 1)  /* Host Controller Reset */
#define XHCI_CMD_INTE          (1 << 2)  /* Interrupter Enable */

/* USBSTS Flags */
#define XHCI_STS_HCH           (1 << 0)  /* HC Halted */
#define XHCI_STS_HSE           (1 << 2)  /* Host System Error */
#define XHCI_STS_EINT          (1 << 3)  /* Event Interrupt */
#define XHCI_STS_PCD           (1 << 4)  /* Port Change Detect */
#define XHCI_STS_CNR           (1 << 11) /* Controller Not Ready */

/* PORTSC Flags */
#define XHCI_PORTSC_CCS        (1 << 0)  /* Current Connect Status */
#define XHCI_PORTSC_PED        (1 << 1)  /* Port Enabled/Disabled */
#define XHCI_PORTSC_PR         (1 << 4)  /* Port Reset */
#define XHCI_PORTSC_PLS_MASK   (0xF << 5)/* Port Link State */
#define XHCI_PORTSC_PP         (1 << 9)  /* Port Power */
#define XHCI_PORTSC_CSC        (1 << 17) /* Connect Status Change */
#define XHCI_PORTSC_PRC        (1 << 21) /* Port Reset Change */

/* Interrupter Registers (Runtime) */
#define XHCI_RT_IMAN           0x00
#define XHCI_RT_IMOD           0x04
#define XHCI_RT_ERSTSZ         0x08
#define XHCI_RT_ERSTBA         0x10
#define XHCI_RT_ERDP           0x18

/* xHCI Generic TRB Structure */
struct xhci_trb {
    uint32_t parameter_low;
    uint32_t parameter_high;
    uint32_t status;
    uint32_t control;
} __attribute__((packed));

/* TRB Types */
#define XHCI_TRB_NORMAL              1
#define XHCI_TRB_SETUP_STAGE         2
#define XHCI_TRB_DATA_STAGE          3
#define XHCI_TRB_STATUS_STAGE        4
#define XHCI_TRB_LINK                6
#define XHCI_TRB_EVENT_DATA          7
#define XHCI_TRB_ENABLE_SLOT_CMD     9
#define XHCI_TRB_DISABLE_SLOT_CMD    10
#define XHCI_TRB_ADDRESS_DEV_CMD     11
#define XHCI_TRB_CONFIG_EP_CMD       12
#define XHCI_TRB_TRANSFER_EVENT      32
#define XHCI_TRB_CMD_COMPLETION_EVENT 33
#define XHCI_TRB_PORT_STATUS_CHANGE  34

/* Event Ring Segment Table Entry */
struct xhci_erst_entry {
    uint64_t ring_segment_base_address;
    uint32_t ring_segment_size;
    uint32_t reserved;
} __attribute__((packed));

struct xhci_ring {
    struct xhci_trb *trbs;
    uint64_t trbs_phys;
    uint32_t enqueue_idx;
    uint32_t dequeue_idx;
    uint8_t cycle_bit;
    uint32_t size;
};

struct xhci_controller {
    const struct pci_device *pci_dev;
    volatile uint8_t *mmio_base;
    uint8_t cap_length;
    uint16_t hci_version;
    uint32_t max_slots;
    uint32_t max_ports;
    uint32_t max_scratchpads;

    volatile uint8_t *op_base;
    volatile uint8_t *rt_base;
    volatile uint8_t *db_base;

    uint64_t *dcbaa;
    uint64_t dcbaa_phys;

    struct xhci_ring cmd_ring;
    struct xhci_ring evt_ring;
    struct xhci_erst_entry *erst;
    uint64_t erst_phys;

    bool initialized;
};

/* Core xHCI API */
bool xhci_initialize(void);
void xhci_poll(void);
uint32_t xhci_get_controller_count(void);
const struct xhci_controller *xhci_get_controller(uint32_t index);

#endif /* KOS_XHCI_H */
