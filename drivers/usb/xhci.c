#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/cpu.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/pci.h>
#include <kos/pmm.h>
#include <kos/timer.h>
#include <kos/usb.h>
#include <kos/vmm.h>
#include <kos/xhci.h>

static struct xhci_controller g_xhci_controllers[4];
static uint32_t g_xhci_count = 0;

static inline uint32_t xhci_read32(volatile uint8_t *base, uint32_t offset) {
    return *(volatile uint32_t *)(base + offset);
}

static inline void xhci_write32(volatile uint8_t *base, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(base + offset) = value;
}

static inline void xhci_write64(volatile uint8_t *base, uint32_t offset, uint64_t value) {
    *(volatile uint32_t *)(base + offset) = (uint32_t)value;
    *(volatile uint32_t *)(base + offset + 4) = (uint32_t)(value >> 32);
}

static bool init_ring(struct xhci_ring *ring, uint32_t size) {
    uint64_t phys = pmm_allocate_frame();
    if (phys == 0) return false;

    ring->trbs = (struct xhci_trb *)vmm_physical_to_virtual(phys);
    ring->trbs_phys = phys;
    ring->size = size;
    ring->enqueue_idx = 0;
    ring->dequeue_idx = 0;
    ring->cycle_bit = 1;

    for (uint32_t i = 0; i < size; ++i) {
        ring->trbs[i].parameter_low = 0;
        ring->trbs[i].parameter_high = 0;
        ring->trbs[i].status = 0;
        ring->trbs[i].control = 0;
    }
    return true;
}

static bool init_controller(struct xhci_controller *hc, const struct pci_device *pci) {
    hc->pci_dev = pci;
    pci_enable_memory_bus_mastering(pci);

    uint64_t bar0 = (uint64_t)(pci->bars[0] & ~0xFull);
    if ((pci->bars[0] & 0x04) != 0) {
        bar0 |= ((uint64_t)pci->bars[1] << 32);
    }
    if (bar0 == 0) return false;

    hc->mmio_base = (volatile uint8_t *)vmm_map_mmio(bar0, 0x10000);
    if (hc->mmio_base == 0) return false;

    /* 1. Read Capability Registers */
    hc->cap_length = *(volatile uint8_t *)(hc->mmio_base + XHCI_CAP_CAPLENGTH);
    hc->hci_version = *(volatile uint16_t *)(hc->mmio_base + XHCI_CAP_HCIVERSION);

    uint32_t hcsparams1 = xhci_read32(hc->mmio_base, XHCI_CAP_HCSPARAMS1);
    hc->max_slots = hcsparams1 & 0xFF;
    hc->max_ports = (hcsparams1 >> 24) & 0xFF;

    uint32_t hcsparams2 = xhci_read32(hc->mmio_base, XHCI_CAP_HCSPARAMS2);
    hc->max_scratchpads = ((hcsparams2 >> 27) & 0x1F) | (((hcsparams2 >> 21) & 0x1F) << 5);

    uint32_t dboff = xhci_read32(hc->mmio_base, XHCI_CAP_DBOFF) & ~0x03u;
    uint32_t rtsoff = xhci_read32(hc->mmio_base, XHCI_CAP_RTSOFF) & ~0x1Fu;

    hc->op_base = hc->mmio_base + hc->cap_length;
    hc->rt_base = hc->mmio_base + rtsoff;
    hc->db_base = hc->mmio_base + dboff;

    log_infof("xHCI: Controller version 0x%04X (Slots: %u, Ports: %u, Scratchpads: %u)",
              (unsigned)hc->hci_version, (unsigned)hc->max_slots, (unsigned)hc->max_ports, (unsigned)hc->max_scratchpads);

    /* 2. Reset Host Controller */
    uint32_t usbcmd = xhci_read32(hc->op_base, XHCI_OP_USBCMD);
    if ((usbcmd & XHCI_CMD_RS) != 0) {
        xhci_write32(hc->op_base, XHCI_OP_USBCMD, usbcmd & ~XHCI_CMD_RS);
        uint64_t wait_start = timer_ticks();
        while ((xhci_read32(hc->op_base, XHCI_OP_USBSTS) & XHCI_STS_HCH) == 0) {
            if (timer_ticks() - wait_start > timer_frequency_hz() / 5) break;
            cpu_pause();
        }
    }

    xhci_write32(hc->op_base, XHCI_OP_USBCMD, XHCI_CMD_HCRST);
    uint64_t rst_start = timer_ticks();
    while ((xhci_read32(hc->op_base, XHCI_OP_USBCMD) & XHCI_CMD_HCRST) != 0
           || (xhci_read32(hc->op_base, XHCI_OP_USBSTS) & XHCI_STS_CNR) != 0) {
        if (timer_ticks() - rst_start > timer_frequency_hz() / 2) {
            log_error("xHCI: Reset timed out.");
            return false;
        }
        cpu_pause();
    }

    /* 3. Configure Max Slots Enabled */
    uint32_t num_slots = hc->max_slots > XHCI_MAX_SLOTS ? XHCI_MAX_SLOTS : hc->max_slots;
    xhci_write32(hc->op_base, XHCI_OP_CONFIG, num_slots);

    /* 4. Allocate and Setup DCBAA */
    uint64_t dcbaa_phys = pmm_allocate_frame();
    if (dcbaa_phys == 0) return false;
    hc->dcbaa_phys = dcbaa_phys;
    hc->dcbaa = (uint64_t *)vmm_physical_to_virtual(dcbaa_phys);
    for (uint32_t i = 0; i < 256; ++i) hc->dcbaa[i] = 0;
    xhci_write64(hc->op_base, XHCI_OP_DCBAAP, dcbaa_phys);

    /* 5. Initialize Command Ring */
    if (!init_ring(&hc->cmd_ring, XHCI_RING_SIZE)) return false;
    xhci_write64(hc->op_base, XHCI_OP_CRCR, hc->cmd_ring.trbs_phys | 1); /* RCS = 1 */

    /* 6. Initialize Event Ring & ERST (Runtime Interrupter 0) */
    if (!init_ring(&hc->evt_ring, XHCI_RING_SIZE)) return false;
    uint64_t erst_phys = pmm_allocate_frame();
    if (erst_phys == 0) return false;
    hc->erst_phys = erst_phys;
    hc->erst = (struct xhci_erst_entry *)vmm_physical_to_virtual(erst_phys);
    hc->erst[0].ring_segment_base_address = hc->evt_ring.trbs_phys;
    hc->erst[0].ring_segment_size = XHCI_RING_SIZE;
    hc->erst[0].reserved = 0;

    volatile uint8_t *ir0 = hc->rt_base + 0x20; /* Primary Interrupter */
    xhci_write32(ir0, XHCI_RT_ERSTSZ, 1);
    xhci_write64(ir0, XHCI_RT_ERDP, hc->evt_ring.trbs_phys);
    xhci_write64(ir0, XHCI_RT_ERSTBA, hc->erst_phys);
    xhci_write32(ir0, XHCI_RT_IMAN, 2); /* Enable interrupter */

    /* 7. Start Host Controller (USBCMD.RS = 1) */
    xhci_write32(hc->op_base, XHCI_OP_USBCMD, XHCI_CMD_RS | XHCI_CMD_INTE);
    uint64_t run_start = timer_ticks();
    while ((xhci_read32(hc->op_base, XHCI_OP_USBSTS) & XHCI_STS_HCH) != 0) {
        if (timer_ticks() - run_start > timer_frequency_hz() / 5) {
            log_error("xHCI: Failed to transition to running state.");
            return false;
        }
        cpu_pause();
    }

    /* 8. Scan and reset connected ports */
    uint32_t connected_ports = 0;
    for (uint32_t port = 1; port <= hc->max_ports; ++port) {
        uint32_t port_offset = XHCI_OP_PORTSC_BASE + (port - 1) * 0x10;
        uint32_t portsc = xhci_read32(hc->op_base, port_offset);

        if ((portsc & XHCI_PORTSC_CCS) != 0) {
            connected_ports++;
            log_infof("xHCI: Port %u device connected (PORTSC: 0x%08X). Resetting port...", (unsigned)port, (unsigned)portsc);
            /* Issue Port Reset */
            xhci_write32(hc->op_base, port_offset, (portsc & ~XHCI_PORTSC_PED) | XHCI_PORTSC_PR);
        }
    }

    hc->initialized = true;
    log_infof("xHCI: Initialized controller on PCI %02X:%02X.%X (Connected ports: %u)",
              (unsigned)pci->bus, (unsigned)pci->device, (unsigned)pci->function, (unsigned)connected_ports);
    return true;
}

bool xhci_initialize(void) {
    g_xhci_count = 0;
    uint64_t dev_count = pci_device_count();

    for (uint64_t i = 0; i < dev_count; ++i) {
        const struct pci_device *pci = pci_device_at(i);
        if (pci != 0 && pci->class_code == 0x0C && pci->subclass == 0x03 && pci->programming_interface == 0x30) {
            if (g_xhci_count < 4) {
                if (init_controller(&g_xhci_controllers[g_xhci_count], pci)) {
                    g_xhci_count++;
                }
            }
        }
    }

    if (g_xhci_count == 0) {
        log_info("xHCI: No xHCI controllers detected on PCI bus.");
    }
    return true;
}

void xhci_poll(void) {
    for (uint32_t c = 0; c < g_xhci_count; ++c) {
        struct xhci_controller *hc = &g_xhci_controllers[c];
        if (!hc->initialized) continue;

        struct xhci_ring *er = &hc->evt_ring;
        while (1) {
            struct xhci_trb *trb = &er->trbs[er->dequeue_idx];
            uint8_t c_bit = (uint8_t)(trb->control & 1);
            if (c_bit != er->cycle_bit) {
                break;
            }

            uint32_t trb_type = (trb->control >> 10) & 0x3F;
            if (trb_type == XHCI_TRB_PORT_STATUS_CHANGE) {
                uint32_t port_id = (trb->parameter_low >> 24) & 0xFF;
                log_infof("xHCI: Port status change event on port %u", (unsigned)port_id);
            }

            er->dequeue_idx = (er->dequeue_idx + 1) % er->size;
            if (er->dequeue_idx == 0) {
                er->cycle_bit ^= 1;
            }

            /* Update ERDP */
            volatile uint8_t *ir0 = hc->rt_base + 0x20;
            xhci_write64(ir0, XHCI_RT_ERDP, hc->evt_ring.trbs_phys + er->dequeue_idx * sizeof(struct xhci_trb));
        }
    }
}

uint32_t xhci_get_controller_count(void) { return g_xhci_count; }
const struct xhci_controller *xhci_get_controller(uint32_t index) {
    return index < g_xhci_count ? &g_xhci_controllers[index] : 0;
}
