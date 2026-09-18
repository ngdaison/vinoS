#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/acpi.h>
#include <kos/apic.h>
#include <kos/log.h>
#include <kos/vmm.h>

#define IOREGSEL 0x00
#define IOWIN    0x10

static volatile uint8_t *ioapic_base = 0;
static uint32_t ioapic_gsi_base = 0;
static uint32_t ioapic_max_redirs = 24;
static bool ioapic_enabled = false;

static uint32_t ioapic_read(uint8_t reg) {
    if (ioapic_base == 0) return 0;
    *(volatile uint32_t *)(ioapic_base + IOREGSEL) = reg;
    return *(volatile uint32_t *)(ioapic_base + IOWIN);
}

static void ioapic_write(uint8_t reg, uint32_t value) {
    if (ioapic_base == 0) return;
    *(volatile uint32_t *)(ioapic_base + IOREGSEL) = reg;
    *(volatile uint32_t *)(ioapic_base + IOWIN) = value;
}

static void ioapic_write_redtbl(uint32_t index, uint64_t entry) {
    uint8_t low_reg = (uint8_t)(IOAPIC_REG_REDTBL_BASE + index * 2);
    uint8_t high_reg = (uint8_t)(low_reg + 1);
    ioapic_write(low_reg, (uint32_t)entry);
    ioapic_write(high_reg, (uint32_t)(entry >> 32));
}

static uint64_t ioapic_read_redtbl(uint32_t index) {
    uint8_t low_reg = (uint8_t)(IOAPIC_REG_REDTBL_BASE + index * 2);
    uint8_t high_reg = (uint8_t)(low_reg + 1);
    uint32_t low = ioapic_read(low_reg);
    uint32_t high = ioapic_read(high_reg);
    return ((uint64_t)high << 32) | low;
}

bool ioapic_is_enabled(void) {
    return ioapic_enabled;
}

void ioapic_route_irq(uint8_t source_irq, uint8_t vector, uint32_t target_lapic_id, bool masked) {
    if (!ioapic_enabled) return;

    uint32_t gsi = source_irq;
    uint32_t flags = 0;

    const struct acpi_iso_entry *iso = acpi_find_iso_for_irq(source_irq);
    if (iso != 0) {
        gsi = iso->gsi;
        /* ISO polarity: bit 0..1: 00=Bus, 01=High, 11=Low */
        if ((iso->flags & 0x03) == 0x03) {
            flags |= IOAPIC_REDTBL_LOW_ACTIVE;
        }
        /* ISO trigger: bit 2..3: 00=Bus, 01=Edge, 11=Level */
        if ((iso->flags & 0x0C) == 0x0C) {
            flags |= IOAPIC_REDTBL_LEVEL;
        }
    }

    if (gsi < ioapic_gsi_base || gsi >= ioapic_gsi_base + ioapic_max_redirs) {
        return;
    }

    uint32_t index = gsi - ioapic_gsi_base;
    uint64_t redtbl_entry = (uint64_t)vector | (uint64_t)flags;
    if (masked) {
        redtbl_entry |= IOAPIC_REDTBL_MASKED;
    }
    redtbl_entry |= ((uint64_t)target_lapic_id << 56);

    ioapic_write_redtbl(index, redtbl_entry);
}

void ioapic_mask_irq(uint8_t source_irq) {
    if (!ioapic_enabled) return;
    uint32_t gsi = source_irq;
    const struct acpi_iso_entry *iso = acpi_find_iso_for_irq(source_irq);
    if (iso != 0) gsi = iso->gsi;
    if (gsi < ioapic_gsi_base || gsi >= ioapic_gsi_base + ioapic_max_redirs) return;
    uint32_t index = gsi - ioapic_gsi_base;
    uint64_t entry = ioapic_read_redtbl(index);
    entry |= IOAPIC_REDTBL_MASKED;
    ioapic_write_redtbl(index, entry);
}

void ioapic_unmask_irq(uint8_t source_irq) {
    if (!ioapic_enabled) return;
    uint32_t gsi = source_irq;
    const struct acpi_iso_entry *iso = acpi_find_iso_for_irq(source_irq);
    if (iso != 0) gsi = iso->gsi;
    if (gsi < ioapic_gsi_base || gsi >= ioapic_gsi_base + ioapic_max_redirs) return;
    uint32_t index = gsi - ioapic_gsi_base;
    uint64_t entry = ioapic_read_redtbl(index);
    entry &= ~((uint64_t)IOAPIC_REDTBL_MASKED);
    ioapic_write_redtbl(index, entry);
}

bool ioapic_initialize(void) {
    uint64_t ioapic_phys = 0xFEC00000;
    ioapic_gsi_base = 0;

    if (acpi_get_ioapic_count() > 0) {
        const struct acpi_ioapic_entry *io_entry = acpi_get_ioapic(0);
        if (io_entry != 0 && io_entry->address != 0) {
            ioapic_phys = io_entry->address;
            ioapic_gsi_base = io_entry->gsi_base;
        }
    }

    ioapic_base = (volatile uint8_t *)vmm_map_mmio(ioapic_phys, 0x1000);
    if (ioapic_base == 0) {
        log_error("IOAPIC: Failed to map MMIO address.");
        return false;
    }

    uint32_t version_reg = ioapic_read(IOAPIC_REG_VERSION);
    ioapic_max_redirs = ((version_reg >> 16) & 0xFF) + 1;
    uint32_t ioapic_id = (ioapic_read(IOAPIC_REG_ID) >> 24) & 0x0F;

    /* Mask all redirection entries initially */
    for (uint32_t i = 0; i < ioapic_max_redirs; ++i) {
        ioapic_write_redtbl(i, (uint64_t)IOAPIC_REDTBL_MASKED | (32 + i));
    }

    ioapic_enabled = true;

    /* Route standard legacy IRQs through IOAPIC to BSP LAPIC */
    uint32_t bsp_id = lapic_get_id();
    ioapic_route_irq(0, KOS_APIC_TIMER_VECTOR, bsp_id, false);       /* Timer (IRQ0) */
    ioapic_route_irq(1, KOS_APIC_KEYBOARD_VECTOR, bsp_id, false);    /* Keyboard (IRQ1) */
    ioapic_route_irq(4, KOS_APIC_SERIAL_VECTOR, bsp_id, false);      /* Serial COM1 (IRQ4) */

    log_infof("IOAPIC: Initialized (ID: %u, GSI Base: %u, Max Redirs: %u, Base: 0x%lX)",
              (unsigned)ioapic_id, (unsigned)ioapic_gsi_base, (unsigned)ioapic_max_redirs, (unsigned long)ioapic_phys);

    return true;
}
