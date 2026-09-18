#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/acpi.h>
#include <kos/apic.h>
#include <kos/cpu.h>
#include <kos/io.h>
#include <kos/log.h>
#include <kos/timer.h>
#include <kos/vmm.h>

#define IA32_APIC_BASE_MSR 0x1B
#define IA32_APIC_BASE_ENABLE (1ULL << 11)

static volatile uint8_t *lapic_base = 0;
static bool lapic_enabled = false;

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);
    __asm__ volatile ("wrmsr" : : "a"(low), "d"(high), "c"(msr) : "memory");
}

uint32_t lapic_read(uint32_t reg) {
    if (lapic_base == 0) return 0;
    return *(volatile uint32_t *)(lapic_base + reg);
}

void lapic_write(uint32_t reg, uint32_t value) {
    if (lapic_base == 0) return;
    *(volatile uint32_t *)(lapic_base + reg) = value;
}

void lapic_eoi(void) {
    if (lapic_enabled) {
        lapic_write(LAPIC_REG_EOI, 0);
    }
}

uint32_t lapic_get_id(void) {
    if (!lapic_enabled) return 0;
    return (lapic_read(LAPIC_REG_ID) >> 24) & 0xFF;
}

bool lapic_is_enabled(void) {
    return lapic_enabled;
}

void lapic_init_ap(void) {
    if (lapic_base == 0) return;

    /* 1. Ensure APIC Global Enable bit in MSR is set */
    uint64_t apic_base_msr = rdmsr(IA32_APIC_BASE_MSR);
    if ((apic_base_msr & IA32_APIC_BASE_ENABLE) == 0) {
        wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | IA32_APIC_BASE_ENABLE);
    }

    /* 2. Enable Local APIC with Spurious Vector */
    lapic_write(LAPIC_REG_SVR, KOS_APIC_SPURIOUS_VECTOR | 0x100);

    /* 3. Accept all interrupt priority levels */
    lapic_write(LAPIC_REG_TPR, 0x00);

    /* 4. Disable LINT0 and LINT1 on AP */
    lapic_write(LAPIC_REG_LVT_LINT0, 0x10000);
    lapic_write(LAPIC_REG_LVT_LINT1, 0x10000);

    /* 5. Clear error status register */
    lapic_write(LAPIC_REG_ESR, 0);
    lapic_write(LAPIC_REG_ESR, 0);

    /* 6. Send EOI */
    lapic_write(LAPIC_REG_EOI, 0);
}

bool lapic_initialize(void) {
    uint64_t lapic_phys = acpi_get_lapic_address();
    if (lapic_phys == 0) {
        lapic_phys = 0xFEE00000;
    }

    lapic_base = (volatile uint8_t *)vmm_map_mmio(lapic_phys, 0x1000);
    if (lapic_base == 0) {
        log_error("LAPIC: Failed to map MMIO physical base address.");
        return false;
    }

    /* Enable Local APIC on BSP */
    uint64_t apic_base_msr = rdmsr(IA32_APIC_BASE_MSR);
    if ((apic_base_msr & IA32_APIC_BASE_ENABLE) == 0) {
        wrmsr(IA32_APIC_BASE_MSR, apic_base_msr | IA32_APIC_BASE_ENABLE);
    }

    lapic_write(LAPIC_REG_SVR, KOS_APIC_SPURIOUS_VECTOR | 0x100);
    lapic_write(LAPIC_REG_TPR, 0x00);
    lapic_write(LAPIC_REG_DFR, 0xFFFFFFFF);
    lapic_write(LAPIC_REG_LDR, (lapic_read(LAPIC_REG_LDR) & 0x00FFFFFF) | 1);

    lapic_write(LAPIC_REG_LVT_LINT0, 0x10000); /* Mask LINT0 */
    lapic_write(LAPIC_REG_LVT_LINT1, 0x10000); /* Mask LINT1 */
    lapic_write(LAPIC_REG_LVT_ERROR, 0x10000); /* Mask Error */

    lapic_write(LAPIC_REG_ESR, 0);
    lapic_write(LAPIC_REG_ESR, 0);
    lapic_write(LAPIC_REG_EOI, 0);

    lapic_enabled = true;
    uint32_t bsp_id = lapic_get_id();
    uint32_t version = lapic_read(LAPIC_REG_VERSION) & 0xFF;
    log_infof("LAPIC: Initialized on BSP (ID: %u, Version: 0x%02X, Base: 0x%lX)",
              (unsigned)bsp_id, (unsigned)version, (unsigned long)lapic_phys);

    return true;
}

static void wait_icr_idle(void) {
    while ((lapic_read(LAPIC_REG_ICR_LOW) & (1 << 12)) != 0) {
        cpu_pause();
    }
}

void lapic_send_ipi(uint32_t target_lapic_id, uint32_t vector) {
    if (!lapic_enabled) return;
    wait_icr_idle();
    lapic_write(LAPIC_REG_ICR_HIGH, target_lapic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_ICR_FIXED | LAPIC_ICR_ASSERT | LAPIC_ICR_EDGE | (vector & 0xFF));
}

void lapic_send_ipi_all_excluding_self(uint32_t vector) {
    if (!lapic_enabled) return;
    wait_icr_idle();
    lapic_write(LAPIC_REG_ICR_HIGH, 0);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_ICR_DEST_ALL_EX_SELF | LAPIC_ICR_FIXED | LAPIC_ICR_ASSERT | LAPIC_ICR_EDGE | (vector & 0xFF));
}

void lapic_send_init(uint32_t target_lapic_id) {
    if (!lapic_enabled) return;
    wait_icr_idle();
    lapic_write(LAPIC_REG_ICR_HIGH, target_lapic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_ICR_INIT | LAPIC_ICR_ASSERT | LAPIC_ICR_EDGE);
}

void lapic_send_sipi(uint32_t target_lapic_id, uint8_t page_vector) {
    if (!lapic_enabled) return;
    wait_icr_idle();
    lapic_write(LAPIC_REG_ICR_HIGH, target_lapic_id << 24);
    lapic_write(LAPIC_REG_ICR_LOW, LAPIC_ICR_SIPI | LAPIC_ICR_ASSERT | LAPIC_ICR_EDGE | (uint32_t)page_vector);
}
