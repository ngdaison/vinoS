#ifndef KOS_APIC_H
#define KOS_APIC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>

/* Special Interrupt Vectors */
#define KOS_APIC_TIMER_VECTOR          0x20  /* 32 */
#define KOS_APIC_KEYBOARD_VECTOR       0x21  /* 33 */
#define KOS_APIC_SERIAL_VECTOR         0x24  /* 36 */
#define KOS_IPI_RESCHEDULE_VECTOR      0xFC
#define KOS_IPI_TLB_SHOOTDOWN_VECTOR   0xFD
#define KOS_IPI_GENERIC_VECTOR         0xFE
#define KOS_APIC_SPURIOUS_VECTOR       0xFF

/* Local APIC Register Offsets */
#define LAPIC_REG_ID                   0x020
#define LAPIC_REG_VERSION              0x030
#define LAPIC_REG_TPR                  0x080
#define LAPIC_REG_APR                  0x090
#define LAPIC_REG_PPR                  0x0A0
#define LAPIC_REG_EOI                  0x0B0
#define LAPIC_REG_RRD                  0x0C0
#define LAPIC_REG_LDR                  0x0D0
#define LAPIC_REG_DFR                  0x0E0
#define LAPIC_REG_SVR                  0x0F0
#define LAPIC_REG_ISR0                 0x100
#define LAPIC_REG_TMR0                 0x180
#define LAPIC_REG_IRR0                 0x200
#define LAPIC_REG_ESR                  0x280
#define LAPIC_REG_ICR_LOW              0x300
#define LAPIC_REG_ICR_HIGH             0x310
#define LAPIC_REG_LVT_TIMER            0x320
#define LAPIC_REG_LVT_THERMAL          0x330
#define LAPIC_REG_LVT_PERF             0x340
#define LAPIC_REG_LVT_LINT0            0x350
#define LAPIC_REG_LVT_LINT1            0x360
#define LAPIC_REG_LVT_ERROR            0x370
#define LAPIC_REG_TIMER_INITCNT        0x380
#define LAPIC_REG_TIMER_CURRCNT        0x390
#define LAPIC_REG_TIMER_DIV            0x3E0

/* ICR Flags */
#define LAPIC_ICR_FIXED                0x00000
#define LAPIC_ICR_LOWEST               0x00100
#define LAPIC_ICR_SMI                  0x00200
#define LAPIC_ICR_NMI                  0x00400
#define LAPIC_ICR_INIT                 0x00500
#define LAPIC_ICR_SIPI                 0x00600
#define LAPIC_ICR_DEASSERT             0x00000
#define LAPIC_ICR_ASSERT               0x04000
#define LAPIC_ICR_EDGE                 0x00000
#define LAPIC_ICR_LEVEL                0x08000
#define LAPIC_ICR_DEST_SELF            0x40000
#define LAPIC_ICR_DEST_ALL             0x80000
#define LAPIC_ICR_DEST_ALL_EX_SELF     0xC0000

/* IOAPIC Registers */
#define IOAPIC_REG_ID                  0x00
#define IOAPIC_REG_VERSION             0x01
#define IOAPIC_REG_ARB                 0x02
#define IOAPIC_REG_REDTBL_BASE         0x10

#define IOAPIC_REDTBL_MASKED           (1 << 16)
#define IOAPIC_REDTBL_LEVEL            (1 << 15)
#define IOAPIC_REDTBL_LOW_ACTIVE       (1 << 13)

/* Local APIC API */
bool lapic_initialize(void);
void lapic_init_ap(void);
uint32_t lapic_read(uint32_t reg);
void lapic_write(uint32_t reg, uint32_t value);
void lapic_eoi(void);
uint32_t lapic_get_id(void);
bool lapic_is_enabled(void);

void lapic_send_ipi(uint32_t target_lapic_id, uint32_t vector);
void lapic_send_ipi_all_excluding_self(uint32_t vector);
void lapic_send_init(uint32_t target_lapic_id);
void lapic_send_sipi(uint32_t target_lapic_id, uint8_t page_vector);

/* IOAPIC API */
bool ioapic_initialize(void);
void ioapic_route_irq(uint8_t source_irq, uint8_t vector, uint32_t target_lapic_id, bool masked);
void ioapic_mask_irq(uint8_t source_irq);
void ioapic_unmask_irq(uint8_t source_irq);
bool ioapic_is_enabled(void);

#endif /* KOS_APIC_H */
