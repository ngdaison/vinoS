#ifndef KOS_CPU_H
#define KOS_CPU_H

#include <stdint.h>

#include <kos/compiler.h>

enum {
    KOS_KERNEL_CODE_SELECTOR = 0x08,
    KOS_KERNEL_DATA_SELECTOR = 0x10,
    KOS_KERNEL_TSS_SELECTOR = 0x18,
    KOS_USER_DATA_SELECTOR = 0x2b,
    KOS_USER_CODE_SELECTOR = 0x33,
};

void gdt_initialize(void);
void idt_initialize(void);
void tss_set_rsp0(uint64_t rsp0);
uint64_t tss_get_rsp0(void);
uint64_t tss_get_ist1(void);
KOS_NORETURN void cpu_halt(void);
KOS_NORETURN void cpu_idle(void);
KOS_NORETURN void cpu_reboot(void);
KOS_NORETURN void enter_userspace(uint64_t entry_point, uint64_t user_rsp);
void cpu_enable_interrupts(void);
void cpu_wait_for_interrupt(void);
void cpu_pause(void);
uint64_t cpu_interrupt_save_disable(void);
void cpu_interrupt_restore(uint64_t flags);
uint64_t cpu_read_cr2(void);
uint64_t cpu_read_cr3(void);
void cpu_write_cr3(uint64_t cr3);
void cpu_invalidate_page(uint64_t virtual_address);
void cpu_trigger_divide_by_zero(void);

#endif
