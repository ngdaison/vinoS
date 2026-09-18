#include <stdbool.h>
#include <stdint.h>

#include <kos/compiler.h>
#include <kos/cpu.h>
#include <kos/descriptors.h>
#include <kos/log.h>

extern void gdt_load(const struct descriptor_table_pointer *pointer);
extern void tss_load(uint16_t selector);
extern uint8_t kos_boot_stack_top[];

enum {
    DOUBLE_FAULT_STACK_SIZE = 16384,
};

static uint64_t gdt_entries[7] KOS_ALIGNED(16) = {
    0x0000000000000000ull, /* 0: Null Descriptor */
    0x00af9a000000ffffull, /* 1: Kernel Code (0x08) */
    0x00cf92000000ffffull, /* 2: Kernel Data (0x10) */
    0x0000000000000000ull, /* 3: TSS Low (0x18) */
    0x0000000000000000ull, /* 4: TSS High (0x20) */
    0x00cff2000000ffffull, /* 5: User Data (0x28 | 3 = 0x2B) */
    0x00affa000000ffffull, /* 6: User Code (0x30 | 3 = 0x33) */
};

static struct task_state_segment tss KOS_ALIGNED(16);
static uint8_t double_fault_stack[DOUBLE_FAULT_STACK_SIZE] KOS_ALIGNED(16);

static void gdt_configure_tss_descriptor(void) {
    uint64_t base = (uint64_t)&tss;
    uint64_t limit = sizeof(tss) - 1;

    gdt_entries[3] = (limit & 0xffff)
        | ((base & 0xffffff) << 16)
        | (0x89ull << 40)
        | ((limit & 0xf0000) << 32)
        | (((base >> 24) & 0xff) << 56);
    gdt_entries[4] = base >> 32;
}

#include <kos/smp.h>

KOS_NOINLINE void tss_set_rsp0(uint64_t rsp0) {
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0) {
        cpu->tss.rsp0 = rsp0;
    }
    tss.rsp0 = rsp0;
}

KOS_NOINLINE uint64_t tss_get_rsp0(void) {
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0 && cpu->tss.rsp0 != 0) {
        return cpu->tss.rsp0;
    }
    return tss.rsp0;
}

KOS_NOINLINE uint64_t tss_get_ist1(void) {
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0 && cpu->tss.ist1 != 0) {
        return cpu->tss.ist1;
    }
    return tss.ist1;
}

KOS_NOINLINE bool tss_set_ist(uint8_t index, uint64_t stack_top) {
    switch (index) {
        case 1: tss.ist1 = stack_top; return true;
        case 2: tss.ist2 = stack_top; return true;
        case 3: tss.ist3 = stack_top; return true;
        case 4: tss.ist4 = stack_top; return true;
        case 5: tss.ist5 = stack_top; return true;
        case 6: tss.ist6 = stack_top; return true;
        case 7: tss.ist7 = stack_top; return true;
        default: return false;
    }
}

KOS_NOINLINE uint64_t tss_get_ist(uint8_t index) {
    switch (index) {
        case 1: return tss.ist1;
        case 2: return tss.ist2;
        case 3: return tss.ist3;
        case 4: return tss.ist4;
        case 5: return tss.ist5;
        case 6: return tss.ist6;
        case 7: return tss.ist7;
        default: return 0;
    }
}

void gdt_initialize(void) {
    tss_set_rsp0((uint64_t)kos_boot_stack_top);
    tss.ist1 = (uint64_t)(double_fault_stack + DOUBLE_FAULT_STACK_SIZE);
    tss.io_map_base = sizeof(tss);
    gdt_configure_tss_descriptor();

    const struct descriptor_table_pointer gdt_pointer = {
        .limit = sizeof(gdt_entries) - 1,
        .base = (uint64_t)gdt_entries,
    };
    gdt_load(&gdt_pointer);
    tss_load(KOS_KERNEL_TSS_SELECTOR);

    if (tss_get_rsp0() == 0 || tss_get_ist1() == 0 || tss_get_ist(1) == 0) {
        log_error("TSS initialization verification failed: rsp0 or ist1 is zero.");
        cpu_halt();
    }
}
