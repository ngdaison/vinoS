#ifndef KOS_DESCRIPTORS_H
#define KOS_DESCRIPTORS_H

#include <stdbool.h>
#include <stdint.h>

#include <kos/compiler.h>

struct descriptor_table_pointer {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct task_state_segment {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t io_map_base;
} __attribute__((packed));

_Static_assert(sizeof(struct task_state_segment) == 104,
    "64-bit TSS size must be exactly 104 bytes");
_Static_assert(__builtin_offsetof(struct task_state_segment, rsp0) == 4,
    "TSS rsp0 must be at offset 4");
_Static_assert(__builtin_offsetof(struct task_state_segment, ist1) == 36,
    "TSS ist1 must be at offset 36 (0x24)");
_Static_assert(__builtin_offsetof(struct task_state_segment, io_map_base) == 102,
    "TSS io_map_base must be at offset 102 (0x66)");

#define GDT_KERNEL_CS 0x08
#define GDT_KERNEL_DS 0x10
#define GDT_USER_CS   0x2b
#define GDT_USER_DS   0x33

/* GDT & TSS Lifecycle */
void gdt_initialize(void);
void tss_set_rsp0(uint64_t rsp0);
uint64_t tss_get_rsp0(void);
uint64_t tss_get_ist1(void);
bool tss_set_ist(uint8_t index, uint64_t stack_top);
uint64_t tss_get_ist(uint8_t index);

#endif /* KOS_DESCRIPTORS_H */
