#ifndef KOS_INTERRUPTS_H
#define KOS_INTERRUPTS_H

#include <stdbool.h>
#include <stdint.h>

enum {
    KOS_EXCEPTION_VECTOR_COUNT = 32,
};

struct interrupt_context {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t vector;
    uint64_t error_code;
    union {
        uint64_t rip;
        uint64_t instruction_pointer;
    };
    union {
        uint64_t cs;
        uint64_t code_segment;
    };
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

_Static_assert(sizeof(struct interrupt_context) == 176,
    "struct interrupt_context must be exactly 176 bytes (22 quadwords)");
_Static_assert(__builtin_offsetof(struct interrupt_context, r15) == 0x00, "r15 offset must be 0x00");
_Static_assert(__builtin_offsetof(struct interrupt_context, r14) == 0x08, "r14 offset must be 0x08");
_Static_assert(__builtin_offsetof(struct interrupt_context, r13) == 0x10, "r13 offset must be 0x10");
_Static_assert(__builtin_offsetof(struct interrupt_context, r12) == 0x18, "r12 offset must be 0x18");
_Static_assert(__builtin_offsetof(struct interrupt_context, r11) == 0x20, "r11 offset must be 0x20");
_Static_assert(__builtin_offsetof(struct interrupt_context, r10) == 0x28, "r10 offset must be 0x28");
_Static_assert(__builtin_offsetof(struct interrupt_context, r9) == 0x30, "r9 offset must be 0x30");
_Static_assert(__builtin_offsetof(struct interrupt_context, r8) == 0x38, "r8 offset must be 0x38");
_Static_assert(__builtin_offsetof(struct interrupt_context, rdi) == 0x40, "rdi offset must be 0x40");
_Static_assert(__builtin_offsetof(struct interrupt_context, rsi) == 0x48, "rsi offset must be 0x48");
_Static_assert(__builtin_offsetof(struct interrupt_context, rbp) == 0x50, "rbp offset must be 0x50");
_Static_assert(__builtin_offsetof(struct interrupt_context, rdx) == 0x58, "rdx offset must be 0x58");
_Static_assert(__builtin_offsetof(struct interrupt_context, rcx) == 0x60, "rcx offset must be 0x60");
_Static_assert(__builtin_offsetof(struct interrupt_context, rbx) == 0x68, "rbx offset must be 0x68");
_Static_assert(__builtin_offsetof(struct interrupt_context, rax) == 0x70, "rax offset must be 0x70");
_Static_assert(__builtin_offsetof(struct interrupt_context, vector) == 0x78, "vector offset must be 0x78");
_Static_assert(__builtin_offsetof(struct interrupt_context, error_code) == 0x80, "error_code offset must be 0x80");
_Static_assert(__builtin_offsetof(struct interrupt_context, rip) == 0x88, "rip offset must be 0x88");
_Static_assert(__builtin_offsetof(struct interrupt_context, instruction_pointer) == 0x88, "instruction_pointer offset must be 0x88");
_Static_assert(__builtin_offsetof(struct interrupt_context, cs) == 0x90, "cs offset must be 0x90");
_Static_assert(__builtin_offsetof(struct interrupt_context, code_segment) == 0x90, "code_segment offset must be 0x90");
_Static_assert(__builtin_offsetof(struct interrupt_context, rflags) == 0x98, "rflags offset must be 0x98");
_Static_assert(__builtin_offsetof(struct interrupt_context, rsp) == 0xA0, "rsp offset must be 0xA0");
_Static_assert(__builtin_offsetof(struct interrupt_context, ss) == 0xA8, "ss offset must be 0xA8");

typedef void (*irq_handler)(uint8_t irq, void *context);
typedef void (*exception_handler_t)(struct interrupt_context *context);

typedef void (*exception_handler_t)(struct interrupt_context *context);

/* Hardware PIC IRQ (vectors 32 to 47) APIs */
bool irq_register_handler(uint8_t irq, irq_handler handler);
bool irq_unregister_handler(uint8_t irq, irq_handler handler);
uint64_t irq_dispatch_count(uint8_t irq);
uint64_t irq_unhandled_count(uint8_t irq);

/* Dynamic CPU Exception (vectors 0 to 31) APIs */
int exception_register_handler(uint8_t vector, exception_handler_t handler);
int exception_unregister_handler(uint8_t vector, exception_handler_t handler);
exception_handler_t exception_get_handler(uint8_t vector);
uint64_t exception_dispatch_count(uint8_t vector);

/* Self-test and verification */
bool exception_self_test(void);
uint8_t idt_get_gate_ist(uint8_t vector);
void idt_initialize(void);
void idt_reload(void);

#endif /* KOS_INTERRUPTS_H */
