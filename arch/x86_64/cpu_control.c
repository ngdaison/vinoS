#include <stdint.h>

#include <kos/cpu.h>
#include <kos/io.h>

enum {
    PS2_CONTROLLER_STATUS = 0x64,
    PS2_CONTROLLER_INPUT_BUFFER_FULL = 0x02,
    PS2_CONTROLLER_RESET = 0xfe,
    PS2_RESET_SPIN_LIMIT = 1000000,
};

KOS_NORETURN void cpu_halt(void) {
    __asm__ volatile ("cli");
    for (;;) {
        __asm__ volatile ("hlt");
    }
}

KOS_NORETURN void cpu_idle(void) {
    for (;;) {
        __asm__ volatile ("sti; hlt" : : : "memory");
    }
}

KOS_NORETURN void cpu_reboot(void) {
    for (uint64_t spin = 0; spin < PS2_RESET_SPIN_LIMIT; ++spin) {
        if ((io_in8(PS2_CONTROLLER_STATUS) & PS2_CONTROLLER_INPUT_BUFFER_FULL) == 0) {
            io_out8(PS2_CONTROLLER_STATUS, PS2_CONTROLLER_RESET);
            break;
        }
    }
    cpu_halt();
}

void cpu_enable_interrupts(void) {
    __asm__ volatile ("sti" : : : "memory");
}

void cpu_wait_for_interrupt(void) {
    __asm__ volatile ("hlt" : : : "memory");
}

void cpu_pause(void) {
    __asm__ volatile ("pause" : : : "memory");
}

uint64_t cpu_interrupt_save_disable(void) {
    uint64_t flags;
    __asm__ volatile ("pushfq; popq %0; cli" : "=r"(flags) : : "memory");
    return flags;
}

void cpu_interrupt_restore(uint64_t flags) {
    if ((flags & (1ull << 9)) != 0) {
        __asm__ volatile ("sti" : : : "memory");
    }
    else {
        __asm__ volatile ("cli" : : : "memory");
    }
}

uint64_t cpu_read_cr2(void) {
    uint64_t value;
    __asm__ volatile ("mov %%cr2, %0" : "=r"(value));
    return value;
}

uint64_t cpu_read_cr3(void) {
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

void cpu_write_cr3(uint64_t cr3) {
    __asm__ volatile ("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

void cpu_invalidate_page(uint64_t virtual_address) {
    __asm__ volatile ("invlpg (%0)" : : "r"(virtual_address) : "memory");
}

KOS_NOINLINE KOS_OPTNONE void cpu_trigger_divide_by_zero(void) {
    volatile uint64_t numerator = 1;
    volatile uint64_t denominator = 0;
    volatile uint64_t result = numerator / denominator;
    (void)result;
}
