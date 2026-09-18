#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/compiler.h>
#include <kos/console.h>
#include <kos/cpu.h>
#include <kos/interrupts.h>
#include <kos/log.h>
#include <kos/panic.h>
#include <kos/serial.h>
#include <kos/symbol.h>
#include <kos/timer.h>

/* Forward-compatible weak linkage for Task ID query */
extern uint64_t task_get_current_tid(void) __attribute__((weak));

/* Lockless atomic recursion latch and state flags */
static volatile uint32_t s_panic_recursion = 0;
static volatile bool s_force_recursion_test = false;

bool panic_is_active(void) {
    return s_panic_recursion > 0;
}

uint32_t panic_get_recursion_count(void) {
    return s_panic_recursion;
}

static void panic_puts(const char *str) {
    if (str == NULL) {
        return;
    }
    serial_emergency_puts(str);
    if (console_is_initialized()) {
        console_write(str);
    }
}

static void panic_printf(const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    int len = kvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        panic_puts(buf);
    }
}

static inline bool is_canonical_address(uint64_t addr) {
    return (addr <= 0x00007FFFFFFFFFFFULL) || (addr >= 0xFFFF800000000000ULL);
}

static inline bool is_canonical_range(uint64_t addr, uint64_t size) {
    if (size == 0) {
        return is_canonical_address(addr);
    }
    uint64_t end = addr + size - 1;
    if (end < addr) {
        return false;
    }
    return is_canonical_address(addr) && is_canonical_address(end);
}

static void print_trace_line(const char *line) {
    panic_puts(line);
}

static void print_frame(uint32_t index, uint64_t rip, uint64_t rbp) {
    uint64_t offset = 0;
    const char *name = symbol_lookup(rip, &offset);
    if (name == NULL) {
        name = "<unknown>";
    }

    char line[160];
    ksnprintf(line, sizeof(line), "  #%02u  0x%016llx  in  %s+0x%llx (RBP: 0x%016llx)\r\n",
              index,
              (unsigned long long)rip,
              name,
              (unsigned long long)offset,
              (unsigned long long)rbp);
    print_trace_line(line);
}

void stack_trace_with_ip(uint64_t initial_rip, uint64_t initial_rbp, uint64_t max_depth) {
    if (max_depth == 0) {
        max_depth = 16;
    }

    print_trace_line("\r\n--- Call Trace / Stack Backtrace ---\r\n");

    uint32_t frame_index = 0;
    uint64_t current_rbp = initial_rbp;

    /* If initial_rip is supplied, print Frame #00 for the faulting/calling instruction */
    if (initial_rip != 0) {
        print_frame(frame_index++, initial_rip, current_rbp);
    }

    /* Unwind caller frames */
    while (frame_index < max_depth) {
        /* Check 1: Reject NULL or near-NULL (< 0x1000) */
        if (current_rbp < 0x1000ULL) {
            if (current_rbp != 0) {
                print_trace_line("  [Backtrace stopped: near-null frame pointer]\r\n");
            }
            break;
        }

        /* Check 2: Canonical address check for [RBP] and [RBP + 8] */
        if (!is_canonical_range(current_rbp, 16)) {
            print_trace_line("  [Backtrace stopped: non-canonical frame pointer]\r\n");
            break;
        }

        /* Check 3: 8-byte alignment verification */
        if ((current_rbp & 0x7ULL) != 0) {
            print_trace_line("  [Backtrace stopped: misaligned frame pointer]\r\n");
            break;
        }

        /* Safely dereference frame */
        uint64_t next_rbp = *(const volatile uint64_t *)current_rbp;
        uint64_t return_rip = *(const volatile uint64_t *)(current_rbp + 8ULL);

        /* Validate Return RIP */
        if (return_rip < 0x1000ULL || !is_canonical_address(return_rip)) {
            if (return_rip != 0) {
                char warn[160];
                ksnprintf(warn, sizeof(warn), "  #%02u  0x%016llx  in  <unknown>+0x0 (RBP: 0x%016llx) [invalid return address]\r\n",
                          frame_index, (unsigned long long)return_rip, (unsigned long long)current_rbp);
                print_trace_line(warn);
            }
            break;
        }

        /* Print caller frame */
        print_frame(frame_index++, return_rip, current_rbp);

        /* Check 4: Strict monotonicity check */
        if (next_rbp == 0) {
            /* Clean root termination (e.g. entry.asm root) */
            break;
        }
        if (next_rbp <= current_rbp) {
            print_trace_line("  [Backtrace stopped: non-monotonic frame pointer (cycle detected)]\r\n");
            break;
        }

        current_rbp = next_rbp;
    }

    if (frame_index >= max_depth) {
        print_trace_line("  [Backtrace truncated: reached maximum depth]\r\n");
    }
}

void stack_trace(uint64_t rbp, uint64_t max_depth) {
    stack_trace_with_ip(0, rbp, max_depth);
}

void stack_trace_from_context(const struct interrupt_context *ctx, uint64_t max_depth) {
    if (ctx == NULL) {
        uint64_t rbp;
        __asm__ volatile ("movq %%rbp, %0" : "=r"(rbp));
        stack_trace(rbp, max_depth);
    } else {
        stack_trace_with_ip(ctx->rip, ctx->rbp, max_depth);
    }
}

void stack_trace_dump_current(uint64_t max_depth) {
    uint64_t rbp;
    __asm__ volatile ("movq %%rbp, %0" : "=r"(rbp));
    stack_trace(rbp, max_depth);
}

static void panic_dump_raw_stack(uint64_t rsp, uint32_t count) {
    if (rsp < 0x1000ULL) {
        panic_puts("  [WARNING] RSP is NULL or in zero-page. Stack dump aborted.\r\n");
        return;
    }

    if (!is_canonical_address(rsp)) {
        panic_puts("  [WARNING] RSP is non-canonical address. Stack dump aborted.\r\n");
        return;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint64_t addr = rsp + ((uint64_t)i * sizeof(uint64_t));
        if (!is_canonical_range(addr, sizeof(uint64_t))) {
            break;
        }

        uint64_t value = *(const volatile uint64_t *)addr;
        panic_printf("  [RSP+0x%02X] 0x%016llX: 0x%016llX\r\n",
                     (unsigned int)(i * 8), (unsigned long long)addr, (unsigned long long)value);
    }
}

KOS_NORETURN void panic_test_recursion(void) {
    s_force_recursion_test = true;
    panic("Primary panic triggering deliberate recursion latch test");
}

KOS_NORETURN void panic_vformat(const struct interrupt_context *ctx, const char *fmt, va_list args) {
    /*
     * 1. LOCKLESS ATOMIC RECURSION LATCH
     */
    uint32_t recursion = __atomic_add_fetch(&s_panic_recursion, 1, __ATOMIC_SEQ_CST);
    if (recursion > 1) {
        serial_emergency_puts("\r\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n");
        serial_emergency_puts("CRITICAL: RECURSIVE KERNEL PANIC DETECTED!\r\n");
        serial_emergency_puts("Recursion count: ");
        serial_emergency_put_dec((uint64_t)recursion);
        serial_emergency_puts("\r\nImmediate CPU halt to prevent triple fault / crash loop.\r\n");
        serial_emergency_puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n");
        cpu_interrupt_save_disable();
        cpu_halt();
    }

    /* Check for deliberate recursion test trigger */
    if (s_force_recursion_test) {
        s_force_recursion_test = false;
        serial_emergency_puts("Deliberately triggering secondary panic to test recursion latch...\r\n");
        panic("Secondary recursive panic test");
    }

    /*
     * 2. DISABLE INTERRUPTS & ENTER EMERGENCY MODE
     */
    cpu_interrupt_save_disable();
    log_enter_emergency_mode();

    /*
     * 3. CONTEXT RECOVERY (if explicit panic)
     */
    struct interrupt_context captured_ctx;
    if (ctx == NULL) {
        for (size_t b = 0; b < sizeof(captured_ctx); ++b) {
            ((uint8_t *)&captured_ctx)[b] = 0;
        }
        __asm__ volatile (
            "movq %%r15,  0(%0)\n"
            "movq %%r14,  8(%0)\n"
            "movq %%r13, 16(%0)\n"
            "movq %%r12, 24(%0)\n"
            "movq %%r11, 32(%0)\n"
            "movq %%r10, 40(%0)\n"
            "movq %%r9,  48(%0)\n"
            "movq %%r8,  56(%0)\n"
            "movq %%rdi, 64(%0)\n"
            "movq %%rsi, 72(%0)\n"
            "movq %%rbp, 80(%0)\n"
            "movq %%rdx, 88(%0)\n"
            "movq %%rcx, 96(%0)\n"
            "movq %%rbx, 104(%0)\n"
            "movq %%rax, 112(%0)\n"
            : : "r"(&captured_ctx) : "memory"
        );
        captured_ctx.vector = 0xFF; /* Marker: explicit software panic */
        captured_ctx.error_code = 0;
        captured_ctx.rip = (uint64_t)(uintptr_t)__builtin_return_address(0);
        captured_ctx.rsp = (uint64_t)(uintptr_t)__builtin_frame_address(0) + 16;
        __asm__ volatile ("movq %%cs, %0" : "=r"(captured_ctx.cs));
        __asm__ volatile ("movq %%ss, %0" : "=r"(captured_ctx.ss));
        __asm__ volatile ("pushfq; popq %0" : "=r"(captured_ctx.rflags));
        ctx = &captured_ctx;
    }

    /*
     * 4. FORMAT PANIC REASON STRING
     */
    char reason[256];
    if (fmt != NULL) {
        kvsnprintf(reason, sizeof(reason), fmt, args);
    } else {
        reason[0] = '\0';
    }

    /*
     * 5. EMIT PANIC HEADER & SYSTEM STATE
     */
    panic_puts("\r\n============================== KERNEL PANIC ==============================\r\n");
    panic_printf("Reason : %s\r\n", reason[0] != '\0' ? reason : "Unspecified kernel condition");

    uint64_t uptime_sec = timer_uptime_seconds();
    uint64_t uptime_ms = timer_ticks() % 1000;
    uint64_t tid = (task_get_current_tid != NULL) ? task_get_current_tid() : 0;
    panic_printf("Uptime : %llu.%03llu s | CPU: 0 | Current TID: %llu\r\n",
                 (unsigned long long)uptime_sec, (unsigned long long)uptime_ms,
                 (unsigned long long)tid);

    if (ctx->vector != 0xFF) {
        panic_printf("Trigger: CPU Exception Vector 0x%02llX | Error Code: 0x%016llX\r\n",
                     (unsigned long long)ctx->vector, (unsigned long long)ctx->error_code);
    } else {
        panic_puts("Trigger: Explicit Software Panic (Kernel Assertion / Fatal Error)\r\n");
    }

    /*
     * 6. COMPLETE REGISTER & CONTEXT DUMP (2-column format)
     */
    panic_puts("-------------------------- CPU REGISTER DUMP ---------------------------\r\n");
    panic_printf("  RAX: 0x%016llX   RBX: 0x%016llX\r\n", (unsigned long long)ctx->rax, (unsigned long long)ctx->rbx);
    panic_printf("  RCX: 0x%016llX   RDX: 0x%016llX\r\n", (unsigned long long)ctx->rcx, (unsigned long long)ctx->rdx);
    panic_printf("  RSI: 0x%016llX   RDI: 0x%016llX\r\n", (unsigned long long)ctx->rsi, (unsigned long long)ctx->rdi);
    panic_printf("  RBP: 0x%016llX   RSP: 0x%016llX\r\n", (unsigned long long)ctx->rbp, (unsigned long long)ctx->rsp);
    panic_printf("  R8 : 0x%016llX   R9 : 0x%016llX\r\n", (unsigned long long)ctx->r8,  (unsigned long long)ctx->r9);
    panic_printf("  R10: 0x%016llX   R11: 0x%016llX\r\n", (unsigned long long)ctx->r10, (unsigned long long)ctx->r11);
    panic_printf("  R12: 0x%016llX   R13: 0x%016llX\r\n", (unsigned long long)ctx->r12, (unsigned long long)ctx->r13);
    panic_printf("  R14: 0x%016llX   R15: 0x%016llX\r\n", (unsigned long long)ctx->r14, (unsigned long long)ctx->r15);
    panic_printf("  RIP: 0x%016llX   CS : 0x%016llX\r\n", (unsigned long long)ctx->rip, (unsigned long long)ctx->cs);
    panic_printf("  RFL: 0x%016llX   SS : 0x%016llX\r\n", (unsigned long long)ctx->rflags, (unsigned long long)ctx->ss);

    uint64_t cr2 = cpu_read_cr2();
    uint64_t cr3 = cpu_read_cr3();
    panic_printf("  CR2: 0x%016llX   CR3: 0x%016llX\r\n", (unsigned long long)cr2, (unsigned long long)cr3);

    /*
     * 7. STACK BACKTRACE (K12.4)
     */
    stack_trace_with_ip(ctx->rip, ctx->rbp, 16);

    /*
     * 8. SAFE RAW STACK DUMP
     */
    panic_puts("------------------------------ RAW STACK -------------------------------\r\n");
    panic_dump_raw_stack(ctx->rsp, 16);

    /*
     * 9. CLEAN HALT
     */
    panic_puts("=========================================================================\r\n");
    panic_puts("System halted. Please reboot or inspect serial/QEMU logs.\r\n");
    cpu_interrupt_save_disable();
    cpu_halt();
}

KOS_NORETURN void panic(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    panic_vformat(NULL, fmt, args);
    va_end(args);
}

KOS_NORETURN void panic_with_context(const struct interrupt_context *ctx, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    panic_vformat(ctx, fmt, args);
    va_end(args);
}

KOS_NORETURN void panic_with_message(const char *message) {
    panic("%s", message);
}

KOS_NORETURN void kernel_panic(const char *message, const struct interrupt_context *ctx) {
    panic_with_context(ctx, "%s", message);
}
