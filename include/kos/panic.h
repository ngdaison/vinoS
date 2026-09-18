#ifndef KOS_PANIC_H
#define KOS_PANIC_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <kos/compiler.h>
#include <kos/interrupts.h>

/*
 * ============================================================================
 * KOS Kernel Panic Subsystem (K12.3 & K12.4)
 *
 * Guarantees:
 * 1. ZERO dynamic memory allocation (kmalloc/malloc are NEVER called).
 * 2. ZERO mutex acquisition and ZERO sleeping locks (deadlock avoidance).
 * 3. Lockless atomic recursion latch (immediate COM1 emergency halt on re-entry).
 * 4. Complete register dump: RAX..R15, RIP, CS, RFLAGS, RSP, SS, CR2, CR3.
 * 5. Stack frame unwinding with canonical and bounds verification.
 * 6. Dual output to COM1 serial (polling) and Framebuffer console.
 * 7. Permanent interrupt disable and clean infinite halt.
 * ============================================================================
 */

/* Explicit software panic */
KOS_NORETURN void panic(const char *fmt, ...)
    __attribute__((__format__(__printf__, 1, 2)));

/* Exception panic with saved interrupt context */
KOS_NORETURN void panic_with_context(const struct interrupt_context *context, const char *fmt, ...)
    __attribute__((__format__(__printf__, 2, 3)));

/* Varargs format variant */
KOS_NORETURN void panic_vformat(const struct interrupt_context *context, const char *fmt, va_list args);

/* Raw message panic */
KOS_NORETURN void panic_with_message(const char *message);

/* Compatibility adapter matching PROJECT.md interface contract */
KOS_NORETURN void kernel_panic(const char *message, const struct interrupt_context *context);

/* Panic state queries */
bool panic_is_active(void);
uint32_t panic_get_recursion_count(void);

/* Intentional recursion trigger for testing recursion guard */
KOS_NORETURN void panic_test_recursion(void);

/* Stack backtrace interfaces (K12.4) */
void stack_trace(uint64_t rbp, uint64_t max_depth);
void stack_trace_with_ip(uint64_t rip, uint64_t rbp, uint64_t max_depth);
void stack_trace_from_context(const struct interrupt_context *ctx, uint64_t max_depth);
void stack_trace_dump_current(uint64_t max_depth);

/* Kernel assertion macro */
#define KOS_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            panic("Assertion failed: (%s) at %s:%d in %s()", \
                  #expr, __FILE__, __LINE__, __func__); \
        } \
    } while (0)

#endif /* KOS_PANIC_H */
