#include <stdbool.h>
#include <stdint.h>

#include <kos/atomic.h>
#include <kos/cpu.h>
#include <kos/io.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    PIT_CHANNEL_0_DATA = 0x40,
    PIT_COMMAND = 0x43,
    PIT_INPUT_FREQUENCY_HZ = 1193182,
    PIT_COMMAND_CHANNEL_0_LOHI_MODE_3 = 0x36,
    PIT_MIN_DIVISOR = 1,
    PIT_MAX_DIVISOR = 65536,
};

static atomic64_t s_timer_ticks = ATOMIC64_INIT(0);
static atomic_t s_timer_frequency = ATOMIC_INIT(0);
static volatile bool s_timer_initialized = false;

/* Check whether local CPU interrupts (RFLAGS.IF) are enabled */
static inline bool timer_irqs_enabled(void) {
    uint64_t flags;
    __asm__ volatile ("pushfq; popq %0" : "=r"(flags) : : "memory");
    return (flags & (1ull << 9)) != 0;
}

/*
 * Calibrated busy-wait fallback loop when interrupts are disabled
 * or timer has not yet been initialized.
 * Reading port 0x80 (standard diagnostic POST port) takes ~1 microsecond on PC hardware.
 * 1000 reads to port 0x80 yields approximately 1 millisecond.
 */
static void timer_busy_wait_ms(uint64_t ms) {
    for (uint64_t m = 0; m < ms; ++m) {
        for (uint32_t i = 0; i < 1000; ++i) {
            (void)io_in8(0x80);
        }
    }
}

bool timer_initialize(uint32_t frequency_hz) {
    if (frequency_hz == 0) {
        return false;
    }
    uint64_t divisor = (PIT_INPUT_FREQUENCY_HZ + frequency_hz / 2) / frequency_hz;
    if (divisor < PIT_MIN_DIVISOR || divisor > PIT_MAX_DIVISOR) {
        return false;
    }

    io_out8(PIT_COMMAND, PIT_COMMAND_CHANNEL_0_LOHI_MODE_3);
    io_out8(PIT_CHANNEL_0_DATA, (uint8_t)divisor);
    io_out8(PIT_CHANNEL_0_DATA, (uint8_t)(divisor >> 8));

    atomic64_set(&s_timer_ticks, 0);
    atomic_set(&s_timer_frequency, (int32_t)frequency_hz);
    s_timer_initialized = true;
    return true;
}

void timer_init(uint32_t frequency_hz) {
    (void)timer_initialize(frequency_hz);
}

bool timer_is_initialized(void) {
    return s_timer_initialized;
}

void timer_interrupt(void) {
    if (s_timer_initialized) {
        atomic64_inc(&s_timer_ticks);
    }
}

uint64_t timer_get_ticks(void) {
    return (uint64_t)atomic64_read(&s_timer_ticks);
}

uint32_t timer_frequency_hz(void) {
    return (uint32_t)atomic_read(&s_timer_frequency);
}

uint64_t timer_ms_to_ticks(uint64_t ms) {
    uint32_t hz = timer_frequency_hz();
    if (hz == 1000) {
        return ms;
    }
    if (hz == 0) {
        return 0;
    }
    if (ms > UINT64_MAX / (uint64_t)hz) {
        return UINT64_MAX;
    }
    return (ms * (uint64_t)hz) / 1000ULL;
}

uint64_t timer_ticks_to_ms(uint64_t ticks) {
    uint32_t hz = timer_frequency_hz();
    if (hz == 1000) {
        return ticks;
    }
    if (hz == 0) {
        return 0;
    }
    if (ticks > UINT64_MAX / 1000ULL) {
        return (ticks / (uint64_t)hz) * 1000ULL;
    }
    return (ticks * 1000ULL) / (uint64_t)hz;
}

uint64_t timer_get_uptime_ms(void) {
    return timer_ticks_to_ms(timer_get_ticks());
}

uint64_t timer_uptime_seconds(void) {
    return timer_get_uptime_ms() / 1000ULL;
}

void timer_delay_ms(uint64_t ms) {
    if (ms == 0) {
        return;
    }

    /* Fallback 1: Interrupts disabled or timer driver not initialized -> Calibrated busy wait */
    if (!s_timer_initialized || !timer_irqs_enabled()) {
        timer_busy_wait_ms(ms);
        return;
    }

    /* Multitasking active -> Yield/Sleep cooperative or preemptive thread */
    if (task_is_multitasking_active()) {
        task_sleep(ms);
        return;
    }

    /* Fallback 2: Multitasking not active yet, but interrupts are enabled (early boot self-tests) */
    uint64_t target_ticks = timer_ms_to_ticks(ms);
    if (target_ticks == 0) {
        target_ticks = 1;
    }
    uint64_t start = timer_get_ticks();
    while (timer_get_ticks() - start < target_ticks) {
        cpu_wait_for_interrupt();
    }
}

void timer_wait_ticks(uint64_t requested_ticks) {
    if (requested_ticks == 0) {
        return;
    }
    if (!s_timer_initialized || !timer_irqs_enabled()) {
        uint64_t ms = timer_ticks_to_ms(requested_ticks);
        timer_busy_wait_ms(ms > 0 ? ms : 1);
        return;
    }
    uint64_t start = timer_get_ticks();
    while (timer_get_ticks() - start < requested_ticks) {
        if (task_is_multitasking_active()) {
            task_yield();
        } else {
            cpu_wait_for_interrupt();
        }
    }
}
