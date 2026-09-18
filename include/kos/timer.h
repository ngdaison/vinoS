#ifndef KOS_TIMER_H
#define KOS_TIMER_H

#include <stdbool.h>
#include <stdint.h>

/* Standard PIT timer frequency for KOS: 1000 Hz (1 ms per tick) */
#define TIMER_HERTZ 1000U

/* Driver Lifecycle */
void timer_init(uint32_t frequency_hz);
bool timer_initialize(uint32_t frequency_hz);
bool timer_is_initialized(void);
void timer_interrupt(void);

/* Monotonic Counter */
uint64_t timer_get_ticks(void);
static inline uint64_t timer_ticks(void) {
    return timer_get_ticks();
}

/* Frequency & Conversion */
uint32_t timer_frequency_hz(void);
uint64_t timer_ms_to_ticks(uint64_t ms);
uint64_t timer_ticks_to_ms(uint64_t ticks);

/* Uptime */
uint64_t timer_get_uptime_ms(void);
uint64_t timer_uptime_seconds(void);

/* Delays */
void timer_delay_ms(uint64_t ms);
void timer_wait_ticks(uint64_t requested_ticks);

#endif /* KOS_TIMER_H */
