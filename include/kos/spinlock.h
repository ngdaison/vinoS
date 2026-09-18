#ifndef KOS_SPINLOCK_H
#define KOS_SPINLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/cpu.h>
#include <kos/atomic.h>

/* RFLAGS Interrupt Flag bitmask (Bit 9) */
#define KOS_RFLAGS_IF (1ULL << 9)

/* Spinlock state constants */
#define KOS_SPINLOCK_UNLOCKED 0U
#define KOS_SPINLOCK_LOCKED   1U
#define KOS_SPINLOCK_NO_CPU   0xFFFFFFFFU

/*
 * Spinlock Structure (K12.6):
 * - lock / state: 32-bit atomic variable (0 = unlocked, 1 = locked).
 *   Anonymous union provides 100% backward compatibility with legacy struct kos_spinlock.
 * - owner_cpu: ID of the CPU core holding the lock.
 * - last_rip: Instruction pointer of the caller that acquired the lock.
 * - lock_count: Total successful acquisitions.
 */
typedef struct kos_spinlock {
    union {
        volatile uint32_t lock;
        volatile uint32_t state;
    };
    volatile uint32_t owner_cpu;
    volatile uint64_t last_rip;
    volatile uint64_t lock_count;
} kos_spinlock_t;

typedef kos_spinlock_t spinlock_t;

/* Static Initializer */
#define SPINLOCK_INIT \
    { .lock = KOS_SPINLOCK_UNLOCKED, .owner_cpu = KOS_SPINLOCK_NO_CPU, .last_rip = 0, .lock_count = 0 }

#define KOS_SPINLOCK_INIT SPINLOCK_INIT
#define KOS_SPINLOCK_INITIALIZER SPINLOCK_INIT

/* Core Spinlock API */
void spinlock_init(kos_spinlock_t *lock);
void spinlock_lock(kos_spinlock_t *lock);
bool spinlock_try_lock(kos_spinlock_t *lock);
void spinlock_unlock(kos_spinlock_t *lock);
uint64_t spinlock_lock_irqsave(kos_spinlock_t *lock);
void spinlock_unlock_irqrestore(kos_spinlock_t *lock, uint64_t flags);
bool spinlock_try_lock_irqsave(kos_spinlock_t *lock, uint64_t *flags_out);

/* Query lock status */
static inline bool spinlock_is_locked(const kos_spinlock_t *lock) {
    if (lock == NULL) {
        return false;
    }
    return __atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != KOS_SPINLOCK_UNLOCKED;
}

/* Query if CPU interrupts are currently enabled on this core */
static inline bool spinlock_irqs_enabled(void) {
    uint64_t flags;
    __asm__ volatile ("pushfq; popq %0" : "=r"(flags) : : "memory");
    return (flags & KOS_RFLAGS_IF) != 0;
}

#endif /* KOS_SPINLOCK_H */
