#include <kos/spinlock.h>
#include <kos/cpu.h>
#include <kos/task.h>

/*
 * Low-level spinlock acquisition engine.
 * Records the explicit caller RIP to ensure accurate diagnostics
 * regardless of intermediate wrapper layers (such as spinlock_lock_irqsave).
 */
static void spinlock_lock_internal(kos_spinlock_t *lock, uint64_t caller_rip) {
    if (lock == NULL) {
        return;
    }

    for (;;) {
        /*
         * Optimistic acquisition: Test-and-Set with ACQUIRE semantics.
         * Returns previous value: if 0, lock is successfully acquired.
         */
        if (__atomic_exchange_n(&lock->lock, KOS_SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == KOS_SPINLOCK_UNLOCKED) {
            lock->owner_cpu = 0; /* Core 0 for current single-core bootstrap */
            lock->last_rip = caller_rip;
            lock->lock_count++;
            return;
        }

        /*
         * Contention loop: Test-and-Test-and-Set (TTAS).
         * Spins on local cache line using relaxed loads and pause instruction.
         * Prevents cache line bouncing and reduces memory bus contention.
         */
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != KOS_SPINLOCK_UNLOCKED) {
            cpu_relax();
        }
    }
}

void spinlock_init(kos_spinlock_t *lock) {
    if (lock == NULL) {
        return;
    }
    __atomic_store_n(&lock->lock, KOS_SPINLOCK_UNLOCKED, __ATOMIC_RELAXED);
    lock->owner_cpu = KOS_SPINLOCK_NO_CPU;
    lock->last_rip = 0;
    lock->lock_count = 0;
}

void spinlock_lock(kos_spinlock_t *lock) {
    preempt_disable();
    spinlock_lock_internal(lock, (uint64_t)__builtin_return_address(0));
}

bool spinlock_try_lock(kos_spinlock_t *lock) {
    if (lock == NULL) {
        return false;
    }

    preempt_disable();

    /* Fast check without asserting bus lock */
    if (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != KOS_SPINLOCK_UNLOCKED) {
        preempt_enable();
        return false;
    }

    if (__atomic_exchange_n(&lock->lock, KOS_SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == KOS_SPINLOCK_UNLOCKED) {
        lock->owner_cpu = 0;
        lock->last_rip = (uint64_t)__builtin_return_address(0);
        lock->lock_count++;
        return true;
    }

    preempt_enable();
    return false;
}

void spinlock_unlock(kos_spinlock_t *lock) {
    if (lock == NULL) {
        return;
    }

    lock->owner_cpu = KOS_SPINLOCK_NO_CPU;
    lock->last_rip = 0;

    /* Release store ensures memory visibility before resetting lock state */
    __atomic_store_n(&lock->lock, KOS_SPINLOCK_UNLOCKED, __ATOMIC_RELEASE);
    preempt_enable();
}

uint64_t spinlock_lock_irqsave(kos_spinlock_t *lock) {
    /* 1. Disable local interrupts first to prevent ISR re-entrancy deadlock */
    uint64_t flags = cpu_interrupt_save_disable();

    preempt_disable();

    /* 2. Acquire lock with caller's return address recorded */
    spinlock_lock_internal(lock, (uint64_t)__builtin_return_address(0));

    return flags;
}

void spinlock_unlock_irqrestore(kos_spinlock_t *lock, uint64_t flags) {
    /* 1. Release lock first so critical section is completely exited */
    if (lock != NULL) {
        lock->owner_cpu = KOS_SPINLOCK_NO_CPU;
        lock->last_rip = 0;
        __atomic_store_n(&lock->lock, KOS_SPINLOCK_UNLOCKED, __ATOMIC_RELEASE);
    }

    /* 2. Restore saved RFLAGS interrupt enablement state */
    cpu_interrupt_restore(flags);

    /* 3. Re-enable preemption (triggers deferred reschedule if preempt_count hits 0) */
    preempt_enable();
}

bool spinlock_try_lock_irqsave(kos_spinlock_t *lock, uint64_t *flags_out) {
    if (flags_out == NULL) {
        return false;
    }

    uint64_t flags = cpu_interrupt_save_disable();
    preempt_disable();

    if (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) == KOS_SPINLOCK_UNLOCKED &&
        __atomic_exchange_n(&lock->lock, KOS_SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == KOS_SPINLOCK_UNLOCKED) {
        lock->owner_cpu = 0;
        lock->last_rip = (uint64_t)__builtin_return_address(0);
        lock->lock_count++;
        *flags_out = flags;
        return true;
    }

    preempt_enable();
    cpu_interrupt_restore(flags);
    return false;
}
