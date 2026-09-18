#include <kos/mutex.h>
#include <kos/task.h>
#include <kos/log.h>
#include <kos/cpu.h>

struct mutex_waiter {
    struct list_head node;
    struct task *task;
    uint32_t tid;
    volatile bool granted;
};

void mutex_init(kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return;
    }
    spinlock_init(&mutex->wait_lock);
    mutex->state = 0;
    mutex->owner_tid = 0;
    list_init(&mutex->wait_list);
    mutex->waiters_count = 0;
}

void mutex_lock(kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return;
    }

    uint32_t my_tid = (uint32_t)task_current_tid();

    /*
     * Fast Path:
     * Uncontended lock acquisition.
     * Atomically transition state 0 -> 1 using acquire memory semantics.
     * If waiters_count > 0, we must take the slow path to avoid barging
     * in front of already queued threads.
     */
    if (__atomic_load_n(&mutex->waiters_count, __ATOMIC_RELAXED) == 0) {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            mutex->owner_tid = my_tid;
            return;
        }
    }

    /*
     * Error checking & recursion detection:
     * If the current thread already holds this mutex, locking again would
     * cause self-deadlock. Reject recursion.
     */
    if (mutex->owner_tid == my_tid && my_tid != 0) {
        log_warnf("mutex_lock: recursion detected! TID %u already owns mutex %p",
                  my_tid, (void *)mutex);
        return;
    }

    /*
     * Early boot / single-thread safeguard:
     * If multitasking has not yet started, the thread cannot sleep
     * (no other task could ever wake it up).
     */
    if (!task_is_multitasking_active()) {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            mutex->owner_tid = my_tid;
            return;
        }
        for (uint32_t spin = 0; spin < 10000; ++spin) {
            cpu_pause();
            expected = 0;
            if (__atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                mutex->owner_tid = my_tid;
                return;
            }
        }
        log_warnf("mutex_lock: early-boot lock contention unresolved for mutex %p", (void *)mutex);
        return;
    }

    /*
     * Slow Path:
     * Contended path. Acquire internal spinlock (with irqsave) to manipulate
     * the wait queue and thread state atomically.
     */
    uint64_t flags = spinlock_lock_irqsave(&mutex->wait_lock);

    /* Defensive self-healing if mutex was zero-initialized ({0}) */
    if (mutex->wait_list.next == NULL) {
        list_init(&mutex->wait_list);
    }

    /* Check if lock became free while acquiring wait_lock */
    if (mutex->state == 0 && list_empty(&mutex->wait_list)) {
        mutex->state = 1;
        mutex->owner_tid = my_tid;
        spinlock_unlock_irqrestore(&mutex->wait_lock, flags);
        return;
    }

    /* Allocate waiter node on current thread's stack */
    struct mutex_waiter waiter;
    waiter.task = task_current();
    waiter.tid = my_tid;
    waiter.granted = false;

    list_add_tail(&waiter.node, &mutex->wait_list);
    mutex->waiters_count++;

    /* Loop until ownership is transferred to us */
    while (!waiter.granted) {
        /* Mark current task as BLOCKED using task_block */
        task_block(waiter.task);

        /*
         * Release spinlock BEFORE switching context so interrupts are restored
         * and other threads can acquire wait_lock or call mutex_unlock.
         */
        spinlock_unlock_irqrestore(&mutex->wait_lock, flags);

        /* Yield CPU to another runnable task */
        schedule();

        /* Re-acquire spinlock to check granted flag */
        flags = spinlock_lock_irqsave(&mutex->wait_lock);

        /* Deadlock safeguard: if no other tasks exist, reclaim if free */
        if (!waiter.granted && mutex->state == 0 &&
            (list_empty(&mutex->wait_list) || list_first_entry(&mutex->wait_list, struct mutex_waiter, node) == &waiter)) {
            list_del(&waiter.node);
            if (mutex->waiters_count > 0) {
                mutex->waiters_count--;
            }
            mutex->state = 1;
            mutex->owner_tid = my_tid;
            waiter.granted = true;
            break;
        }
    }

    spinlock_unlock_irqrestore(&mutex->wait_lock, flags);
}

void mutex_unlock(kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return;
    }

    uint32_t my_tid = (uint32_t)task_current_tid();

    /*
     * Error checking:
     * Cannot unlock a mutex that is not locked, or locked by another thread.
     */
    if (mutex->state == 0) {
        log_warnf("mutex_unlock: attempt to unlock already unlocked mutex %p", (void *)mutex);
        return;
    }

    if (mutex->owner_tid != my_tid && mutex->owner_tid != 0 && my_tid != 0) {
        log_warnf("mutex_unlock: TID %u attempting to unlock mutex %p held by TID %u",
                  my_tid, (void *)mutex, mutex->owner_tid);
        return;
    }

    /*
     * Fast Path:
     * If no threads are waiting, clear owner and atomically release lock.
     */
    if (__atomic_load_n(&mutex->waiters_count, __ATOMIC_RELAXED) == 0) {
        mutex->owner_tid = 0;
        __atomic_store_n(&mutex->state, 0, __ATOMIC_RELEASE);

        /* Double check if a waiter arrived right during release */
        if (__atomic_load_n(&mutex->waiters_count, __ATOMIC_RELAXED) == 0) {
            return;
        }
    }

    /*
     * Slow Path:
     * Wake up the next waiting thread and transfer ownership.
     */
    uint64_t flags = spinlock_lock_irqsave(&mutex->wait_lock);

    if (mutex->wait_list.next == NULL) {
        list_init(&mutex->wait_list);
    }

    if (list_empty(&mutex->wait_list)) {
        mutex->owner_tid = 0;
        mutex->waiters_count = 0;
        __atomic_store_n(&mutex->state, 0, __ATOMIC_RELEASE);
        spinlock_unlock_irqrestore(&mutex->wait_lock, flags);
        return;
    }

    /* Dequeue head waiter (FIFO order) */
    struct mutex_waiter *next_waiter = list_first_entry(&mutex->wait_list, struct mutex_waiter, node);
    list_del(&next_waiter->node);
    if (mutex->waiters_count > 0) {
        mutex->waiters_count--;
    }

    /*
     * Direct Ownership Handover:
     * Transfer lock ownership directly to next_waiter.
     * Keep mutex->state = 1 so external threads cannot steal it.
     */
    mutex->owner_tid = next_waiter->tid;
    mutex->state = 1;
    next_waiter->granted = true;

    /* Make the waiting thread RUNNABLE */
    if (next_waiter->task != NULL) {
        task_unblock(next_waiter->task);
    }

    spinlock_unlock_irqrestore(&mutex->wait_lock, flags);
}

bool mutex_try_lock(kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return false;
    }

    uint32_t my_tid = (uint32_t)task_current_tid();

    /* Recursion rejection */
    if (mutex->owner_tid == my_tid && my_tid != 0) {
        return false;
    }

    /* Do not steal if there are queued waiters */
    if (__atomic_load_n(&mutex->waiters_count, __ATOMIC_RELAXED) != 0) {
        return false;
    }

    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        mutex->owner_tid = my_tid;
        return true;
    }

    return false;
}

bool mutex_is_locked(const kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return false;
    }
    return __atomic_load_n(&mutex->state, __ATOMIC_RELAXED) != 0;
}

uint32_t mutex_get_owner(const kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return 0;
    }
    return mutex->owner_tid;
}

uint32_t mutex_waiters_count(const kos_mutex_t *mutex) {
    if (mutex == NULL) {
        return 0;
    }
    return __atomic_load_n(&mutex->waiters_count, __ATOMIC_RELAXED);
}
