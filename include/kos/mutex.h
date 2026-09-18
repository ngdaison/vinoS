#ifndef KOS_MUTEX_H
#define KOS_MUTEX_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/list.h>
#include <kos/spinlock.h>

struct kos_mutex {
    kos_spinlock_t wait_lock;       /* Protects wait_list and internal state */
    volatile uint32_t state;         /* 0 = unlocked, 1 = locked */
    volatile uint32_t owner_tid;     /* TID of holding thread, 0 if free */
    struct list_head wait_list;      /* Queue of waiting threads */
    volatile uint32_t waiters_count; /* Count of threads queued in wait_list */
};

typedef struct kos_mutex kos_mutex_t;
typedef struct kos_mutex mutex_t;

/* Static Initializers */
#define KOS_MUTEX_INIT(name) { \
    .wait_lock = SPINLOCK_INIT, \
    .state = 0, \
    .owner_tid = 0, \
    .wait_list = { &(name).wait_list, &(name).wait_list }, \
    .waiters_count = 0, \
}

#define MUTEX_INIT(name) KOS_MUTEX_INIT(name)

#define DEFINE_MUTEX(name) \
    kos_mutex_t name = KOS_MUTEX_INIT(name)

/* Core Mutex APIs */
void mutex_init(kos_mutex_t *mutex);
void mutex_lock(kos_mutex_t *mutex);
bool mutex_try_lock(kos_mutex_t *mutex);
void mutex_unlock(kos_mutex_t *mutex);

/* Diagnostic & State Queries */
bool mutex_is_locked(const kos_mutex_t *mutex);
uint32_t mutex_get_owner(const kos_mutex_t *mutex);
uint32_t mutex_waiters_count(const kos_mutex_t *mutex);

#endif /* KOS_MUTEX_H */
