#ifndef KOS_WAIT_H
#define KOS_WAIT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/list.h>
#include <kos/spinlock.h>
#include <kos/object.h>
#include <kos/handle.h>
#include <kos/task.h>

/* Forward declarations */
struct process;

/* Wait Queue Entry Flags */
#define WQ_FLAG_EXCLUSIVE   (1U << 0)
#define WQ_FLAG_WOKEN       (1U << 1)

/*
 * Wait Queue Entry (K12.16):
 * Allocated on stack of waiting thread or embedded in custom waiters.
 */
struct wait_queue_entry {
    struct task *task;
    struct list_head node;
    uint32_t flags;
};

/*
 * Standard Wait Queue Subsystem (K12.16)
 */
struct wait_queue {
    kos_spinlock_t lock;
    struct list_head head;
    uint32_t waiter_count;
};

typedef struct wait_queue wait_queue_t;

#define WAIT_QUEUE_INIT(name) { \
    .lock = SPINLOCK_INIT, \
    .head = { &(name).head, &(name).head }, \
    .waiter_count = 0, \
}

#define DEFINE_WAIT_QUEUE(name) \
    struct wait_queue name = WAIT_QUEUE_INIT(name)

/* Core Wait Queue APIs */
void wait_queue_init(struct wait_queue *wq);
void wait_queue_add(struct wait_queue *wq, struct wait_queue_entry *entry);
void wait_queue_remove(struct wait_queue *wq, struct wait_queue_entry *entry);
void wait_queue_wake_one(struct wait_queue *wq);
void wait_queue_wake_all(struct wait_queue *wq);
void wait_event(struct wait_queue *wq, bool (*condition)(void *arg), void *arg);
bool wait_event_timeout(struct wait_queue *wq, bool (*condition)(void *arg), void *arg, uint64_t timeout_ms);

/*
 * Wait Queue Kernel Object Integration (K12.14 / K12.15)
 */
struct kos_wait_object {
    struct kos_object_header header;
    struct wait_queue wq;
};

struct kos_event_object {
    struct kos_object_header header;
    struct wait_queue wq;
    bool manual_reset;
    bool signaled;
    kos_spinlock_t lock;
};

/* Event Kernel Object APIs */
handle_t event_create(struct process *proc, bool manual_reset, bool initial_state);
bool event_signal(struct process *proc, handle_t handle);
bool event_reset(struct process *proc, handle_t handle);
bool event_wait(struct process *proc, handle_t handle, uint64_t timeout_ms);

/* Standalone Wait Queue Kernel Object APIs */
handle_t wait_queue_create_object(struct process *proc);

#endif /* KOS_WAIT_H */
