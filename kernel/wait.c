#include <kos/wait.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/cpu.h>
#include <kos/process.h>

void wait_queue_init(struct wait_queue *wq) {
    if (wq == NULL) {
        return;
    }
    spinlock_init(&wq->lock);
    list_init(&wq->head);
    wq->waiter_count = 0;
}

void wait_queue_add(struct wait_queue *wq, struct wait_queue_entry *entry) {
    if (wq == NULL || entry == NULL) {
        return;
    }
    if (wq->head.next == NULL) {
        list_init(&wq->head);
    }
    list_add_tail(&entry->node, &wq->head);
    wq->waiter_count++;
}

void wait_queue_remove(struct wait_queue *wq, struct wait_queue_entry *entry) {
    if (wq == NULL || entry == NULL) {
        return;
    }
    if (entry->node.next != NULL && entry->node.next != &entry->node) {
        list_del_init(&entry->node);
        if (wq->waiter_count > 0) {
            wq->waiter_count--;
        }
    }
}

void wait_queue_wake_one(struct wait_queue *wq) {
    if (wq == NULL) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&wq->lock);
    if (!list_empty(&wq->head)) {
        struct list_head *first = wq->head.next;
        struct wait_queue_entry *entry = list_entry(first, struct wait_queue_entry, node);
        list_del_init(&entry->node);
        if (wq->waiter_count > 0) {
            wq->waiter_count--;
        }
        entry->flags |= WQ_FLAG_WOKEN;
        if (entry->task != NULL) {
            task_unblock(entry->task);
            task_request_reschedule();
        }
    }
    spinlock_unlock_irqrestore(&wq->lock, flags);
}

void wait_queue_wake_all(struct wait_queue *wq) {
    if (wq == NULL) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&wq->lock);
    while (!list_empty(&wq->head)) {
        struct list_head *first = wq->head.next;
        struct wait_queue_entry *entry = list_entry(first, struct wait_queue_entry, node);
        list_del_init(&entry->node);
        if (wq->waiter_count > 0) {
            wq->waiter_count--;
        }
        entry->flags |= WQ_FLAG_WOKEN;
        if (entry->task != NULL) {
            task_unblock(entry->task);
        }
    }
    task_request_reschedule();
    spinlock_unlock_irqrestore(&wq->lock, flags);
}

void wait_event(struct wait_queue *wq, bool (*condition)(void *arg), void *arg) {
    if (wq == NULL) {
        return;
    }
    if (condition != NULL && condition(arg)) {
        return;
    }

    struct thread *cur = thread_current();
    if (cur == NULL || !task_is_multitasking_active()) {
        while (condition != NULL && !condition(arg)) {
            cpu_pause();
        }
        return;
    }

    struct wait_queue_entry entry;
    entry.task = cur;
    entry.flags = 0;
    list_init(&entry.node);

    for (;;) {
        uint64_t flags = spinlock_lock_irqsave(&wq->lock);
        if (condition != NULL && condition(arg)) {
            wait_queue_remove(wq, &entry);
            spinlock_unlock_irqrestore(&wq->lock, flags);
            break;
        }

        if (entry.node.next == NULL || entry.node.next == &entry.node) {
            wait_queue_add(wq, &entry);
        }

        task_block(cur);
        spinlock_unlock_irqrestore(&wq->lock, flags);

        schedule();
    }

    uint64_t flags = spinlock_lock_irqsave(&wq->lock);
    wait_queue_remove(wq, &entry);
    spinlock_unlock_irqrestore(&wq->lock, flags);
}

bool wait_event_timeout(struct wait_queue *wq, bool (*condition)(void *arg), void *arg, uint64_t timeout_ms) {
    if (wq == NULL) {
        return false;
    }
    if (condition != NULL && condition(arg)) {
        return true;
    }
    if (timeout_ms == 0) {
        return (condition != NULL && condition(arg));
    }

    struct thread *cur = thread_current();
    if (cur == NULL || !task_is_multitasking_active()) {
        uint64_t start = timer_get_ticks();
        uint64_t wait_ticks = timer_ms_to_ticks(timeout_ms);
        if (wait_ticks == 0) {
            wait_ticks = 1;
        }
        while (condition != NULL && !condition(arg)) {
            if (timer_get_ticks() - start >= wait_ticks) {
                return false;
            }
            cpu_pause();
        }
        return (condition != NULL && condition(arg));
    }

    uint64_t ticks_to_sleep = timer_ms_to_ticks(timeout_ms);
    if (ticks_to_sleep == 0) {
        ticks_to_sleep = 1;
    }
    uint64_t start_tick = timer_get_ticks();
    uint64_t deadline = start_tick + ticks_to_sleep;
    if (deadline < start_tick) {
        deadline = UINT64_MAX;
    }

    struct wait_queue_entry entry;
    entry.task = cur;
    entry.flags = 0;
    list_init(&entry.node);

    bool success = false;

    for (;;) {
        uint64_t flags = spinlock_lock_irqsave(&wq->lock);
        if (condition != NULL && condition(arg)) {
            wait_queue_remove(wq, &entry);
            spinlock_unlock_irqrestore(&wq->lock, flags);
            success = true;
            break;
        }

        uint64_t now = timer_get_ticks();
        if (now >= deadline) {
            wait_queue_remove(wq, &entry);
            spinlock_unlock_irqrestore(&wq->lock, flags);
            success = false;
            break;
        }

        if (entry.node.next == NULL || entry.node.next == &entry.node) {
            wait_queue_add(wq, &entry);
        }

        task_sleep_enqueue(cur, deadline);
        task_block(cur);

        spinlock_unlock_irqrestore(&wq->lock, flags);

        schedule();

        task_sleep_dequeue(cur);
    }

    task_sleep_dequeue(cur);

    uint64_t flags = spinlock_lock_irqsave(&wq->lock);
    wait_queue_remove(wq, &entry);
    spinlock_unlock_irqrestore(&wq->lock, flags);

    return success;
}

/*
 * Kernel Object Integration (K12.14 / K12.15)
 */

static void event_destructor(void *obj) {
    struct kos_event_object *ev = (struct kos_event_object *)obj;
    if (ev != NULL) {
        wait_queue_wake_all(&ev->wq);
        (void)kfree(ev);
    }
}

static void wait_queue_object_destructor(void *obj) {
    struct kos_wait_object *wo = (struct kos_wait_object *)obj;
    if (wo != NULL) {
        wait_queue_wake_all(&wo->wq);
        (void)kfree(wo);
    }
}

handle_t event_create(struct process *proc, bool manual_reset, bool initial_state) {
    if (proc == NULL) {
        return KOS_INVALID_HANDLE;
    }
    struct kos_event_object *ev = (struct kos_event_object *)kmalloc(sizeof(struct kos_event_object));
    if (ev == NULL) {
        return KOS_INVALID_HANDLE;
    }

    kos_object_init(&ev->header, KOS_OBJ_EVENT, event_destructor);
    wait_queue_init(&ev->wq);
    ev->manual_reset = manual_reset;
    ev->signaled = initial_state;
    spinlock_init(&ev->lock);

    handle_t h = handle_create(proc, &ev->header,
                               KOS_RIGHT_WAIT | KOS_RIGHT_SIGNAL |
                               KOS_RIGHT_READ | KOS_RIGHT_WRITE |
                               KOS_RIGHT_DUPLICATE | KOS_RIGHT_DESTROY);
    kos_object_unref(&ev->header);
    return h;
}

bool event_signal(struct process *proc, handle_t handle) {
    if (proc == NULL || handle == KOS_INVALID_HANDLE) {
        return false;
    }
    struct kos_event_object *ev = (struct kos_event_object *)handle_lookup_type(
        proc, handle, KOS_OBJ_EVENT, KOS_RIGHT_SIGNAL);
    if (ev == NULL) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&ev->lock);
    ev->signaled = true;
    if (ev->manual_reset) {
        wait_queue_wake_all(&ev->wq);
    } else {
        wait_queue_wake_one(&ev->wq);
        ev->signaled = false;
    }
    spinlock_unlock_irqrestore(&ev->lock, flags);
    return true;
}

bool event_reset(struct process *proc, handle_t handle) {
    if (proc == NULL || handle == KOS_INVALID_HANDLE) {
        return false;
    }
    struct kos_event_object *ev = (struct kos_event_object *)handle_lookup_type(
        proc, handle, KOS_OBJ_EVENT, KOS_RIGHT_SIGNAL);
    if (ev == NULL) {
        return false;
    }

    uint64_t flags = spinlock_lock_irqsave(&ev->lock);
    ev->signaled = false;
    spinlock_unlock_irqrestore(&ev->lock, flags);
    return true;
}

static bool event_check_condition(void *arg) {
    struct kos_event_object *ev = (struct kos_event_object *)arg;
    uint64_t flags = spinlock_lock_irqsave(&ev->lock);
    bool is_sig = ev->signaled;
    if (is_sig && !ev->manual_reset) {
        ev->signaled = false;
    }
    spinlock_unlock_irqrestore(&ev->lock, flags);
    return is_sig;
}

bool event_wait(struct process *proc, handle_t handle, uint64_t timeout_ms) {
    if (proc == NULL || handle == KOS_INVALID_HANDLE) {
        return false;
    }
    struct kos_event_object *ev = (struct kos_event_object *)handle_lookup_type(
        proc, handle, KOS_OBJ_EVENT, KOS_RIGHT_WAIT);
    if (ev == NULL) {
        return false;
    }

    if (timeout_ms == 0) {
        return event_check_condition(ev);
    } else if (timeout_ms == UINT64_MAX) {
        wait_event(&ev->wq, event_check_condition, ev);
        return true;
    } else {
        return wait_event_timeout(&ev->wq, event_check_condition, ev, timeout_ms);
    }
}

handle_t wait_queue_create_object(struct process *proc) {
    if (proc == NULL) {
        return KOS_INVALID_HANDLE;
    }
    struct kos_wait_object *wo = (struct kos_wait_object *)kmalloc(sizeof(struct kos_wait_object));
    if (wo == NULL) {
        return KOS_INVALID_HANDLE;
    }

    kos_object_init(&wo->header, KOS_OBJ_WAIT_QUEUE, wait_queue_object_destructor);
    wait_queue_init(&wo->wq);

    handle_t h = handle_create(proc, &wo->header,
                               KOS_RIGHT_WAIT | KOS_RIGHT_SIGNAL |
                               KOS_RIGHT_READ | KOS_RIGHT_DUPLICATE |
                               KOS_RIGHT_DESTROY);
    kos_object_unref(&wo->header);
    return h;
}
