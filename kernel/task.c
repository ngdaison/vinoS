#include <stdbool.h>
#include <stdint.h>

#include <kos/atomic.h>
#include <kos/compiler.h>
#include <kos/cpu.h>
#include <kos/descriptors.h>
#include <kos/heap.h>
#include <kos/list.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/process.h>
#include <kos/smp.h>
#include <kos/spinlock.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    TASK_SELF_TEST_ITERATIONS = 32,
    TASK_LOG_DEMO_ITERATIONS = 5,
};

struct task_self_test_counter {
    uint64_t count;
};

struct task_log_demo_state {
    const char *label;
    uint64_t count;
};

extern void task_switch(struct task_context *old, const struct task_context *next);

_Static_assert(__builtin_offsetof(struct task_context, rsp) == 48,
    "task_switch.asm expects rsp at offset 48");
_Static_assert(__builtin_offsetof(struct task_context, rip) == 56,
    "task_switch.asm expects rip at offset 56");
_Static_assert(__builtin_offsetof(struct task_context, rflags) == 64,
    "task_switch.asm expects rflags at offset 64");

static struct task tasks[TASK_MAX_COUNT];
static struct task *current_task;
static uint64_t next_task_id = 1;
static bool initialized;
static volatile bool reschedule_requested;

/* Dedicated Idle Task */
static uint8_t idle_stack[TASK_KERNEL_STACK_SIZE] KOS_ALIGNED(16);
struct task idle_task;

/* Sleep queue state */
static kos_spinlock_t sleep_lock = SPINLOCK_INIT;
static struct list_head sleep_queue = LIST_HEAD_INIT(sleep_queue);
static volatile uint64_t sleeping_task_count = 0;

static void sleep_queue_insert_sorted(struct task *task) {
    struct list_head *pos = sleep_queue.next;
    while (pos != &sleep_queue) {
        struct task *entry = list_entry(pos, struct task, sleep_node);
        if (task->sleep_target_tick < entry->sleep_target_tick) {
            __list_add(&task->sleep_node, pos->prev, pos);
            sleeping_task_count++;
            return;
        }
        pos = pos->next;
    }
    list_add_tail(&task->sleep_node, &sleep_queue);
    sleeping_task_count++;
}

void task_sleep_enqueue(struct task *task, uint64_t target_tick) {
    if (task == NULL) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&sleep_lock);
    if (task->sleep_node.next != NULL && task->sleep_node.next != &task->sleep_node) {
        list_del_init(&task->sleep_node);
        if (sleeping_task_count > 0) {
            sleeping_task_count--;
        }
    }
    task->sleep_target_tick = target_tick;
    sleep_queue_insert_sorted(task);
    spinlock_unlock_irqrestore(&sleep_lock, flags);
}

void task_sleep_dequeue(struct task *task) {
    if (task == NULL) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&sleep_lock);
    if (task->sleep_node.next != NULL && task->sleep_node.next != &task->sleep_node) {
        list_del_init(&task->sleep_node);
        if (sleeping_task_count > 0) {
            sleeping_task_count--;
        }
    }
    task->sleep_target_tick = 0;
    spinlock_unlock_irqrestore(&sleep_lock, flags);
}

uint64_t task_sleeping_count(void) {
    return __atomic_load_n(&sleeping_task_count, __ATOMIC_RELAXED);
}

static uint64_t task_index(const struct task *task) {
    return (uint64_t)(task - tasks);
}

static struct task *task_find_next_ready(void) {
    uint64_t start = (current_task >= tasks && current_task < tasks + TASK_MAX_COUNT)
                   ? task_index(current_task) : 0;
    for (uint64_t step = 1; step <= TASK_MAX_COUNT; ++step) {
        struct task *candidate = &tasks[(start + step) % TASK_MAX_COUNT];
        if (candidate->state == THREAD_STATE_RUNNABLE) {
            return candidate;
        }
    }
    return 0;
}

static bool task_release(struct task *task) {
    if (task == 0 || task == current_task || task->state == THREAD_STATE_RUNNING || task == &idle_task) {
        return false;
    }
    if (task->stack != 0 && task->stack != idle_stack && !kfree(task->stack)) {
        return false;
    }
    *task = (struct task){ .state = THREAD_STATE_UNUSED };
    return true;
}

void task_reap_terminated(void) {
    struct thread *reaper = reaper_get_thread();
    if (reaper != NULL && reaper->state == THREAD_STATE_BLOCKED) {
        task_unblock(reaper);
        task_yield();
    }
    for (uint64_t index = 1; index < TASK_MAX_COUNT; ++index) {
        if (tasks[index].state == THREAD_STATE_DEAD) {
            tasks[index].state = THREAD_STATE_UNUSED;
        }
    }
}

void task_start_trampoline(void) {
    current_task->entry(current_task->argument);
    thread_exit(0);
}

static void idle_task_entry(void *argument) {
    (void)argument;
    for (;;) {
        if (task_ready_count() > 0) {
            task_yield();
        }
        cpu_wait_for_interrupt();
    }
}

struct task *task_allocate_slot(void) {
    for (uint64_t index = 1; index < TASK_MAX_COUNT; ++index) {
        if (tasks[index].state == THREAD_STATE_UNUSED || tasks[index].state == THREAD_STATE_DEAD) {
            return &tasks[index];
        }
    }
    return NULL;
}

void task_free_slot(struct task *task) {
    if (task != NULL && task != &tasks[0] && task != &idle_task) {
        task->state = THREAD_STATE_UNUSED;
    }
}

uint64_t task_next_id(void) {
    return next_task_id++;
}

bool task_initialize(void) {
    if (initialized) {
        return false;
    }
    spinlock_init(&sleep_lock);
    list_init(&sleep_queue);
    sleeping_task_count = 0;

    for (uint64_t index = 0; index < TASK_MAX_COUNT; ++index) {
        tasks[index].state = THREAD_STATE_UNUSED;
        tasks[index].sleep_target_tick = 0;
        tasks[index].preempt_count = 0;
        tasks[index].reschedule_pending = false;
        tasks[index].quantum_remaining = TASK_DEFAULT_QUANTUM;
        tasks[index].stack = NULL;
        tasks[index].stack_size = 0;
        tasks[index].process = NULL;
        tasks[index].exit_code = 0;
        list_init(&tasks[index].sleep_node);
        list_init(&tasks[index].reaper_node);
        list_init(&tasks[index].process_node);
    }

    /* Bootstrap task (TID 1) */
    tasks[0].name = "bootstrap";
    tasks[0].state = THREAD_STATE_RUNNING;
    tasks[0].tid = next_task_id++;
    tasks[0].id = tasks[0].tid;
    tasks[0].sleep_target_tick = 0;
    tasks[0].preempt_count = 0;
    tasks[0].reschedule_pending = false;
    tasks[0].quantum_remaining = TASK_DEFAULT_QUANTUM;
    tasks[0].context.rflags = 0x202;
    tasks[0].stack = NULL;
    tasks[0].stack_size = 16384;
    list_init(&tasks[0].sleep_node);
    list_init(&tasks[0].reaper_node);
    list_init(&tasks[0].process_node);
    current_task = &tasks[0];

    /* Dedicated Idle task (TID 0) */
    uint64_t idle_stack_top = ((uint64_t)idle_stack + sizeof(idle_stack)) & ~0xfull;
    idle_stack_top -= sizeof(uint64_t);
    *(uint64_t *)idle_stack_top = 0;
    idle_task = (struct task){
        .context = {
            .rsp = idle_stack_top,
            .rip = (uint64_t)task_start_trampoline,
            .rflags = 0x202,
        },
        .entry = idle_task_entry,
        .argument = 0,
        .stack = idle_stack,
        .stack_size = sizeof(idle_stack),
        .name = "idle",
        .state = THREAD_STATE_RUNNABLE,
        .tid = 0,
        .id = 0,
        .sleep_target_tick = 0,
        .preempt_count = 0,
        .reschedule_pending = false,
        .quantum_remaining = TASK_DEFAULT_QUANTUM,
        .exit_code = 0,
    };
    list_init(&idle_task.sleep_node);
    list_init(&idle_task.reaper_node);
    list_init(&idle_task.process_node);

    initialized = true;

    /* Initialize process subsystem (creates idle process, kernel process, and reaper thread) */
    process_subsystem_init();

    return true;
}

bool task_create_kernel(const char *name, task_entry entry, void *argument) {
    if (!initialized || name == 0 || entry == 0) {
        return false;
    }
    return thread_create(process_get_kernel(), entry, argument, name) != NULL;
}

void schedule(void) {
    if (!initialized) {
        return;
    }

    uint64_t flags = cpu_interrupt_save_disable();

    struct task *next = task_find_next_ready();
    __atomic_store_n(&reschedule_requested, false, __ATOMIC_RELAXED);

    if (next == 0) {
        /* No runnable tasks found in tasks[] */
        if (current_task != 0 && current_task->state == THREAD_STATE_RUNNING && current_task != &idle_task) {
            cpu_interrupt_restore(flags);
            return;
        }

        if (current_task == &idle_task) {
            cpu_interrupt_restore(flags);
            return;
        }

        next = &idle_task;
    }

    if (next == current_task) {
        cpu_interrupt_restore(flags);
        return;
    }

    struct task *previous = current_task;
    if (previous != 0 && previous->state == THREAD_STATE_RUNNING) {
        previous->state = THREAD_STATE_RUNNABLE;
    }

    next->state = THREAD_STATE_RUNNING;
    next->quantum_remaining = TASK_DEFAULT_QUANTUM;
    current_task = next;
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0) {
        cpu->current_task = next;
    }

    if (next->process != NULL && next->process->pml4_physical != 0) {
        if (previous == NULL || previous->process != next->process) {
            cpu_write_cr3(next->process->pml4_physical);
        }
    }

    if (next->stack != NULL) {
        tss_set_rsp0(((uint64_t)next->stack + next->stack_size) & ~0xFull);
    } else {
        extern uint8_t kos_boot_stack_top[];
        tss_set_rsp0((uint64_t)kos_boot_stack_top);
    }

    previous->context.rflags = flags;
    task_switch(&previous->context, &next->context);
}

void task_yield(void) {
    schedule();
}

void preempt_disable(void) {
    if (!initialized || current_task == NULL) {
        return;
    }
    current_task->preempt_count++;
}

void preempt_enable(void) {
    if (!initialized || current_task == NULL) {
        return;
    }
    if (current_task->preempt_count > 0) {
        current_task->preempt_count--;
    }
    if (current_task->preempt_count == 0 && spinlock_irqs_enabled()) {
        if (current_task->reschedule_pending || __atomic_load_n(&reschedule_requested, __ATOMIC_RELAXED)) {
            current_task->reschedule_pending = false;
            schedule();
        }
    }
}

uint32_t preempt_count(void) {
    if (!initialized || current_task == NULL) {
        return 0;
    }
    return current_task->preempt_count;
}

void task_block(struct task *task) {
    if (!initialized) {
        return;
    }
    if (task == 0) {
        task = current_task;
    }
    if (task != 0) {
        task->state = THREAD_STATE_BLOCKED;
    }
}

void task_unblock(struct task *task) {
    if (task == 0) {
        return;
    }
    if (task->state == THREAD_STATE_BLOCKED) {
        task->state = THREAD_STATE_RUNNABLE;
    }
}

struct task *task_current(void) {
    if (!initialized) {
        return 0;
    }
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0 && cpu->current_task != 0) {
        return cpu->current_task;
    }
    return current_task;
}

enum task_state task_get_state(const struct task *task) {
    return task ? (enum task_state)task->state : TASK_UNUSED;
}

uint64_t task_current_tid(void) {
    struct task *cur = task_current();
    if (!initialized || cur == 0) {
        return 1;
    }
    return cur->tid;
}

uint64_t task_get_current_tid(void) {
    return task_current_tid();
}

uint64_t task_current_id(void) {
    return task_current_tid();
}

uint64_t task_get_current_id(void) {
    return task_current_tid();
}

bool task_is_multitasking_active(void) {
    return initialized;
}

KOS_NORETURN void task_exit(void) {
    thread_exit(0);
}

void task_sleep(uint64_t ms) {
    /* Safeguard 1: Single-task / early boot / interrupt context */
    if (!task_is_multitasking_active() || !spinlock_irqs_enabled() || current_task == NULL) {
        timer_delay_ms(ms);
        return;
    }

    /* Safeguard 2: Zero delay yields CPU without queuing */
    if (ms == 0) {
        task_yield();
        return;
    }

    uint64_t ticks_to_sleep = timer_ms_to_ticks(ms);
    if (ticks_to_sleep == 0) {
        ticks_to_sleep = 1;
    }

    uint64_t now = timer_get_ticks();
    uint64_t deadline = now + ticks_to_sleep;
    if (deadline < now) {
        deadline = UINT64_MAX;
    }

    uint64_t flags = spinlock_lock_irqsave(&sleep_lock);
    struct task *cur = current_task;
    cur->sleep_target_tick = deadline;
    cur->state = THREAD_STATE_SLEEPING;
    sleep_queue_insert_sorted(cur);
    spinlock_unlock_irqrestore(&sleep_lock, flags);

    while (cur->state == THREAD_STATE_SLEEPING) {
        schedule();
        if (cur->state == THREAD_STATE_SLEEPING) {
            cpu_wait_for_interrupt();
        }
    }

    cur->state = THREAD_STATE_RUNNING;
}

void task_timer_tick(void) {
    if (!initialized) {
        return;
    }

    bool woken = false;

    if (__atomic_load_n(&sleeping_task_count, __ATOMIC_RELAXED) > 0) {
        uint64_t current_ticks = timer_get_ticks();
        uint64_t flags = spinlock_lock_irqsave(&sleep_lock);

        struct list_head *pos = sleep_queue.next;
        while (pos != &sleep_queue) {
            struct task *task = list_entry(pos, struct task, sleep_node);
            struct list_head *next = pos->next;

            if (current_ticks < task->sleep_target_tick) {
                break;
            }

            list_del_init(&task->sleep_node);
            if (sleeping_task_count > 0) {
                sleeping_task_count--;
            }

            task->state = THREAD_STATE_RUNNABLE;
            task->quantum_remaining = TASK_DEFAULT_QUANTUM;
            woken = true;

            pos = next;
        }

        spinlock_unlock_irqrestore(&sleep_lock, flags);
    }

    if (current_task == NULL) {
        return;
    }

    if (woken) {
        if (current_task == &idle_task || current_task->preempt_count == 0) {
            __atomic_store_n(&reschedule_requested, true, __ATOMIC_RELAXED);
        } else {
            current_task->reschedule_pending = true;
        }
    }

    if (current_task == &idle_task) {
        if (task_ready_count() > 0) {
            __atomic_store_n(&reschedule_requested, true, __ATOMIC_RELAXED);
        }
        return;
    }

    if (current_task->state == THREAD_STATE_RUNNING) {
        if (current_task->quantum_remaining > 0) {
            current_task->quantum_remaining--;
        }
        if (current_task->quantum_remaining == 0) {
            current_task->quantum_remaining = TASK_DEFAULT_QUANTUM;
            if (current_task->preempt_count == 0) {
                __atomic_store_n(&reschedule_requested, true, __ATOMIC_RELAXED);
            } else {
                current_task->reschedule_pending = true;
            }
        }
    }
}

void task_reschedule_if_needed(void) {
    if (!initialized || current_task == NULL) {
        return;
    }
    if (current_task->preempt_count > 0) {
        return;
    }
    if (__atomic_exchange_n(&reschedule_requested, false, __ATOMIC_RELAXED) ||
        current_task->reschedule_pending ||
        (current_task == &idle_task && task_ready_count() > 0)) {
        current_task->reschedule_pending = false;
        schedule();
    }
}

void task_request_reschedule(void) {
    __atomic_store_n(&reschedule_requested, true, __ATOMIC_RELAXED);
    if (current_task != NULL && current_task->preempt_count > 0) {
        current_task->reschedule_pending = true;
    }
}

uint64_t task_count(void) {
    uint64_t count = 0;
    for (uint64_t index = 0; index < TASK_MAX_COUNT; ++index) {
        if (tasks[index].state != THREAD_STATE_UNUSED) {
            ++count;
        }
    }
    if (idle_task.state != THREAD_STATE_UNUSED) {
        ++count;
    }
    return count;
}

uint64_t task_ready_count(void) {
    uint64_t count = 0;
    for (uint64_t index = 0; index < TASK_MAX_COUNT; ++index) {
        if (tasks[index].state == THREAD_STATE_RUNNABLE) {
            ++count;
        }
    }
    return count;
}

static void task_self_test_entry(void *argument) {
    struct task_self_test_counter *counter = argument;
    for (uint64_t index = 0; index < TASK_SELF_TEST_ITERATIONS; ++index) {
        ++counter->count;
        task_yield();
    }
}

bool task_run_self_test(void) {
    static struct task_self_test_counter first;
    static struct task_self_test_counter second;

    if (!initialized || task_ready_count() != 0) {
        return false;
    }
    first.count = 0;
    second.count = 0;
    if (!task_create_kernel("selftest-A", task_self_test_entry, &first)) {
        return false;
    }
    if (!task_create_kernel("selftest-B", task_self_test_entry, &second)) {
        (void)task_release(&tasks[1]);
        return false;
    }
    while (task_ready_count() != 0) {
        task_yield();
    }
    bool passed = first.count == TASK_SELF_TEST_ITERATIONS && second.count == TASK_SELF_TEST_ITERATIONS;
    task_reap_terminated();
    return passed;
}

static void task_log_demo_entry(void *argument) {
    struct task_log_demo_state *state = argument;
    for (uint64_t index = 0; index < TASK_LOG_DEMO_ITERATIONS; ++index) {
        ++state->count;
        log_info_u64(state->label, state->count);
        task_yield();
    }
}

bool task_run_log_demo(void) {
    static struct task_log_demo_state first = { .label = "task-A count: " };
    static struct task_log_demo_state second = { .label = "task-B count: " };

    if (!initialized || task_ready_count() != 0) {
        return false;
    }
    first.count = 0;
    second.count = 0;
    if (!task_create_kernel("log-demo-A", task_log_demo_entry, &first)) {
        return false;
    }
    if (!task_create_kernel("log-demo-B", task_log_demo_entry, &second)) {
        (void)task_release(&tasks[1]);
        return false;
    }
    while (task_ready_count() != 0) {
        task_yield();
    }
    bool passed = first.count == TASK_LOG_DEMO_ITERATIONS && second.count == TASK_LOG_DEMO_ITERATIONS;
    task_reap_terminated();
    return passed;
}
