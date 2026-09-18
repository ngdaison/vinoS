#ifndef KOS_TASK_H
#define KOS_TASK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/list.h>
#include <kos/memory.h>

#define TASK_DEFAULT_QUANTUM 20
#define TASK_MAX_COUNT 64
#define TASK_KERNEL_STACK_SIZE (KOS_PAGE_SIZE * 4)

struct task_context {
    uint64_t rbx;
    uint64_t rbp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rsp;
    uint64_t rip;
    uint64_t rflags;
};

typedef void (*task_entry)(void *argument);

enum thread_state {
    THREAD_STATE_UNUSED = 0,
    THREAD_STATE_RUNNABLE = 1,   /* Ready to execute */
    THREAD_STATE_RUNNING = 2,    /* Currently executing on CPU */
    THREAD_STATE_BLOCKED = 3,    /* Waiting on lock / event */
    THREAD_STATE_SLEEPING = 4,   /* Sleeping on timer queue */
    THREAD_STATE_ZOMBIE = 5,     /* Terminated, stack pending reaping */
    THREAD_STATE_DEAD = 6,       /* Stack reclaimed by reaper */
};

enum task_state {
    TASK_UNUSED = THREAD_STATE_UNUSED,
    TASK_RUNNING = THREAD_STATE_RUNNING,
    TASK_READY = THREAD_STATE_RUNNABLE,
    TASK_RUNNABLE = THREAD_STATE_RUNNABLE,
    TASK_BLOCKED = THREAD_STATE_BLOCKED,
    TASK_SLEEPING = THREAD_STATE_SLEEPING,
    TASK_TERMINATED = THREAD_STATE_ZOMBIE,
    TASK_ZOMBIE = THREAD_STATE_ZOMBIE,
    TASK_DEAD = THREAD_STATE_DEAD,
};

#define TASK_STATE_UNUSED      TASK_UNUSED
#define TASK_STATE_RUNNING     TASK_RUNNING
#define TASK_STATE_READY       TASK_READY
#define TASK_STATE_RUNNABLE    TASK_RUNNABLE
#define TASK_STATE_BLOCKED     TASK_BLOCKED
#define TASK_STATE_SLEEPING    TASK_SLEEPING
#define TASK_STATE_TERMINATED  TASK_TERMINATED
#define TASK_STATE_ZOMBIE      TASK_ZOMBIE
#define TASK_STATE_DEAD        TASK_DEAD

struct process;

struct task {
    struct task_context context;
    task_entry entry;
    void *argument;
    uint8_t *stack;
    size_t stack_size;
    const char *name;
    volatile enum thread_state state;
    uint64_t tid;
    uint64_t id; /* backward-compatibility alias for tid */
    struct process *process;
    struct list_head process_node;
    int exit_code;
    uint64_t sleep_target_tick;
    struct list_head sleep_node;
    uint32_t preempt_count;
    bool reschedule_pending;
    uint32_t quantum_remaining;
    struct list_head reaper_node;
};

#define thread task
typedef struct task thread_t;
typedef struct task task_t;

bool task_initialize(void);
bool task_create_kernel(const char *name, task_entry entry, void *argument);
void task_yield(void);
void schedule(void);
void task_block(struct task *task);
void task_unblock(struct task *task);
struct task *task_current(void);
enum task_state task_get_state(const struct task *task);
KOS_NORETURN void task_exit(void);
void task_reap_terminated(void);
void task_timer_tick(void);
void task_reschedule_if_needed(void);
uint64_t task_count(void);
uint64_t task_ready_count(void);
bool task_run_self_test(void);
bool task_run_log_demo(void);

uint64_t task_current_tid(void);
uint64_t task_get_current_tid(void);
uint64_t task_current_id(void);
uint64_t task_get_current_id(void);
bool task_is_multitasking_active(void);

void task_sleep(uint64_t ms);
uint64_t task_sleeping_count(void);

void preempt_disable(void);
void preempt_enable(void);
uint32_t preempt_count(void);
void task_request_reschedule(void);
void task_sleep_enqueue(struct task *task, uint64_t target_tick);
void task_sleep_dequeue(struct task *task);

/* Low-level helpers for thread/process subsystem */
struct task *task_allocate_slot(void);
void task_free_slot(struct task *task);
uint64_t task_next_id(void);
void task_start_trampoline(void);

#endif
