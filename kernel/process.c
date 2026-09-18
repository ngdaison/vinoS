#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/atomic.h>
#include <kos/compiler.h>
#include <kos/cpu.h>
#include <kos/heap.h>
#include <kos/list.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/process.h>
#include <kos/handle.h>
#include <kos/wait.h>
#include <kos/spinlock.h>
#include <kos/task.h>
#include <kos/descriptors.h>
#include <kos/elf.h>
#include <kos/pmm.h>
#include <kos/vmm.h>

extern struct task idle_task;

static struct process processes[PROCESS_MAX_COUNT];
static struct list_head process_list = LIST_HEAD_INIT(process_list);
static kos_spinlock_t process_lock = SPINLOCK_INIT;
static uint64_t next_pid = 2;
static volatile uint64_t active_process_count = 0;

static struct process idle_process;
static struct process kernel_process;

static kos_spinlock_t reaper_lock = SPINLOCK_INIT;
static struct list_head reaper_queue = LIST_HEAD_INIT(reaper_queue);
static struct thread *reaper_thread_ptr = NULL;
static volatile uint64_t reaper_reaped_total = 0;
static bool process_initialized = false;

struct process *process_get_kernel(void) {
    return &kernel_process;
}

struct process *process_get_idle(void) {
    return &idle_process;
}

struct process *process_get_current(void) {
    struct thread *cur = thread_current();
    if (cur != NULL && cur->process != NULL) {
        return cur->process;
    }
    return &kernel_process;
}

struct thread *thread_current(void) {
    return task_current();
}

enum thread_state thread_get_state(const struct thread *thread) {
    return thread ? thread->state : THREAD_STATE_UNUSED;
}

const char *thread_state_name(enum thread_state state) {
    switch (state) {
        case THREAD_STATE_UNUSED:   return "UNUSED";
        case THREAD_STATE_RUNNABLE: return "RUNNABLE";
        case THREAD_STATE_RUNNING:  return "RUNNING";
        case THREAD_STATE_BLOCKED:  return "BLOCKED";
        case THREAD_STATE_SLEEPING: return "SLEEPING";
        case THREAD_STATE_ZOMBIE:   return "ZOMBIE";
        case THREAD_STATE_DEAD:     return "DEAD";
        default:                    return "UNKNOWN";
    }
}

const char *process_state_name(enum process_state state) {
    switch (state) {
        case PROCESS_STATE_UNUSED: return "UNUSED";
        case PROCESS_STATE_ACTIVE: return "ACTIVE";
        case PROCESS_STATE_ZOMBIE: return "ZOMBIE";
        case PROCESS_STATE_DEAD:   return "DEAD";
        default:                   return "UNKNOWN";
    }
}

struct thread *reaper_get_thread(void) {
    return reaper_thread_ptr;
}

uint64_t reaper_reaped_count(void) {
    return __atomic_load_n(&reaper_reaped_total, __ATOMIC_RELAXED);
}

uint64_t process_count(void) {
    return __atomic_load_n(&active_process_count, __ATOMIC_RELAXED);
}

struct process *process_find_by_pid(uint64_t pid) {
    if (pid == 0) {
        return &idle_process;
    }
    if (pid == 1) {
        return &kernel_process;
    }
    uint64_t flags = spinlock_lock_irqsave(&process_lock);
    struct list_head *pos = process_list.next;
    while (pos != &process_list) {
        struct process *proc = list_entry(pos, struct process, process_node);
        if (proc->pid == pid) {
            spinlock_unlock_irqrestore(&process_lock, flags);
            return proc;
        }
        pos = pos->next;
    }
    spinlock_unlock_irqrestore(&process_lock, flags);
    return NULL;
}

struct process *process_create(const char *name) {
    if (name == NULL) {
        return NULL;
    }
    uint64_t flags = spinlock_lock_irqsave(&process_lock);
    struct process *proc = NULL;
    for (size_t i = 0; i < PROCESS_MAX_COUNT; i++) {
        if (processes[i].state == PROCESS_STATE_UNUSED || processes[i].state == PROCESS_STATE_DEAD) {
            proc = &processes[i];
            break;
        }
    }
    if (proc == NULL) {
        spinlock_unlock_irqrestore(&process_lock, flags);
        return NULL;
    }

    proc->pid = next_pid++;
    struct process *cur = process_get_current();
    proc->ppid = cur ? cur->pid : 1;
    proc->state = PROCESS_STATE_ACTIVE;
    proc->exit_code = 0;
    list_init(&proc->threads);
    proc->thread_count = 0;
    proc->pml4_physical = cpu_read_cr3() & ~0xFFFull;
    spinlock_init(&proc->lock);
    list_init(&proc->process_node);
    list_init(&proc->children);
    list_init(&proc->sibling_node);
    proc->handles = handle_table_create();
    wait_queue_init(&proc->exit_wq);

    size_t len = 0;
    while (name[len] != '\0' && len < sizeof(proc->name) - 1) {
        proc->name[len] = name[len];
        len++;
    }
    proc->name[len] = '\0';

    list_add_tail(&proc->process_node, &process_list);
    __atomic_fetch_add(&active_process_count, 1, __ATOMIC_RELAXED);

    if (cur != NULL) {
        uint64_t pflags = spinlock_lock_irqsave(&cur->lock);
        list_add_tail(&proc->sibling_node, &cur->children);
        spinlock_unlock_irqrestore(&cur->lock, pflags);
    } else {
        uint64_t kflags = spinlock_lock_irqsave(&kernel_process.lock);
        list_add_tail(&proc->sibling_node, &kernel_process.children);
        spinlock_unlock_irqrestore(&kernel_process.lock, kflags);
    }

    spinlock_unlock_irqrestore(&process_lock, flags);
    return proc;
}

void process_destroy(struct process *proc) {
    if (proc == NULL || proc->pid <= 1) {
        return;
    }

    /* 1. Reparent children to kernel_process */
    uint64_t pflags = spinlock_lock_irqsave(&proc->lock);
    struct list_head *cpos = proc->children.next;
    while (cpos != &proc->children) {
        struct process *child = list_entry(cpos, struct process, sibling_node);
        cpos = cpos->next;
        list_del_init(&child->sibling_node);
        child->ppid = 1;
        uint64_t kflags = spinlock_lock_irqsave(&kernel_process.lock);
        list_add_tail(&child->sibling_node, &kernel_process.children);
        spinlock_unlock_irqrestore(&kernel_process.lock, kflags);
    }

    /* 2. Unlink from parent's children list */
    list_del_init(&proc->sibling_node);

    /* 3. Dequeue and free all remaining threads */
    struct list_head *tpos = proc->threads.next;
    while (tpos != &proc->threads) {
        struct thread *t = list_entry(tpos, struct thread, process_node);
        tpos = tpos->next;
        list_del_init(&t->process_node);

        task_sleep_dequeue(t);

        uint64_t rflags = spinlock_lock_irqsave(&reaper_lock);
        if (t->reaper_node.next != NULL && t->reaper_node.next != &t->reaper_node) {
            list_del_init(&t->reaper_node);
        }
        spinlock_unlock_irqrestore(&reaper_lock, rflags);

        if (t != thread_current()) {
            if (t != &idle_task && t->stack != NULL && t->stack_size > 0) {
                kfree(t->stack);
                t->stack = NULL;
                t->stack_size = 0;
            }
            task_free_slot(t);
        }
    }
    proc->thread_count = 0;
    spinlock_unlock_irqrestore(&proc->lock, pflags);

    /* 4. Mark dead, unlink from active process list, extract handle table */
    struct handle_table *ht = NULL;
    uint64_t flags = spinlock_lock_irqsave(&process_lock);
    if (proc->state != PROCESS_STATE_DEAD) {
        proc->state = PROCESS_STATE_DEAD;
        list_del_init(&proc->process_node);
        if (active_process_count > 2) {
            __atomic_fetch_sub(&active_process_count, 1, __ATOMIC_RELAXED);
        }
    }
    ht = proc->handles;
    proc->handles = NULL;
    spinlock_unlock_irqrestore(&process_lock, flags);

    /* 5. Destroy handle table */
    if (ht != NULL) {
        handle_table_destroy(ht);
    }

    /* 6. Destroy private user address space if non-zero and not kernel PML4 */
    uint64_t user_pml4 = proc->pml4_physical;
    proc->pml4_physical = 0;
    if (user_pml4 != 0 && user_pml4 != kernel_process.pml4_physical) {
        vmm_destroy_address_space(user_pml4);
    }

    /* 7. Wake any remaining waiters */
    wait_queue_wake_all(&proc->exit_wq);
}

void process_exit(struct process *proc, int exit_code) {
    if (proc == NULL || proc->pid <= 1) {
        return;
    }
    uint64_t flags = spinlock_lock_irqsave(&proc->lock);
    if (proc->state == PROCESS_STATE_ZOMBIE || proc->state == PROCESS_STATE_DEAD) {
        spinlock_unlock_irqrestore(&proc->lock, flags);
        return;
    }
    proc->exit_code = exit_code;
    proc->state = PROCESS_STATE_ZOMBIE;

    /* 1. Close handle table to trigger object unref and destructors */
    struct handle_table *ht = proc->handles;
    proc->handles = NULL;

    /* 2. Transition remaining non-current threads to ZOMBIE and enqueue to reaper */
    struct thread *cur = thread_current();
    struct list_head *pos = proc->threads.next;
    while (pos != &proc->threads) {
        struct thread *t = list_entry(pos, struct thread, process_node);
        pos = pos->next;
        if (t != cur && t->state != THREAD_STATE_ZOMBIE && t->state != THREAD_STATE_DEAD) {
            t->exit_code = exit_code;
            t->state = THREAD_STATE_ZOMBIE;
            task_sleep_dequeue(t);
            uint64_t rflags = spinlock_lock_irqsave(&reaper_lock);
            list_add_tail(&t->reaper_node, &reaper_queue);
            if (reaper_thread_ptr != NULL) {
                task_unblock(reaper_thread_ptr);
            }
            spinlock_unlock_irqrestore(&reaper_lock, rflags);
        }
    }

    bool has_no_threads = (proc->thread_count == 0);
    uint64_t ppid = proc->ppid;
    spinlock_unlock_irqrestore(&proc->lock, flags);

    if (ht != NULL) {
        handle_table_destroy(ht);
    }

    /* 3. Broadcast wakeup to all threads/processes waiting on exit_wq */
    wait_queue_wake_all(&proc->exit_wq);

    /* 4. IMPORTANT: Do NOT automatically destroy if parent is active! */
    if (has_no_threads) {
        struct process *parent = process_find_by_pid(ppid);
        if (parent == NULL || parent->state == PROCESS_STATE_DEAD) {
            process_destroy(proc);
        }
    }

    if (cur != NULL && cur->process == proc) {
        thread_exit(exit_code);
    }
}

static bool process_exit_condition(void *arg) {
    struct process *proc = (struct process *)arg;
    if (proc == NULL) {
        return true;
    }
    return (proc->state == PROCESS_STATE_ZOMBIE || proc->state == PROCESS_STATE_DEAD);
}

bool process_wait(struct process *proc, int *exit_code, uint64_t timeout_ms) {
    if (proc == NULL) {
        return false;
    }

    bool exited = false;
    if (timeout_ms == 0) {
        exited = process_exit_condition(proc);
    } else if (timeout_ms == UINT64_MAX) {
        wait_event(&proc->exit_wq, process_exit_condition, proc);
        exited = process_exit_condition(proc);
    } else {
        exited = wait_event_timeout(&proc->exit_wq, process_exit_condition, proc, timeout_ms);
    }

    if (exited) {
        if (exit_code != NULL) {
            *exit_code = proc->exit_code;
        }

        /* Remove proc from parent's children list */
        struct process *parent = process_find_by_pid(proc->ppid);
        if (parent != NULL) {
            uint64_t parent_flags = spinlock_lock_irqsave(&parent->lock);
            list_del_init(&proc->sibling_node);
            spinlock_unlock_irqrestore(&parent->lock, parent_flags);
        } else {
            list_del_init(&proc->sibling_node);
        }

        /* Reap child: transition to DEAD, reclaim resources, free table slot */
        process_destroy(proc);
        return true;
    }

    return false;
}

int process_exec(const char *path, int argc, char *const argv[]) {
    if (path == NULL) {
        return -1;
    }

    struct process *proc = process_get_current();
    if (proc == NULL) {
        return -1;
    }

    /* 1. Create a private user address space */
    uint64_t pml4_phys = vmm_create_address_space();
    if (pml4_phys == 0) {
        return -1;
    }

    /* 2. Load the ELF binary image into the private address space */
    struct elf_binary_image img;
    bool ok = elf_load_binary(path, pml4_phys, &img);
    if (!ok) {
        vmm_destroy_address_space(pml4_phys);
        return -1;
    }

    /* 3. Allocate and set up user stack with argc/argv formatted per System V ABI */
    uint64_t user_rsp = 0;
    ok = process_setup_user_stack(pml4_phys, argc, argv, &user_rsp);
    if (!ok) {
        vmm_destroy_address_space(pml4_phys);
        return -1;
    }

    /* 4. Clean up old user address space if proc had a private user PML4 */
    uint64_t old_pml4 = proc->pml4_physical;
    if (old_pml4 != 0 && old_pml4 != kernel_process.pml4_physical) {
        vmm_destroy_address_space(old_pml4);
    }

    /* 5. Assign new address space */
    proc->pml4_physical = pml4_phys;

    /* 6. Update process name to match binary filename */
    const char *basename = path;
    for (const char *p = path; *p != '\0'; ++p) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }
    size_t nlen = 0;
    while (basename[nlen] != '\0' && nlen < sizeof(proc->name) - 1) {
        proc->name[nlen] = basename[nlen];
        nlen++;
    }
    proc->name[nlen] = '\0';

    /* 7. Ensure TSS RSP0 is configured with kernel stack for current thread */
    struct thread *cur_thread = thread_current();
    if (cur_thread != NULL && cur_thread->stack != NULL) {
        tss_set_rsp0(((uint64_t)cur_thread->stack + cur_thread->stack_size) & ~0xFull);
    }

    /* 8. Switch to the new address space */
    cpu_write_cr3(pml4_phys);

    /* 9. Jump to Ring 3 userspace (noreturn) */
    enter_userspace(img.entry_point, user_rsp);

    /* Unreachable */
    return 0;
}

struct thread *thread_create(struct process *proc, void (*entry)(void *), void *arg, const char *name) {
    if (entry == NULL) {
        return NULL;
    }
    if (proc == NULL) {
        proc = &kernel_process;
    }
    if (name == NULL) {
        name = "thread";
    }

    struct thread *t = task_allocate_slot();
    if (t == NULL) {
        return NULL;
    }

    uint8_t *stack = kmalloc(TASK_KERNEL_STACK_SIZE);
    if (stack == NULL) {
        task_free_slot(t);
        return NULL;
    }

    uint64_t stack_top = ((uint64_t)stack + TASK_KERNEL_STACK_SIZE) & ~0xfull;
    stack_top -= sizeof(uint64_t);
    *(uint64_t *)stack_top = 0;

    uint64_t tid = task_next_id();

    *t = (struct thread){
        .context = {
            .rsp = stack_top,
            .rip = (uint64_t)task_start_trampoline,
            .rflags = 0x202,
        },
        .entry = entry,
        .argument = arg,
        .stack = stack,
        .stack_size = TASK_KERNEL_STACK_SIZE,
        .name = name,
        .state = THREAD_STATE_RUNNABLE,
        .tid = tid,
        .id = tid,
        .process = proc,
        .exit_code = 0,
        .sleep_target_tick = 0,
        .preempt_count = 0,
        .reschedule_pending = false,
        .quantum_remaining = TASK_DEFAULT_QUANTUM,
    };
    list_init(&t->sleep_node);
    list_init(&t->reaper_node);
    list_init(&t->process_node);

    uint64_t pflags = spinlock_lock_irqsave(&proc->lock);
    list_add_tail(&t->process_node, &proc->threads);
    proc->thread_count++;
    spinlock_unlock_irqrestore(&proc->lock, pflags);

    return t;
}

/* Dedicated reaper thread loop running on its own stack */
static void reaper_thread_entry(void *arg) {
    (void)arg;
    for (;;) {
        struct thread *zombie = NULL;
        uint64_t flags = spinlock_lock_irqsave(&reaper_lock);
        if (!list_empty(&reaper_queue)) {
            struct list_head *first = reaper_queue.next;
            list_del_init(first);
            zombie = list_entry(first, struct thread, reaper_node);
        } else {
            /* Queue empty: mark blocked while holding spinlock */
            if (reaper_thread_ptr != NULL) {
                reaper_thread_ptr->state = THREAD_STATE_BLOCKED;
            }
        }
        spinlock_unlock_irqrestore(&reaper_lock, flags);

        if (zombie != NULL) {
            /* 1. Transition state from ZOMBIE to DEAD */
            zombie->state = THREAD_STATE_DEAD;

            /* 2. Safely free kernel stack outside of zombie's running context */
            if (zombie->stack != NULL && zombie->stack_size > 0) {
                (void)kfree(zombie->stack);
                zombie->stack = NULL;
            }

            /* 3. Decrement owning process thread count */
            struct process *proc = zombie->process;
            if (proc != NULL) {
                uint64_t pflags = spinlock_lock_irqsave(&proc->lock);
                list_del_init(&zombie->process_node);
                if (proc->thread_count > 0) {
                    proc->thread_count--;
                }
                bool is_zombie_empty = (proc->state == PROCESS_STATE_ZOMBIE && proc->thread_count == 0);
                uint64_t ppid = proc->ppid;
                spinlock_unlock_irqrestore(&proc->lock, pflags);

                if (is_zombie_empty) {
                    /* Only destroy if parent does not exist or is dead */
                    struct process *parent = process_find_by_pid(ppid);
                    if (parent == NULL || parent->state == PROCESS_STATE_DEAD) {
                        process_destroy(proc);
                    }
                }
            }

            __atomic_fetch_add(&reaper_reaped_total, 1, __ATOMIC_RELAXED);
        } else {
            /* No zombies: switch away until unblocked by thread_exit */
            schedule();
        }
    }
}

KOS_NORETURN void thread_exit(int exit_code) {
    struct thread *cur = thread_current();
    if (cur == NULL || cur == &idle_task || cur->tid == 0 || cur->tid == 1) {
        /* Idle or bootstrap kernel thread must never exit */
        for (;;) {
            cpu_halt();
        }
    }

    cur->exit_code = exit_code;
    cur->state = THREAD_STATE_ZOMBIE;

    struct process *proc = cur->process;
    if (proc != NULL && proc != &kernel_process && proc != &idle_process) {
        uint64_t pflags = spinlock_lock_irqsave(&proc->lock);
        if (proc->state == PROCESS_STATE_ACTIVE) {
            proc->exit_code = exit_code;
            proc->state = PROCESS_STATE_ZOMBIE;
            wait_queue_wake_all(&proc->exit_wq);
        }
        spinlock_unlock_irqrestore(&proc->lock, pflags);
    }

    /* Enqueue onto reaper_queue and wake up reaper thread */
    uint64_t flags = spinlock_lock_irqsave(&reaper_lock);
    list_add_tail(&cur->reaper_node, &reaper_queue);
    if (reaper_thread_ptr != NULL) {
        task_unblock(reaper_thread_ptr);
    }
    spinlock_unlock_irqrestore(&reaper_lock, flags);

    /* Switch away: exiting thread never runs again */
    schedule();

    for (;;) {
        cpu_halt();
    }
}

bool process_subsystem_init(void) {
    if (process_initialized) {
        return true;
    }

    spinlock_init(&process_lock);
    list_init(&process_list);
    spinlock_init(&reaper_lock);
    list_init(&reaper_queue);
    reaper_reaped_total = 0;

    for (size_t i = 0; i < PROCESS_MAX_COUNT; i++) {
        processes[i].state = PROCESS_STATE_UNUSED;
        processes[i].pid = 0;
        processes[i].thread_count = 0;
        list_init(&processes[i].threads);
        list_init(&processes[i].process_node);
        list_init(&processes[i].children);
        list_init(&processes[i].sibling_node);
        spinlock_init(&processes[i].lock);
        processes[i].handles = NULL;
        wait_queue_init(&processes[i].exit_wq);
    }

    /* 1. Establish Idle Process (PID 0) */
    idle_process.pid = 0;
    idle_process.ppid = 0;
    idle_process.state = PROCESS_STATE_ACTIVE;
    idle_process.exit_code = 0;
    list_init(&idle_process.threads);
    list_init(&idle_process.children);
    list_init(&idle_process.sibling_node);
    idle_process.thread_count = 1;
    idle_process.pml4_physical = cpu_read_cr3() & ~0xFFFull;
    spinlock_init(&idle_process.lock);
    list_init(&idle_process.process_node);
    {
        const char *name = "idle";
        size_t i = 0;
        for (; name[i]; i++) idle_process.name[i] = name[i];
        idle_process.name[i] = '\0';
    }
    list_add_tail(&idle_process.process_node, &process_list);
    idle_process.handles = handle_table_create();
    wait_queue_init(&idle_process.exit_wq);

    /* Associate idle task with idle process */
    struct thread *itask = &idle_task;
    itask->process = &idle_process;
    list_init(&itask->process_node);
    list_add_tail(&itask->process_node, &idle_process.threads);

    /* 2. Establish Kernel Bootstrap Process (PID 1) */
    kernel_process.pid = 1;
    kernel_process.ppid = 0;
    kernel_process.state = PROCESS_STATE_ACTIVE;
    kernel_process.exit_code = 0;
    list_init(&kernel_process.threads);
    list_init(&kernel_process.children);
    list_init(&kernel_process.sibling_node);
    kernel_process.thread_count = 1;
    kernel_process.pml4_physical = cpu_read_cr3() & ~0xFFFull;
    spinlock_init(&kernel_process.lock);
    list_init(&kernel_process.process_node);
    {
        const char *name = "kernel";
        size_t i = 0;
        for (; name[i]; i++) kernel_process.name[i] = name[i];
        kernel_process.name[i] = '\0';
    }
    list_add_tail(&kernel_process.process_node, &process_list);
    kernel_process.handles = handle_table_create();
    wait_queue_init(&kernel_process.exit_wq);

    /* Associate bootstrap task with kernel process */
    struct thread *cur = task_current();
    if (cur != NULL) {
        cur->process = &kernel_process;
        list_init(&cur->process_node);
        list_add_tail(&cur->process_node, &kernel_process.threads);
    }

    active_process_count = 2;

    /* 3. Spawn dedicated reaper thread */
    reaper_thread_ptr = thread_create(&kernel_process, reaper_thread_entry, NULL, "reaper");
    if (reaper_thread_ptr != NULL) {
        reaper_thread_ptr->state = THREAD_STATE_BLOCKED;
    }

    process_initialized = true;

    /* 4. Execute Process & Thread Lifecycle Self-Test */
    if (!process_lifecycle_self_test()) {
        log_error("Process lifecycle self-test failed.");
        return false;
    }

    return true;
}

bool process_lifecycle_self_test(void) {
    log_info("[process] Running Process & Thread Lifecycle Self-Test...");

    /* 1. Test parent/child hierarchy linkage */
    struct process *parent = process_get_current();
    if (parent == NULL) {
        log_error("  [FAIL] Current process is NULL");
        return false;
    }

    struct process *child = process_create("test_child");
    if (child == NULL) {
        log_error("  [FAIL] Failed to create child process");
        return false;
    }

    if (child->ppid != parent->pid) {
        log_error("  [FAIL] Child PPID does not match parent PID");
        return false;
    }

    bool found_child = false;
    uint64_t pflags = spinlock_lock_irqsave(&parent->lock);
    struct list_head *pos = parent->children.next;
    while (pos != &parent->children) {
        struct process *p = list_entry(pos, struct process, sibling_node);
        if (p == child) {
            found_child = true;
            break;
        }
        pos = pos->next;
    }
    spinlock_unlock_irqrestore(&parent->lock, pflags);

    if (!found_child) {
        log_error("  [FAIL] Child not found in parent's children list");
        return false;
    }
    log_info("  [PASS] Process hierarchy (children & sibling_node) verified.");

    /* 2. Test Zombie state retention & process_wait reaping */
    process_exit(child, 42);

    if (child->state != PROCESS_STATE_ZOMBIE) {
        log_error("  [FAIL] Child was prematurely destroyed instead of remaining ZOMBIE");
        return false;
    }
    log_info("  [PASS] Zombie process retention with active parent verified.");

    int exit_code = 0;
    bool wait_ok = process_wait(child, &exit_code, 100);
    if (!wait_ok || exit_code != 42) {
        log_error("  [FAIL] process_wait failed or returned wrong exit code");
        return false;
    }

    if (child->state != PROCESS_STATE_DEAD) {
        log_error("  [FAIL] Child state after wait is not DEAD");
        return false;
    }

    found_child = false;
    pflags = spinlock_lock_irqsave(&parent->lock);
    pos = parent->children.next;
    while (pos != &parent->children) {
        struct process *p = list_entry(pos, struct process, sibling_node);
        if (p == child) {
            found_child = true;
            break;
        }
        pos = pos->next;
    }
    spinlock_unlock_irqrestore(&parent->lock, pflags);

    if (found_child) {
        log_error("  [FAIL] Reaped child still found in parent's children list");
        return false;
    }
    log_info("  [PASS] process_wait zombie reaping and hierarchy unlinking verified.");

    /* 3. Test private user address space creation and recursive reclamation (zero leaks) */
    uint64_t frames_before = pmm_free_frame_count();
    struct process *leak_proc = process_create("leak_test_proc");
    if (leak_proc == NULL) {
        log_error("  [FAIL] Failed to create leak test process");
        return false;
    }

    uint64_t user_pml4 = vmm_create_address_space();
    if (user_pml4 == 0) {
        log_error("  [FAIL] Failed to create user address space");
        return false;
    }

    uint64_t f1 = pmm_allocate_frame();
    uint64_t f2 = pmm_allocate_frame();
    if (f1 == 0 || f2 == 0) {
        log_error("  [FAIL] Failed to allocate frames for mapping test");
        return false;
    }
    vmm_map_page_in(user_pml4, 0x400000ull, f1, VMM_PAGE_USER | VMM_PAGE_WRITABLE);
    vmm_map_page_in(user_pml4, 0x500000ull, f2, VMM_PAGE_USER | VMM_PAGE_WRITABLE);

    leak_proc->pml4_physical = user_pml4;
    process_destroy(leak_proc);

    uint64_t frames_after = pmm_free_frame_count();
    if (frames_after != frames_before) {
        log_errorf("  [FAIL] Address space reclamation leaked frames: before=%llu, after=%llu",
                   (unsigned long long)frames_before, (unsigned long long)frames_after);
        return false;
    }
    log_info("  [PASS] Address space reclamation verified with zero frame leaks.");

    /* 4. Test process_exec error handling and unwinding */
    uint64_t frames_exec_before = pmm_free_frame_count();
    int exec_null = process_exec(NULL, 0, NULL);
    if (exec_null != -1) {
        log_error("  [FAIL] process_exec(NULL) did not return -1");
        return false;
    }

    int exec_nonexistent = process_exec("nonexistent.elf", 0, NULL);
    if (exec_nonexistent != -1) {
        log_error("  [FAIL] process_exec(nonexistent) did not return -1");
        return false;
    }

    uint64_t frames_exec_after = pmm_free_frame_count();
    if (frames_exec_after != frames_exec_before) {
        log_errorf("  [FAIL] process_exec error rollback leaked frames: before=%llu, after=%llu",
                   (unsigned long long)frames_exec_before, (unsigned long long)frames_exec_after);
        return false;
    }
    log_info("  [PASS] process_exec error rollback and unwinding verified with zero frame leaks.");

    log_info(">>> [PASS] ALL PROCESS LIFECYCLE & RECLAMATION SELF-TESTS PASSED! <<<");
    return true;
}
