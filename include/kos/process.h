#ifndef KOS_PROCESS_H
#define KOS_PROCESS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/list.h>
#include <kos/spinlock.h>
#include <kos/task.h>
#include <kos/wait.h>

#define PROCESS_NAME_MAX 32
#define PROCESS_MAX_COUNT 32

enum process_state {
    PROCESS_STATE_UNUSED = 0,
    PROCESS_STATE_ACTIVE = 1,
    PROCESS_STATE_ZOMBIE = 2,
    PROCESS_STATE_DEAD   = 3,
};

/* Forward declaration of handle table */
struct handle_table;

struct process {
    uint64_t pid;
    char name[PROCESS_NAME_MAX];
    uint64_t ppid;
    enum process_state state;
    int exit_code;
    struct list_head threads;
    uint32_t thread_count;
    uint64_t pml4_physical;
    kos_spinlock_t lock;
    struct list_head process_node;
    struct list_head children;
    struct list_head sibling_node;
    struct handle_table *handles;
    struct wait_queue exit_wq;
};

/* Process subsystem lifecycle */
bool process_subsystem_init(void);

/* Process lifecycle */
struct process *process_create(const char *name);
int process_exec(const char *path, int argc, char *const argv[]);
void process_exit(struct process *proc, int exit_code);
void process_destroy(struct process *proc);
struct process *process_get_current(void);
struct process *process_find_by_pid(uint64_t pid);
uint64_t process_count(void);
bool process_wait(struct process *proc, int *exit_code, uint64_t timeout_ms);
bool process_lifecycle_self_test(void);

/* Fixed bootstrap and idle processes */
struct process *process_get_kernel(void);
struct process *process_get_idle(void);

/* Thread lifecycle */
struct thread *thread_create(struct process *proc, void (*entry)(void *), void *arg, const char *name);
KOS_NORETURN void thread_exit(int exit_code);
struct thread *thread_current(void);
enum thread_state thread_get_state(const struct thread *thread);

/* State names for debugging/logging */
const char *thread_state_name(enum thread_state state);
const char *process_state_name(enum process_state state);

/* Reaper thread control and stats */
struct thread *reaper_get_thread(void);
uint64_t reaper_reaped_count(void);

#endif /* KOS_PROCESS_H */
