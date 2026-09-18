#ifndef KOS_SMP_H
#define KOS_SMP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/atomic.h>
#include <kos/compiler.h>
#include <kos/descriptors.h>
#include <kos/spinlock.h>

#define SMP_MAX_CPUS 64
#define KOS_TASK_KERNEL_STACK_SIZE 16384

enum cpu_state {
    CPU_OFFLINE  = 0,
    CPU_STARTING = 1,
    CPU_ONLINE   = 2,
    CPU_HALTED   = 3,
};

struct task;

struct percpu_data {
    uint64_t kernel_rsp; /* Offset 0: Kernel stack for syscall */
    uint64_t user_rsp;   /* Offset 8: User stack storage */
    uint32_t cpu_id;
    uint32_t lapic_id;
    volatile uint32_t state;
    struct percpu_data *self;

    struct task *current_task;
    struct task *idle_task;

    struct task_state_segment tss KOS_ALIGNED(16);
    uint64_t gdt_entries[7] KOS_ALIGNED(16);

    uint8_t kernel_stack[KOS_TASK_KERNEL_STACK_SIZE] KOS_ALIGNED(16);
    uint8_t double_fault_stack[16384] KOS_ALIGNED(16);

    volatile uint64_t ipi_reschedule_count;
    volatile uint64_t ipi_tlb_count;
} KOS_ALIGNED(64);

/* Core SMP Subsystem API */
bool smp_initialize(void);
uint32_t smp_get_cpu_count(void);
uint32_t smp_get_online_cpu_count(void);
struct percpu_data *smp_get_percpu(uint32_t cpu_id);
struct percpu_data *smp_get_current_cpu(void);
uint32_t smp_get_cpu_id(void);

/* Cross-Core Synchronization & TLB Shootdown */
void smp_tlb_shootdown(uint64_t virtual_address, uint64_t page_count);
void smp_handle_tlb_shootdown_ipi(void);
void smp_send_reschedule(uint32_t target_cpu_id);

#endif /* KOS_SMP_H */
