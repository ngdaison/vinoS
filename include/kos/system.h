#ifndef KOS_SYSTEM_H
#define KOS_SYSTEM_H

#include <stdint.h>

/* A kernel-owned snapshot: safe to expose through a future user-space ABI. */
struct kos_system_info {
    uint64_t uptime_seconds;
    uint64_t total_memory_bytes;
    uint64_t usable_memory_bytes;
    uint64_t free_memory_frames;
    uint64_t kernel_task_count;
    uint64_t ready_task_count;
};

const char *system_kernel_name(void);
const char *system_architecture(void);
uint32_t system_version_major(void);
uint32_t system_version_minor(void);
void system_info_snapshot(struct kos_system_info *info);

#endif
