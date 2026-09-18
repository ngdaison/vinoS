#include <stdint.h>

#include <kos/pmm.h>
#include <kos/system.h>
#include <kos/task.h>
#include <kos/timer.h>

enum {
    KOS_VERSION_MAJOR = 0,
    KOS_VERSION_MINOR = 1,
};

const char *system_kernel_name(void) {
    return "KOS";
}

const char *system_architecture(void) {
    return "x86_64";
}

uint32_t system_version_major(void) {
    return KOS_VERSION_MAJOR;
}

uint32_t system_version_minor(void) {
    return KOS_VERSION_MINOR;
}

void system_info_snapshot(struct kos_system_info *info) {
    if (info == 0) {
        return;
    }
    *info = (struct kos_system_info) {
        .uptime_seconds = timer_uptime_seconds(),
        .total_memory_bytes = pmm_total_memory_bytes(),
        .usable_memory_bytes = pmm_usable_memory_bytes(),
        .free_memory_frames = pmm_free_frame_count(),
        .kernel_task_count = task_count(),
        .ready_task_count = task_ready_count(),
    };
}
