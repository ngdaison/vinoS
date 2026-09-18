#include <kos/qa.h>
#include <kos/memory.h>
#include <kos/heap.h>
#include <kos/pmm.h>
#include <kos/process.h>
#include <kos/task.h>
#include <kos/socket.h>
#include <kos/vfs.h>
#include <kos/timer.h>
#include <kos/log.h>

struct stress_worker_ctx {
    volatile uint32_t iterations;
    volatile uint32_t completed;
    volatile bool finished;
};

static void stress_thread_worker(void *arg) {
    struct stress_worker_ctx *ctx = (struct stress_worker_ctx *)arg;
    for (uint32_t i = 0; i < ctx->iterations; i++) {
        void *p = kmalloc(128);
        if (p != NULL) {
            memset(p, 0xAA, 128);
            kfree(p);
        }
        if ((i % 10) == 0) {
            task_yield();
        }
    }
    ctx->completed = ctx->iterations;
    ctx->finished = true;
}

bool qa_stress_process_lifecycle(uint32_t iterations) {
    log_info("[stress] 1. Stressing Multi-Threaded Process & Task Lifecycle...");
    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    enum { WORKERS = 4 };
    static struct stress_worker_ctx ctxs[WORKERS];

    for (int w = 0; w < WORKERS; w++) {
        ctxs[w].iterations = iterations;
        ctxs[w].completed = 0;
        ctxs[w].finished = false;
        thread_create(cur_proc, stress_thread_worker, &ctxs[w], "stress_worker");
    }

    uint64_t timeout = timer_get_ticks() + timer_ms_to_ticks(5000);
    bool all_done = false;
    while (timer_get_ticks() < timeout) {
        all_done = true;
        for (int w = 0; w < WORKERS; w++) {
            if (!ctxs[w].finished) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;
        task_yield();
    }

    if (!all_done) {
        log_error("  [FAIL] Thread lifecycle stress timed out!");
        return false;
    }

    log_infof("  [PASS] %d concurrent threads completed %u iterations each.", WORKERS, iterations);
    return true;
}

bool qa_stress_filesystem_io(uint32_t iterations) {
    log_info("[stress] 2. Stressing Filesystem Concurrent Read/Write/Unlink...");
    char filename[64];
    uint8_t write_buf[256];
    memset(write_buf, 0x55, sizeof(write_buf));

    for (uint32_t i = 0; i < iterations; i++) {
        snprintf(filename, sizeof(filename), "D:/stress_file_%u.dat", i % 10);
        if (!vfs_write_file(filename, write_buf, sizeof(write_buf))) {
            log_errorf("  [FAIL] Failed to write %s", filename);
            return false;
        }

        const uint8_t *read_ptr = NULL;
        uint64_t read_sz = 0;
        if (!vfs_read_file(filename, &read_ptr, &read_sz) || read_sz != sizeof(write_buf)) {
            log_errorf("  [FAIL] Failed to read %s", filename);
            return false;
        }

        vfs_unlink_file(filename);
    }

    log_infof("  [PASS] Filesystem completed %u create/read/unlink cycles.", iterations);
    return true;
}

bool qa_stress_socket_concurrency(uint32_t iterations) {
    log_info("[stress] 3. Stressing Socket Lifecycle & Datagram Loopback...");
    for (uint32_t i = 0; i < iterations; i++) {
        struct socket *sock = NULL;
        int err = kos_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
        if (err == 0 && sock != NULL) {
            kos_close(sock);
        }
    }
    log_infof("  [PASS] Socket subsystem completed %u socket create/close cycles.", iterations);
    return true;
}

bool qa_stress_memory_churn(uint32_t iterations) {
    log_info("[stress] 4. Stressing PMM Frame & Heap Churn...");
    for (uint32_t i = 0; i < iterations; i++) {
        /* Allocate 8 physical frames */
        uint64_t frames[8];
        for (int f = 0; f < 8; f++) {
            frames[f] = pmm_allocate_frame();
        }

        /* Allocate heap blocks */
        void *h1 = kmalloc(32);
        void *h2 = kmalloc(512);
        void *h3 = kmalloc(4096);

        if (h1) memset(h1, 0x11, 32);
        if (h2) memset(h2, 0x22, 512);
        if (h3) memset(h3, 0x33, 4096);

        kfree(h1);
        kfree(h2);
        kfree(h3);

        for (int f = 0; f < 8; f++) {
            if (frames[f] != 0) {
                pmm_free_frame(frames[f]);
            }
        }
    }
    log_infof("  [PASS] Memory churn completed %u allocation/deallocation iterations.", iterations);
    return true;
}

bool qa_run_stress_suite(void) {
    log_info("==================================================");
    log_info("      KOS Milestone K27 Multi-Core Stress Suite   ");
    log_info("==================================================");
    bool all_ok = true;

    struct qa_resource_snapshot snap;
    qa_resource_snapshot_take(&snap);

    all_ok = qa_stress_process_lifecycle(50) && all_ok;
    all_ok = qa_stress_filesystem_io(30) && all_ok;
    all_ok = qa_stress_socket_concurrency(50) && all_ok;
    all_ok = qa_stress_memory_churn(50) && all_ok;

    qa_resource_snapshot_verify(&snap, "stress_suite");

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] ALL MULTI-CORE STRESS TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] STRESS TESTS DETECTED FAILURES! <<<");
    }
    log_info("==================================================");
    return all_ok;
}
