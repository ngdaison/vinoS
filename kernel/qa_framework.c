#include <kos/qa.h>
#include <kos/pmm.h>
#include <kos/heap.h>
#include <kos/process.h>
#include <kos/task.h>
#include <kos/socket.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/syscall.h>
#include <kos/uaccess.h>
#include <kos/kpkg.h>
#include <kos/fault_injection.h>

void qa_resource_snapshot_take(struct qa_resource_snapshot *out_snap) {
    if (out_snap == NULL) {
        return;
    }
    memset(out_snap, 0, sizeof(*out_snap));
    out_snap->free_pmm_frames = pmm_free_frame_count();
    out_snap->active_heap_allocs = heap_active_allocation_count();
    out_snap->active_processes = process_count();
    out_snap->active_threads = task_count();
}

bool qa_resource_snapshot_verify(const struct qa_resource_snapshot *before, const char *test_name) {
    if (before == NULL) {
        return true;
    }

    struct qa_resource_snapshot after;
    qa_resource_snapshot_take(&after);

    bool clean = true;

    /* PMM frame delta check */
    if (after.free_pmm_frames != before->free_pmm_frames) {
        int64_t diff = (int64_t)after.free_pmm_frames - (int64_t)before->free_pmm_frames;
        log_errorf("  [LEAK] PMM frames leaked in '%s': delta = %lld frames", test_name, (long long)diff);
        clean = false;
    }

    /* Heap allocation delta check */
    if (after.active_heap_allocs != before->active_heap_allocs) {
        int64_t diff = (int64_t)after.active_heap_allocs - (int64_t)before->active_heap_allocs;
        log_errorf("  [LEAK] Heap allocations leaked in '%s': delta = %lld allocs", test_name, (long long)diff);
        clean = false;
    }

    if (clean) {
        log_infof("  [PASS] Zero resource leaks in '%s' (PMM delta: 0, Heap delta: 0).", test_name);
    }
    return clean;
}

bool qa_run_regression_suite(void) {
    log_info("==================================================");
    log_info("         KOS Milestone K27 Regression Suite       ");
    log_info("==================================================");
    bool all_ok = true;

    /* Regression 1: Canonical address overflow wrapping in uaccess */
    log_info("[regression] 1. Verifying Syscall user pointer overflow wrapping...");
    struct qa_resource_snapshot snap1;
    qa_resource_snapshot_take(&snap1);
    const void *wrapped_ptr = (const void *)0xFFFFFFFFFFFFFFFEULL;
    if (access_ok(wrapped_ptr, 100)) {
        log_error("  [FAIL] access_ok passed wrapped pointer!");
        all_ok = false;
    } else {
        log_info("  [PASS] Wrapped canonical pointer correctly rejected.");
    }
    qa_resource_snapshot_verify(&snap1, "regression_uaccess_wrap");

    /* Regression 2: Path traversal attack containment */
    log_info("[regression] 2. Verifying Package Installer path traversal containment...");
    struct qa_resource_snapshot snap2;
    qa_resource_snapshot_take(&snap2);
    if (kpkg_validate_path("../../../etc/shadow") || kpkg_validate_path("bin/../../secret.txt")) {
        log_error("  [FAIL] kpkg_validate_path allowed relative traversal!");
        all_ok = false;
    } else {
        log_info("  [PASS] Package path traversal strictly blocked.");
    }
    qa_resource_snapshot_verify(&snap2, "regression_path_traversal");

    /* Regression 3: Multi-core spinlock re-entrancy & contention */
    log_info("[regression] 3. Verifying Spinlock IRQ-save & Try-lock...");
    struct qa_resource_snapshot snap3;
    qa_resource_snapshot_take(&snap3);
    kos_spinlock_t lk = SPINLOCK_INIT;
    uint64_t f1 = spinlock_lock_irqsave(&lk);
    if (!spinlock_is_locked(&lk)) {
        log_error("  [FAIL] Spinlock was not marked locked after lock_irqsave!");
        all_ok = false;
    }
    if (spinlock_try_lock(&lk)) {
        log_error("  [FAIL] spinlock_try_lock succeeded on already locked spinlock!");
        all_ok = false;
    }
    spinlock_unlock_irqrestore(&lk, f1);
    if (spinlock_is_locked(&lk)) {
        log_error("  [FAIL] Spinlock remained locked after restore!");
        all_ok = false;
    } else {
        log_info("  [PASS] Spinlock lock/unlock irqsave restored state cleanly.");
    }
    qa_resource_snapshot_verify(&snap3, "regression_spinlock_irqsave");

    if (all_ok) {
        log_info(">>> [PASS] ALL REGRESSION TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] REGRESSION TESTS FAILED! <<<");
    }
    log_info("==================================================");
    return all_ok;
}

bool qa_run_all_suites(void) {
    log_info("==================================================");
    log_info("   KOS Milestone K27 Master QA & CI Test Suite    ");
    log_info("==================================================");

    bool ok = true;
    ok = qa_run_regression_suite() && ok;
    ok = qa_run_fuzz_suite() && ok;
    ok = qa_run_fault_injection_suite() && ok;
    ok = qa_run_stress_suite() && ok;

    log_info("==================================================");
    if (ok) {
        log_info(">>> [PASS] ALL K27 QA, FUZZ, FAULT & STRESS SUITES PASSED! <<<");
    } else {
        log_error(">>> [FAIL] K27 QA TEST SUITE DETECTED FAILURES! <<<");
    }
    log_info("==================================================");
    return ok;
}
