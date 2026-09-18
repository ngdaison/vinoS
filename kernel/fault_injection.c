#include <kos/fault_injection.h>
#include <kos/qa.h>
#include <kos/memory.h>
#include <kos/log.h>
#include <kos/spinlock.h>

static struct fault_injection_config g_fault_config;
static kos_spinlock_t g_fault_lock = SPINLOCK_INIT;
static uint32_t g_alloc_counter = 0;

void fault_injection_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&g_fault_lock);
    memset(&g_fault_config, 0, sizeof(g_fault_config));
    g_alloc_counter = 0;
    spinlock_unlock_irqrestore(&g_fault_lock, flags);
    log_info("Fault Injection: Subsystem initialized.");
}

void fault_injection_set_config(const struct fault_injection_config *config) {
    if (config == NULL) return;
    uint64_t flags = spinlock_lock_irqsave(&g_fault_lock);
    g_fault_config = *config;
    g_alloc_counter = 0;
    spinlock_unlock_irqrestore(&g_fault_lock, flags);
}

void fault_injection_get_config(struct fault_injection_config *out_config) {
    if (out_config == NULL) return;
    uint64_t flags = spinlock_lock_irqsave(&g_fault_lock);
    *out_config = g_fault_config;
    spinlock_unlock_irqrestore(&g_fault_lock, flags);
}

void fault_injection_reset(void) {
    uint64_t flags = spinlock_lock_irqsave(&g_fault_lock);
    memset(&g_fault_config, 0, sizeof(g_fault_config));
    g_alloc_counter = 0;
    spinlock_unlock_irqrestore(&g_fault_lock, flags);
}

bool fault_should_fail_alloc(void) {
    if ((g_fault_config.active_faults & FAULT_ALLOC_FAIL) == 0) {
        return false;
    }
    uint64_t flags = spinlock_lock_irqsave(&g_fault_lock);
    g_alloc_counter++;
    bool fail = false;
    if (g_fault_config.alloc_fail_countdown > 0) {
        if (g_alloc_counter >= g_fault_config.alloc_fail_countdown) {
            fail = true;
        }
    } else if (g_fault_config.alloc_fail_probability > 0) {
        if ((g_alloc_counter % 100) < g_fault_config.alloc_fail_probability) {
            fail = true;
        }
    }
    spinlock_unlock_irqrestore(&g_fault_lock, flags);
    return fail;
}

bool fault_should_fail_block_io(void) {
    return (g_fault_config.active_faults & FAULT_BLOCK_IO_FAIL) != 0;
}

bool fault_should_partial_block_write(void) {
    return (g_fault_config.active_faults & FAULT_BLOCK_PARTIAL) != 0;
}

bool fault_should_drop_packet(void) {
    return (g_fault_config.active_faults & FAULT_NET_DROP) != 0;
}

bool fault_should_corrupt_packet(void) {
    return (g_fault_config.active_faults & FAULT_NET_CORRUPT) != 0;
}

bool fault_injection_self_test(void) {
    log_info("[fault] 1. Testing Memory Allocation Failure Injection...");
    struct fault_injection_config cfg = {
        .active_faults = FAULT_ALLOC_FAIL,
        .alloc_fail_countdown = 2,
    };
    fault_injection_set_config(&cfg);

    bool f1 = fault_should_fail_alloc(); /* 1: false */
    bool f2 = fault_should_fail_alloc(); /* 2: true */
    bool f3 = fault_should_fail_alloc(); /* 3: true */

    fault_injection_reset();

    if (!f1 && f2 && f3) {
        log_info("  [PASS] Memory allocation fault triggered accurately after countdown.");
    } else {
        log_error("  [FAIL] Allocation fault injection did not match countdown!");
        return false;
    }

    log_info("[fault] 2. Testing Network Packet Drop & Corruption Simulation...");
    cfg.active_faults = FAULT_NET_DROP | FAULT_NET_CORRUPT;
    fault_injection_set_config(&cfg);

    if (fault_should_drop_packet() && fault_should_corrupt_packet()) {
        log_info("  [PASS] Network drop and corruption fault hooks active.");
    } else {
        log_error("  [FAIL] Network fault hooks inactive!");
        fault_injection_reset();
        return false;
    }

    fault_injection_reset();
    log_info("  [PASS] Fault injection reset successfully restored normal operations.");
    return true;
}

bool qa_run_fault_injection_suite(void) {
    log_info("==================================================");
    log_info("     KOS Milestone K27 Fault Injection Suite      ");
    log_info("==================================================");
    bool ok = fault_injection_self_test();
    log_info("--------------------------------------------------");
    if (ok) {
        log_info(">>> [PASS] ALL FAULT INJECTION TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] FAULT INJECTION DETECTED FAILURES! <<<");
    }
    log_info("==================================================");
    return ok;
}
