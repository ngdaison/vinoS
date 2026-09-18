#ifndef KOS_QA_H
#define KOS_QA_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>

/* Test Categories */
enum qa_test_category {
    QA_CAT_UNIT = 1,
    QA_CAT_INTEGRATION = 2,
    QA_CAT_FUZZ = 3,
    QA_CAT_FAULT = 4,
    QA_CAT_STRESS = 5,
    QA_CAT_REGRESSION = 6,
};

/* Resource Snapshot for Leak Detection */
struct qa_resource_snapshot {
    uint64_t free_pmm_frames;
    uint64_t active_heap_allocs;
    uint64_t active_processes;
    uint64_t active_threads;
    uint64_t active_sockets;
};

/* QA Test Result Summary */
struct qa_test_stats {
    uint32_t total_tests;
    uint32_t passed_tests;
    uint32_t failed_tests;
    uint32_t skipped_tests;
};

/* Resource Tracking APIs */
void qa_resource_snapshot_take(struct qa_resource_snapshot *out_snap);
bool qa_resource_snapshot_verify(const struct qa_resource_snapshot *before, const char *test_name);

/* Master QA Suite Runners */
bool qa_run_all_suites(void);
bool qa_run_fuzz_suite(void);
bool qa_run_stress_suite(void);
bool qa_run_fault_injection_suite(void);
bool qa_run_regression_suite(void);

/* Individual Fuzzers */
bool qa_fuzz_elf_parser(uint32_t iterations);
bool qa_fuzz_syscall_args(uint32_t iterations);
bool qa_fuzz_partition_tables(uint32_t iterations);
bool qa_fuzz_fat32_engine(uint32_t iterations);
bool qa_fuzz_network_packets(uint32_t iterations);
bool qa_fuzz_asn1_x509(uint32_t iterations);
bool qa_fuzz_tls_records(uint32_t iterations);

/* Individual Stress Tests */
bool qa_stress_process_lifecycle(uint32_t iterations);
bool qa_stress_filesystem_io(uint32_t iterations);
bool qa_stress_socket_concurrency(uint32_t iterations);
bool qa_stress_memory_churn(uint32_t iterations);

#endif /* KOS_QA_H */
