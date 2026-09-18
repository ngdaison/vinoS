#ifndef KOS_FAULT_INJECTION_H
#define KOS_FAULT_INJECTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum fault_type {
    FAULT_NONE = 0,
    FAULT_ALLOC_FAIL = (1 << 0),       /* Fail memory allocations */
    FAULT_BLOCK_IO_FAIL = (1 << 1),    /* Fail block device reads/writes */
    FAULT_BLOCK_PARTIAL = (1 << 2),    /* Partial block write simulation */
    FAULT_NET_DROP = (1 << 3),         /* Drop network packets */
    FAULT_NET_DUP = (1 << 4),          /* Duplicate network packets */
    FAULT_NET_CORRUPT = (1 << 5),      /* Corrupt network packet bytes */
    FAULT_NET_TIMEOUT = (1 << 6),      /* Simulate network timeout */
};

struct fault_injection_config {
    uint32_t active_faults;            /* Bitmask of FAULT_* */
    uint32_t alloc_fail_probability;   /* Percentage (0-100) or counter */
    uint32_t alloc_fail_countdown;     /* Fail after N allocations */
    uint32_t block_fail_probability;   /* Percentage (0-100) */
    uint32_t net_drop_probability;     /* Percentage (0-100) */
    uint32_t net_corrupt_probability;  /* Percentage (0-100) */
};

/* Fault Injection APIs */
void fault_injection_init(void);
void fault_injection_set_config(const struct fault_injection_config *config);
void fault_injection_get_config(struct fault_injection_config *out_config);
void fault_injection_reset(void);

/* Trigger hooks called by subsystems */
bool fault_should_fail_alloc(void);
bool fault_should_fail_block_io(void);
bool fault_should_partial_block_write(void);
bool fault_should_drop_packet(void);
bool fault_should_corrupt_packet(void);

/* Self-test */
bool fault_injection_self_test(void);

#endif /* KOS_FAULT_INJECTION_H */
