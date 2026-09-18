#ifndef KOS_ATOMIC_H
#define KOS_ATOMIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/compiler.h>

/*
 * ============================================================================
 * Atomic Type Definitions
 * ============================================================================
 */

typedef struct {
    volatile int32_t counter;
} atomic_t;

typedef struct {
    volatile int64_t counter;
} atomic64_t;

#define ATOMIC_INIT(i)   { .counter = (int32_t)(i) }
#define ATOMIC64_INIT(i) { .counter = (int64_t)(i) }

/*
 * ============================================================================
 * Memory Barriers and CPU Pipeline Hints
 * ============================================================================
 */

/* Compiler barrier: prevents Clang optimization reordering across this point */
#define atomic_barrier() __asm__ __volatile__("" ::: "memory")

/* Full hardware memory barrier: serializes all loads and stores */
#define smp_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)

/* Read memory barrier: on x86_64 TSO, compiler barrier is sufficient */
#define smp_rmb() atomic_barrier()

/* Write memory barrier: on x86_64 TSO, compiler barrier is sufficient */
#define smp_wmb() atomic_barrier()

/* CPU pipeline relax hint: pauses execution pipeline inside spin loops */
#ifndef cpu_relax
#define cpu_relax() __asm__ __volatile__("pause" ::: "memory")
#endif

/*
 * ============================================================================
 * 32-bit Atomic Operations (atomic_t)
 * ============================================================================
 */

static inline int32_t atomic_read(const atomic_t *v) {
    return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

static inline int32_t atomic_read_acquire(const atomic_t *v) {
    return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

static inline void atomic_set(atomic_t *v, int32_t i) {
    __atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);
}

static inline void atomic_set_release(atomic_t *v, int32_t i) {
    __atomic_store_n(&v->counter, i, __ATOMIC_RELEASE);
}

static inline void atomic_add(atomic_t *v, int32_t i) {
    (void)__atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline void atomic_sub(atomic_t *v, int32_t i) {
    (void)__atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline void atomic_inc(atomic_t *v) {
    (void)__atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline void atomic_dec(atomic_t *v) {
    (void)__atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_add_return(atomic_t *v, int32_t i) {
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_sub_return(atomic_t *v, int32_t i) {
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_inc_return(atomic_t *v) {
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_dec_return(atomic_t *v) {
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_add_fetch(atomic_t *v, int32_t i) {
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_sub_fetch(atomic_t *v, int32_t i) {
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_inc_fetch(atomic_t *v) {
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_dec_fetch(atomic_t *v) {
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_fetch_add(atomic_t *v, int32_t i) {
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_fetch_sub(atomic_t *v, int32_t i) {
    return __atomic_fetch_sub(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_fetch_and(atomic_t *v, int32_t mask) {
    return __atomic_fetch_and(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_fetch_or(atomic_t *v, int32_t mask) {
    return __atomic_fetch_or(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_fetch_xor(atomic_t *v, int32_t mask) {
    return __atomic_fetch_xor(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int32_t atomic_xchg(atomic_t *v, int32_t new_val) {
    return __atomic_exchange_n(&v->counter, new_val, __ATOMIC_SEQ_CST);
}

/*
 * atomic_cmpxchg:
 * Compares *v with old_val:
 * If equal, stores new_val into *v and returns old_val.
 * If not equal, leaves *v unchanged and returns the actual current value in *v.
 * Success condition: return_val == old_val.
 */
static inline int32_t atomic_cmpxchg(atomic_t *v, int32_t old_val, int32_t new_val) {
    int32_t expected = old_val;
    __atomic_compare_exchange_n(&v->counter, &expected, new_val, false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

static inline bool atomic_cmpxchg_bool(atomic_t *v, int32_t old_val, int32_t new_val) {
    int32_t expected = old_val;
    return __atomic_compare_exchange_n(&v->counter, &expected, new_val, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

/* Reference count helpers */
static inline bool atomic_dec_and_test(atomic_t *v) {
    return atomic_dec_return(v) == 0;
}

static inline bool atomic_inc_and_test(atomic_t *v) {
    return atomic_inc_return(v) == 0;
}

/*
 * ============================================================================
 * 64-bit Atomic Operations (atomic64_t)
 * ============================================================================
 */

static inline int64_t atomic64_read(const atomic64_t *v) {
    return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

static inline int64_t atomic64_read_acquire(const atomic64_t *v) {
    return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

static inline void atomic64_set(atomic64_t *v, int64_t i) {
    __atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);
}

static inline void atomic64_set_release(atomic64_t *v, int64_t i) {
    __atomic_store_n(&v->counter, i, __ATOMIC_RELEASE);
}

static inline void atomic64_add(atomic64_t *v, int64_t i) {
    (void)__atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline void atomic64_sub(atomic64_t *v, int64_t i) {
    (void)__atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline void atomic64_inc(atomic64_t *v) {
    (void)__atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline void atomic64_dec(atomic64_t *v) {
    (void)__atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_add_return(atomic64_t *v, int64_t i) {
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_sub_return(atomic64_t *v, int64_t i) {
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_inc_return(atomic64_t *v) {
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_dec_return(atomic64_t *v) {
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_add_fetch(atomic64_t *v, int64_t i) {
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_sub_fetch(atomic64_t *v, int64_t i) {
    return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_inc_fetch(atomic64_t *v) {
    return __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_dec_fetch(atomic64_t *v) {
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_fetch_add(atomic64_t *v, int64_t i) {
    return __atomic_fetch_add(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_fetch_sub(atomic64_t *v, int64_t i) {
    return __atomic_fetch_sub(&v->counter, i, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_fetch_and(atomic64_t *v, int64_t mask) {
    return __atomic_fetch_and(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_fetch_or(atomic64_t *v, int64_t mask) {
    return __atomic_fetch_or(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_fetch_xor(atomic64_t *v, int64_t mask) {
    return __atomic_fetch_xor(&v->counter, mask, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_xchg(atomic64_t *v, int64_t new_val) {
    return __atomic_exchange_n(&v->counter, new_val, __ATOMIC_SEQ_CST);
}

static inline int64_t atomic64_cmpxchg(atomic64_t *v, int64_t old_val, int64_t new_val) {
    int64_t expected = old_val;
    __atomic_compare_exchange_n(&v->counter, &expected, new_val, false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

static inline bool atomic64_cmpxchg_bool(atomic64_t *v, int64_t old_val, int64_t new_val) {
    int64_t expected = old_val;
    return __atomic_compare_exchange_n(&v->counter, &expected, new_val, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline bool atomic64_dec_and_test(atomic64_t *v) {
    return atomic64_dec_return(v) == 0;
}

static inline bool atomic64_inc_and_test(atomic64_t *v) {
    return atomic64_inc_return(v) == 0;
}

/*
 * ============================================================================
 * Generic Pointer Atomic Operations (atomic_ptr_*)
 * ============================================================================
 */

static inline void *atomic_ptr_read(void * const volatile *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_RELAXED);
}

static inline void *atomic_ptr_read_acquire(void * const volatile *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static inline void atomic_ptr_set(void * volatile *ptr, void *val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELAXED);
}

static inline void atomic_ptr_set_release(void * volatile *ptr, void *val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
}

static inline void *atomic_ptr_xchg(void * volatile *ptr, void *new_val) {
    return __atomic_exchange_n(ptr, new_val, __ATOMIC_SEQ_CST);
}

static inline void *atomic_ptr_cmpxchg(void * volatile *ptr, void *old_val, void *new_val) {
    void *expected = old_val;
    __atomic_compare_exchange_n(ptr, &expected, new_val, false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

static inline bool atomic_ptr_cmpxchg_bool(void * volatile *ptr, void *old_val, void *new_val) {
    void *expected = old_val;
    return __atomic_compare_exchange_n(ptr, &expected, new_val, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

#endif /* KOS_ATOMIC_H */
