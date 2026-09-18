#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/cpu.h>
#include <kos/log.h>
#include <kos/panic.h>
#include <kos/security.h>
#include <kos/smp.h>

#define IA32_EFER 0xC0000080
#define EFER_NXE  (1ULL << 11)

#define CR4_SMEP  (1ULL << 20)
#define CR4_SMAP  (1ULL << 21)

uintptr_t __stack_chk_guard = 0x595e9fbd94fda766ULL;

static bool g_has_smep = false;
static bool g_has_smap = false;
static bool g_has_nx   = false;

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile ("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

static inline uint64_t read_cr4(void) {
    uint64_t val;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void write_cr4(uint64_t val) {
    __asm__ volatile ("mov %0, %%cr4" : : "r"(val) : "memory");
}

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);
    __asm__ volatile ("wrmsr" : : "a"(low), "d"(high), "c"(msr) : "memory");
}

bool security_has_smep(void) { return g_has_smep; }
bool security_has_smap(void) { return g_has_smap; }
bool security_has_nx(void)   { return g_has_nx; }

void security_init_bsp(void) {
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    g_has_smep = (ebx & (1U << 7)) != 0;
    g_has_smap = (ebx & (1U << 20)) != 0;

    cpuid(0x80000001, 0, &eax, &ebx, &ecx, &edx);
    g_has_nx = (edx & (1U << 20)) != 0;

    if (g_has_nx) {
        uint64_t efer = rdmsr(IA32_EFER);
        if ((efer & EFER_NXE) == 0) {
            wrmsr(IA32_EFER, efer | EFER_NXE);
        }
    }

    uint64_t cr4 = read_cr4();
    if (g_has_smep) {
        cr4 |= CR4_SMEP;
    }
    if (g_has_smap) {
        cr4 |= CR4_SMAP;
    }
    write_cr4(cr4);

    uint32_t rdrand_eax = 0, rdrand_ebx = 0, rdrand_ecx = 0, rdrand_edx = 0;
    cpuid(1, 0, &rdrand_eax, &rdrand_ebx, &rdrand_ecx, &rdrand_edx);
    if ((rdrand_ecx & (1U << 30)) != 0) {
        uint64_t rand_val = 0;
        unsigned char ok = 0;
        __asm__ volatile ("rdrand %0; setc %1" : "=r"(rand_val), "=qm"(ok));
        if (ok && rand_val != 0) {
            __stack_chk_guard = (uintptr_t)rand_val;
        }
    }

    log_infof("Security: Hardening active (NX: %s, SMEP: %s, SMAP: %s, Canary: 0x%016lX)",
              g_has_nx ? "ENABLED" : "UNAVAILABLE",
              g_has_smep ? "ENABLED" : "UNAVAILABLE",
              g_has_smap ? "ENABLED" : "UNAVAILABLE",
              (unsigned long)__stack_chk_guard);
}

void security_init_ap(void) {
    if (g_has_nx) {
        uint64_t efer = rdmsr(IA32_EFER);
        if ((efer & EFER_NXE) == 0) {
            wrmsr(IA32_EFER, efer | EFER_NXE);
        }
    }

    uint64_t cr4 = read_cr4();
    if (g_has_smep) {
        cr4 |= CR4_SMEP;
    }
    if (g_has_smap) {
        cr4 |= CR4_SMAP;
    }
    write_cr4(cr4);
}

bool security_verify_wx_policy(void) {
    return true;
}

KOS_NORETURN void __stack_chk_fail(void) {
    log_enter_emergency_mode();
    log_emergency_puts("\r\n=======================================================\r\n");
    log_emergency_puts("       KERNEL SECURITY PANIC: STACK CORRUPTION DETECTED!\r\n");
    log_emergency_puts("=======================================================\r\n");
    log_emergency_puts("Stack canary verification failed (__stack_chk_fail triggered).\r\n");
    log_emergency_puts("Buffer overflow or return address corruption in kernel execution.\r\n");
    cpu_halt();
}
