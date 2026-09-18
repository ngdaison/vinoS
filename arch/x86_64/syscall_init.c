#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/cpu.h>
#include <kos/log.h>
#include <kos/syscall.h>

#define IA32_EFER   0xC0000080
#define IA32_STAR   0xC0000081
#define IA32_LSTAR  0xC0000082
#define IA32_FMASK  0xC0000084

#define EFER_SCE    (1ULL << 0)

extern void kos_syscall_entry(void);

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

void syscall_init_core(void) {
    uint64_t efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    /* STAR[63:48] = 0x0020 (User CS/SS base), STAR[47:32] = 0x0008 (Kernel CS/SS base) */
    uint64_t star = (0x0020ULL << 48) | (0x0008ULL << 32);
    wrmsr(IA32_STAR, star);

    /* LSTAR = target RIP for 64-bit syscall */
    wrmsr(IA32_LSTAR, (uint64_t)kos_syscall_entry);

    /* FMASK = RFLAGS mask (mask IF, TF, DF, NT, IOPL, AC) */
    uint64_t fmask = 0x00040700ULL;
    wrmsr(IA32_FMASK, fmask);
}

void syscall_subsystem_init(void) {
    syscall_init_core();
    log_info("Syscall: Fast hardware entry initialized (STAR, LSTAR, FMASK configured).");
}