#ifndef KOS_SYSCALL_H
#define KOS_SYSCALL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <uapi/kos/syscall_numbers.h>

/* Complete user CPU register context saved on syscall entry */
struct syscall_frame {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r9;   /* arg5 */
    uint64_t r8;   /* arg4 */
    uint64_t r10;  /* arg3 */
    uint64_t rdx;  /* arg2 */
    uint64_t rsi;  /* arg1 */
    uint64_t rdi;  /* arg0 */
    uint64_t rax;  /* Syscall number on entry, Return value on exit */
    uint64_t rcx;  /* User RIP saved by syscall hardware */
    uint64_t r11;  /* User RFLAGS saved by syscall hardware */
    uint64_t rsp;  /* User RSP */
};

void syscall_init_core(void);
void syscall_subsystem_init(void);

uint64_t kos_syscall_dispatch_frame(struct syscall_frame *frame);

uint64_t kos_syscall_dispatch(uint64_t number, uint64_t arg0, uint64_t arg1,
                              uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);

const char *kos_syscall_name(uint64_t number);

#endif /* KOS_SYSCALL_H */