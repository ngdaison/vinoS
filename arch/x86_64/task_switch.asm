bits 64
default rel

global task_switch

section .text

; void task_switch(struct task_context *old, const struct task_context *next)
; Save callee-saved state and RFLAGS for current C call chain, then jump to next.
task_switch:
    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], r12
    mov [rdi + 24], r13
    mov [rdi + 32], r14
    mov [rdi + 40], r15
    mov [rdi + 48], rsp
    lea rax, [rel .resume]
    mov [rdi + 56], rax

    mov rbx, [rsi + 0]
    mov rbp, [rsi + 8]
    mov r12, [rsi + 16]
    mov r13, [rsi + 24]
    mov r14, [rsi + 32]
    mov r15, [rsi + 40]
    mov rsp, [rsi + 48]
    push qword [rsi + 64]
    popfq
    jmp qword [rsi + 56]
.resume:
    ret
