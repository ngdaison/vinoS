bits 64
default rel

global kos_syscall_entry
extern kos_syscall_dispatch_frame

section .text

; Fast Syscall Hardware Entry Point (Target of IA32_LSTAR)
; On entry via syscall:
;   RCX = user RIP
;   R11 = user RFLAGS
;   RSP = user RSP
;   RAX = syscall number
;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4, R9 = arg5
kos_syscall_entry:
    swapgs                      ; Switch to per-CPU kernel data
    mov [gs:8], rsp             ; Save user RSP in percpu->user_rsp
    mov rsp, [gs:0]             ; Switch to percpu->kernel_rsp

    ; Push user execution context to construct struct syscall_frame on kernel stack
    push qword [gs:8]           ; [rsp + 120] user RSP
    push r11                    ; [rsp + 112] user RFLAGS
    push rcx                    ; [rsp + 104] user RIP
    push rax                    ; [rsp + 96]  syscall number (will hold return value)
    push rdi                    ; [rsp + 88]  arg0
    push rsi                    ; [rsp + 80]  arg1
    push rdx                    ; [rsp + 72]  arg2
    push r10                    ; [rsp + 64]  arg3
    push r8                     ; [rsp + 56]  arg4
    push r9                     ; [rsp + 48]  arg5
    push rbx                    ; [rsp + 40]
    push rbp                    ; [rsp + 32]
    push r12                    ; [rsp + 24]
    push r13                    ; [rsp + 16]
    push r14                    ; [rsp + 8]
    push r15                    ; [rsp + 0]

    ; Call C Syscall Dispatcher: uint64_t kos_syscall_dispatch_frame(struct syscall_frame *frame)
    mov rdi, rsp
    call kos_syscall_dispatch_frame

    ; Store return value in frame->rax slot
    mov [rsp + 12*8], rax

    ; Restore preserved user registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop rax                     ; Return value in RAX
    pop rcx                     ; User RIP restored into RCX for sysretq
    pop r11                     ; User RFLAGS restored into R11 for sysretq
    pop rsp                     ; Restore user RSP

    swapgs                      ; Switch back to user GS
    o64 sysret                  ; Return to Ring 3 (sysretq)\n