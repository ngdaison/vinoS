bits 64
default rel

global gdt_load
global idt_load
global tss_load
global enter_userspace

section .text

; rdi points to a packed { uint16_t limit; uint64_t base; } descriptor.
gdt_load:
    lgdt [rdi]
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    push qword 0x08
    lea rax, [rel .reload_code_segment]
    push rax
    retfq
.reload_code_segment:
    ret

idt_load:
    lidt [rdi]
    ret

tss_load:
    mov ax, di
    ltr ax
    ret

; void enter_userspace(uint64_t entry_point, uint64_t user_rsp) __attribute__((noreturn))
; Arguments:
;   rdi: entry_point (virtual RIP to execute in user mode)
;   rsi: user_rsp    (virtual RSP user stack pointer)
enter_userspace:
    ; Disable interrupts while preparing the iretq stack frame
    cli

    ; Load data segment registers (DS, ES, FS, GS) with 0x2b (GDT_USER_DS)
    mov ax, 0x2b
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Push 5 quadwords for iretq:
    ;   [rsp + 32] SS:     0x2b (GDT_USER_DS)
    ;   [rsp + 24] RSP:    rsi  (user_rsp)
    ;   [rsp + 16] RFLAGS: 0x202 (IF=1, bit 1=1)
    ;   [rsp + 8]  CS:     0x33 (GDT_USER_CS)
    ;   [rsp + 0]  RIP:    rdi  (entry_point)
    push qword 0x2b
    push rsi
    push qword 0x202
    push qword 0x33
    push rdi

    ; Zero all general-purpose registers to prevent kernel information leakage
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    iretq
