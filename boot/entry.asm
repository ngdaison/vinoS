; KOS x86_64 entry point. Limine enters this symbol in 64-bit System V mode.
; Do not assume the bootloader-provided stack survives later kernel work.

bits 64
default rel

global _start
global kos_boot_stack_bottom
global kos_boot_stack_top
extern kernel_main

section .text
_start:
    cli
    cld

    lea rsp, [kos_boot_stack_top]
    and rsp, -16
    xor rbp, rbp

    call kernel_main

.halt:
    hlt
    jmp .halt

section .bss
align 16
kos_boot_stack_bottom:
    resb 65536
kos_boot_stack_top:
