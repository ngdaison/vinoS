OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    requests PT_LOAD FLAGS(4);
    text     PT_LOAD FLAGS(5);
    rodata   PT_LOAD FLAGS(4);
    data     PT_LOAD FLAGS(6);
}

SECTIONS
{
    /* Higher-half kernel address; Limine builds the required mappings. */
    . = 0xffffffff80000000;

    .limine_requests : ALIGN(8)
    {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text :
    {
        __kernel_text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        __kernel_text_end = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata :
    {
        __kernel_rodata_start = .;
        *(.rodata .rodata.*)
        __kernel_rodata_end = .;
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data :
    {
        __kernel_data_start = .;
        *(.data .data.*)
        __kernel_data_end = .;
    } :data

    .bss (NOLOAD) : ALIGN(16)
    {
        __kernel_bss_start = .;
        *(COMMON)
        *(.bss .bss.*)
        __kernel_bss_end = .;
    } :data

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
