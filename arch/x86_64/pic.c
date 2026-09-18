#include <stdbool.h>
#include <stdint.h>

#include <kos/io.h>
#include <kos/pic.h>

enum {
    PIC_MASTER_COMMAND = 0x20,
    PIC_MASTER_DATA = 0x21,
    PIC_SLAVE_COMMAND = 0xa0,
    PIC_SLAVE_DATA = 0xa1,
    PIC_INITIALIZE = 0x11,
    PIC_8086_MODE = 0x01,
    PIC_END_OF_INTERRUPT = 0x20,
    PIC_READ_ISR = 0x0b,
    PIC_SLAVE_CASCADE_IRQ = 2,
};

static uint8_t master_mask = 0xff;
static uint8_t slave_mask = 0xff;
static bool initialized;

static void pic_write_masks(void) {
    io_out8(PIC_MASTER_DATA, master_mask);
    io_out8(PIC_SLAVE_DATA, slave_mask);
}

static uint8_t pic_read_isr(uint16_t command_port) {
    io_out8(command_port, PIC_READ_ISR);
    return io_in8(command_port);
}

bool pic_initialize(void) {
    io_out8(PIC_MASTER_COMMAND, PIC_INITIALIZE);
    io_wait();
    io_out8(PIC_SLAVE_COMMAND, PIC_INITIALIZE);
    io_wait();

    io_out8(PIC_MASTER_DATA, KOS_PIC_MASTER_VECTOR);
    io_wait();
    io_out8(PIC_SLAVE_DATA, KOS_PIC_SLAVE_VECTOR);
    io_wait();

    io_out8(PIC_MASTER_DATA, 1u << PIC_SLAVE_CASCADE_IRQ);
    io_wait();
    io_out8(PIC_SLAVE_DATA, PIC_SLAVE_CASCADE_IRQ);
    io_wait();

    io_out8(PIC_MASTER_DATA, PIC_8086_MODE);
    io_wait();
    io_out8(PIC_SLAVE_DATA, PIC_8086_MODE);
    io_wait();

    master_mask = 0xff;
    slave_mask = 0xff;
    pic_write_masks();
    initialized = true;
    return true;
}

bool pic_unmask_irq(uint8_t irq) {
    if (!initialized || irq >= 16) {
        return false;
    }
    if (irq < 8) {
        master_mask &= (uint8_t)~(1u << irq);
    }
    else {
        slave_mask &= (uint8_t)~(1u << (irq - 8));
        master_mask &= (uint8_t)~(1u << PIC_SLAVE_CASCADE_IRQ);
    }
    pic_write_masks();
    return true;
}

bool pic_is_spurious_irq(uint8_t irq) {
    if (!initialized) {
        return false;
    }
    if (irq == 7) {
        return (pic_read_isr(PIC_MASTER_COMMAND) & 0x80) == 0;
    }
    if (irq == 15) {
        return (pic_read_isr(PIC_SLAVE_COMMAND) & 0x80) == 0;
    }
    return false;
}

void pic_send_spurious_eoi(uint8_t irq) {
    if (initialized && irq == 15) {
        io_out8(PIC_MASTER_COMMAND, PIC_END_OF_INTERRUPT);
    }
}

void pic_send_eoi(uint8_t irq) {
    if (!initialized || irq >= 16) {
        return;
    }
    if (irq >= 8) {
        io_out8(PIC_SLAVE_COMMAND, PIC_END_OF_INTERRUPT);
    }
    io_out8(PIC_MASTER_COMMAND, PIC_END_OF_INTERRUPT);
}

void pic_disable(void) {
    master_mask = 0xff;
    slave_mask = 0xff;
    pic_write_masks();
    initialized = false;
}
