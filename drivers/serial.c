#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/io.h>
#include <kos/serial.h>

enum {
    COM1 = 0x3f8,
    COM_DATA = 0,
    COM_INTERRUPT_ENABLE = 1,
    COM_FIFO_CONTROL = 2,
    COM_LINE_CONTROL = 3,
    COM_MODEM_CONTROL = 4,
    COM_LINE_STATUS = 5,
    COM_TRANSMITTER_EMPTY = 0x20,
    SERIAL_TRANSMIT_SPIN_LIMIT = 1000000,
    SERIAL_EMERGENCY_SPIN_LIMIT = 100000,
};

static bool serial_initialized;

void serial_emergency_init(void) {
    /* Disable all UART interrupts */
    io_out8(COM1 + COM_INTERRUPT_ENABLE, 0x00);
    /* Enable DLAB (set baud rate divisor) */
    io_out8(COM1 + COM_LINE_CONTROL, 0x80);
    /* Set divisor to 1 (115200 baud) */
    io_out8(COM1 + COM_DATA, 0x01);
    io_out8(COM1 + COM_INTERRUPT_ENABLE, 0x00);
    /* 8 bits, no parity, 1 stop bit, clear DLAB */
    io_out8(COM1 + COM_LINE_CONTROL, 0x03);
    /* Enable FIFO, clear TX/RX FIFOs, 14-byte threshold */
    io_out8(COM1 + COM_FIFO_CONTROL, 0xc7);
    /* Enable DTR, RTS and auxiliary output 2 */
    io_out8(COM1 + COM_MODEM_CONTROL, 0x0b);
    serial_initialized = true;
}

void serial_initialize(void) {
    serial_emergency_init();
}

bool serial_is_initialized(void) {
    return serial_initialized;
}

static inline void serial_emergency_ensure_ready(void) {
    if (!serial_initialized) {
        serial_emergency_init();
    } else {
        /*
         * Self-healing check: If DLAB (bit 7) was inadvertently left set or
         * line control settings were corrupted during a crash, writing to
         * COM_DATA (0x3F8) alters the baud rate divisor instead of transmitting.
         * Force LCR back to standard 8N1 (DLAB=0).
         */
        uint8_t lcr = io_in8(COM1 + COM_LINE_CONTROL);
        if ((lcr & 0x80) != 0 || (lcr & 0x1f) != 0x03) {
            io_out8(COM1 + COM_LINE_CONTROL, 0x03);
        }
    }
}

static inline bool serial_emergency_wait_tx_ready(void) {
    for (uint32_t spin = 0; spin < SERIAL_EMERGENCY_SPIN_LIMIT; ++spin) {
        if ((io_in8(COM1 + COM_LINE_STATUS) & COM_TRANSMITTER_EMPTY) != 0) {
            return true;
        }
        cpu_pause();
    }
    return false;
}

static inline void serial_emergency_raw_putc(uint8_t byte) {
    if (serial_emergency_wait_tx_ready()) {
        io_out8(COM1 + COM_DATA, byte);
    }
}

void serial_emergency_putc(char c) {
    serial_emergency_ensure_ready();

    /* Automatic CRLF translation: '\n' -> '\r\n' */
    if (c == '\n') {
        serial_emergency_raw_putc((uint8_t)'\r');
    }
    serial_emergency_raw_putc((uint8_t)c);
}

void serial_emergency_puts(const char *s) {
    if (s == 0) {
        return;
    }
    serial_emergency_ensure_ready();
    while (*s != '\0') {
        serial_emergency_putc(*s);
        ++s;
    }
}

void serial_emergency_put_hex(uint64_t value) {
    static const char hex_digits[] = "0123456789ABCDEF";
    serial_emergency_puts("0x");
    for (int shift = 60; shift >= 0; shift -= 4) {
        serial_emergency_putc(hex_digits[(value >> shift) & 0x0f]);
    }
}

void serial_emergency_put_dec(uint64_t value) {
    if (value == 0) {
        serial_emergency_putc('0');
        return;
    }
    char buf[24];
    int pos = 0;
    while (value > 0) {
        buf[pos++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (pos > 0) {
        serial_emergency_putc(buf[--pos]);
    }
}

void serial_write_char(char character) {
    serial_emergency_putc(character);
}

void serial_write(const char *text) {
    serial_emergency_puts(text);
}
