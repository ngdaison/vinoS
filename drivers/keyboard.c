#include <stdbool.h>
#include <stdint.h>

#include <kos/io.h>
#include <kos/keyboard.h>

enum {
    PS2_DATA_PORT = 0x60,
    PS2_STATUS_PORT = 0x64,
    PS2_COMMAND_PORT = 0x64,
    PS2_STATUS_OUTPUT_BUFFER_FULL = 0x01,
    PS2_STATUS_INPUT_BUFFER_FULL = 0x02,
    PS2_COMMAND_READ_CONFIGURATION = 0x20,
    PS2_COMMAND_WRITE_CONFIGURATION = 0x60,
    PS2_COMMAND_ENABLE_FIRST_PORT = 0xae,
    PS2_CONFIGURATION_FIRST_PORT_INTERRUPT = 0x01,
    PS2_CONFIGURATION_FIRST_PORT_CLOCK_DISABLED = 0x10,
    PS2_CONFIGURATION_TRANSLATION = 0x40,
    PS2_WAIT_SPIN_LIMIT = 1000000,
    PS2_FLUSH_LIMIT = 64,
    KEYBOARD_BUFFER_CAPACITY = 256,
    KEYBOARD_BUFFER_MASK = KEYBOARD_BUFFER_CAPACITY - 1,
    KEYBOARD_BREAK_CODE = 0x80,
    KEYBOARD_EXTENDED_PREFIX = 0xe0,
    KEYBOARD_LEFT_SHIFT = 0x2a,
    KEYBOARD_RIGHT_SHIFT = 0x36,
    KEYBOARD_LEFT_SHIFT_HELD = 1,
    KEYBOARD_RIGHT_SHIFT_HELD = 2,
};

static char input_buffer[KEYBOARD_BUFFER_CAPACITY];
static volatile uint16_t input_head;
static volatile uint16_t input_tail;
static volatile uint64_t dropped_characters;
static bool initialized;
static uint8_t modifier_state;
static bool extended_scancode;

static bool keyboard_wait_input_empty(void) {
    for (uint64_t spin = 0; spin < PS2_WAIT_SPIN_LIMIT; ++spin) {
        if ((io_in8(PS2_STATUS_PORT) & PS2_STATUS_INPUT_BUFFER_FULL) == 0) {
            return true;
        }
    }
    return false;
}

static bool keyboard_wait_output_full(void) {
    for (uint64_t spin = 0; spin < PS2_WAIT_SPIN_LIMIT; ++spin) {
        if ((io_in8(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_BUFFER_FULL) != 0) {
            return true;
        }
    }
    return false;
}

static void keyboard_flush_output(void) {
    for (uint64_t count = 0; count < PS2_FLUSH_LIMIT; ++count) {
        if ((io_in8(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_BUFFER_FULL) == 0) {
            return;
        }
        (void)io_in8(PS2_DATA_PORT);
    }
}

static void keyboard_enqueue(char character) {
    uint16_t head = input_head;
    uint16_t next_head = (uint16_t)((head + 1) & KEYBOARD_BUFFER_MASK);
    if (next_head == input_tail) {
        ++dropped_characters;
        return;
    }
    input_buffer[head] = character;
    input_head = next_head;
}

static char keyboard_translate_scancode(uint8_t scancode) {
    static const char unshifted[128] = {
        [0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4', [0x06] = '5',
        [0x07] = '6', [0x08] = '7', [0x09] = '8', [0x0a] = '9', [0x0b] = '0',
        [0x0c] = '-', [0x0d] = '=', [0x0e] = '\b', [0x0f] = '\t',
        [0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r', [0x14] = 't',
        [0x15] = 'y', [0x16] = 'u', [0x17] = 'i', [0x18] = 'o', [0x19] = 'p',
        [0x1a] = '[', [0x1b] = ']', [0x1c] = '\n',
        [0x1e] = 'a', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f', [0x22] = 'g',
        [0x23] = 'h', [0x24] = 'j', [0x25] = 'k', [0x26] = 'l', [0x27] = ';',
        [0x28] = '\'', [0x29] = '`', [0x2b] = '\\',
        [0x2c] = 'z', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v', [0x30] = 'b',
        [0x31] = 'n', [0x32] = 'm', [0x33] = ',', [0x34] = '.', [0x35] = '/',
        [0x39] = ' ',
    };
    static const char shifted[128] = {
        [0x02] = '!', [0x03] = '@', [0x04] = '#', [0x05] = '$', [0x06] = '%',
        [0x07] = '^', [0x08] = '&', [0x09] = '*', [0x0a] = '(', [0x0b] = ')',
        [0x0c] = '_', [0x0d] = '+', [0x0e] = '\b', [0x0f] = '\t',
        [0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R', [0x14] = 'T',
        [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I', [0x18] = 'O', [0x19] = 'P',
        [0x1a] = '{', [0x1b] = '}', [0x1c] = '\n',
        [0x1e] = 'A', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F', [0x22] = 'G',
        [0x23] = 'H', [0x24] = 'J', [0x25] = 'K', [0x26] = 'L', [0x27] = ':',
        [0x28] = '"', [0x29] = '~', [0x2b] = '|',
        [0x2c] = 'Z', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V', [0x30] = 'B',
        [0x31] = 'N', [0x32] = 'M', [0x33] = '<', [0x34] = '>', [0x35] = '?',
        [0x39] = ' ',
    };

    return modifier_state != 0 ? shifted[scancode] : unshifted[scancode];
}

bool keyboard_initialize(void) {
    uint8_t configuration;

    initialized = false;
    input_head = 0;
    input_tail = 0;
    dropped_characters = 0;
    modifier_state = 0;
    extended_scancode = false;
    keyboard_flush_output();

    if (!keyboard_wait_input_empty()) {
        return false;
    }
    io_out8(PS2_COMMAND_PORT, PS2_COMMAND_READ_CONFIGURATION);
    if (!keyboard_wait_output_full()) {
        return false;
    }
    configuration = io_in8(PS2_DATA_PORT);
    configuration |= PS2_CONFIGURATION_FIRST_PORT_INTERRUPT | PS2_CONFIGURATION_TRANSLATION;
    configuration &= (uint8_t)~PS2_CONFIGURATION_FIRST_PORT_CLOCK_DISABLED;

    if (!keyboard_wait_input_empty()) {
        return false;
    }
    io_out8(PS2_COMMAND_PORT, PS2_COMMAND_WRITE_CONFIGURATION);
    if (!keyboard_wait_input_empty()) {
        return false;
    }
    io_out8(PS2_DATA_PORT, configuration);
    if (!keyboard_wait_input_empty()) {
        return false;
    }
    io_out8(PS2_COMMAND_PORT, PS2_COMMAND_ENABLE_FIRST_PORT);
    keyboard_flush_output();
    initialized = true;
    return true;
}

bool keyboard_is_initialized(void) {
    return initialized;
}

void keyboard_interrupt(void) {
    if (!initialized || (io_in8(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_BUFFER_FULL) == 0) {
        return;
    }

    uint8_t scancode = io_in8(PS2_DATA_PORT);
    if (scancode == KEYBOARD_EXTENDED_PREFIX) {
        extended_scancode = true;
        return;
    }
    if (extended_scancode) {
        extended_scancode = false;
        return;
    }

    bool released = (scancode & KEYBOARD_BREAK_CODE) != 0;
    uint8_t key = (uint8_t)(scancode & (uint8_t)~KEYBOARD_BREAK_CODE);
    if (key == KEYBOARD_LEFT_SHIFT) {
        if (released) {
            modifier_state &= (uint8_t)~KEYBOARD_LEFT_SHIFT_HELD;
        }
        else {
            modifier_state |= KEYBOARD_LEFT_SHIFT_HELD;
        }
        return;
    }
    if (key == KEYBOARD_RIGHT_SHIFT) {
        if (released) {
            modifier_state &= (uint8_t)~KEYBOARD_RIGHT_SHIFT_HELD;
        }
        else {
            modifier_state |= KEYBOARD_RIGHT_SHIFT_HELD;
        }
        return;
    }
    if (released) {
        return;
    }

    char character = keyboard_translate_scancode(key);
    if (character != '\0') {
        keyboard_enqueue(character);
    }
}

bool keyboard_read_char(char *character) {
    if (character == 0 || input_tail == input_head) {
        return false;
    }
    uint16_t tail = input_tail;
    *character = input_buffer[tail];
    input_tail = (uint16_t)((tail + 1) & KEYBOARD_BUFFER_MASK);
    return true;
}

void keyboard_push_char(char character) {
    if (character != '\0') {
        keyboard_enqueue(character);
    }
}

uint16_t keyboard_pending_count(void) {
    return (uint16_t)((input_head - input_tail) & KEYBOARD_BUFFER_MASK);
}

uint64_t keyboard_dropped_char_count(void) {
    return dropped_characters;
}
