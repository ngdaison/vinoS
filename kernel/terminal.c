#include <stdbool.h>
#include <stdint.h>

#include <kos/command.h>
#include <kos/console.h>
#include <kos/cpu.h>
#include <kos/keyboard.h>
#include <kos/log.h>
#include <kos/net.h>
#include <kos/serial.h>
#include <kos/terminal.h>
#include <kos/task.h>

enum {
    TERMINAL_LINE_CAPACITY = 256,
};

static char line_buffer[TERMINAL_LINE_CAPACITY];
static uint16_t line_length;
static bool initialized;

static void terminal_write(const char *text) {
    serial_write(text);
    console_write(text);
}

static void terminal_write_char(char character) {
    serial_write_char(character);
    console_write_char(character);
}

static void terminal_show_prompt(void) {
    terminal_write("KOS> ");
}

static void terminal_handle_backspace(void) {
    if (line_length == 0) {
        return;
    }
    --line_length;
    console_write_char('\b');
    serial_write("\b \b");
}

static void terminal_execute_line(void) {
    terminal_write_char('\n');
    line_buffer[line_length] = '\0';
    if (line_length != 0 && !kernel_command_execute(line_buffer)) {
        log_error("Unknown command.");
    }
    line_length = 0;
    terminal_show_prompt();
}

static void terminal_handle_character(char character) {
    if (character == '\n') {
        terminal_execute_line();
        return;
    }
    if (character == '\b') {
        terminal_handle_backspace();
        return;
    }
    if (character >= ' ' && character <= '~' && line_length + 1 < TERMINAL_LINE_CAPACITY) {
        line_buffer[line_length] = character;
        ++line_length;
        terminal_write_char(character);
    }
}

bool terminal_initialize(void) {
    if (!keyboard_is_initialized() || initialized) {
        return false;
    }
    line_length = 0;
    initialized = true;
    log_info("KOS debug terminal ready.");
    terminal_show_prompt();
    return true;
}

KOS_NORETURN void terminal_run(void) {
    for (;;) {
        task_reschedule_if_needed();
        net_poll();
        char character;
        if (keyboard_read_char(&character)) {
            terminal_handle_character(character);
        }
        else {
            cpu_wait_for_interrupt();
        }
    }
}
