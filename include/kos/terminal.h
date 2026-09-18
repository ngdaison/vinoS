#ifndef KOS_TERMINAL_H
#define KOS_TERMINAL_H

#include <stdbool.h>

#include <kos/compiler.h>

bool terminal_initialize(void);
KOS_NORETURN void terminal_run(void);

#endif
