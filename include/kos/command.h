#ifndef KOS_COMMAND_H
#define KOS_COMMAND_H

#include <stdbool.h>

/* Kernel terminal command registry. A later user-space shell will replace it. */
bool kernel_command_execute(const char *command);

#endif
