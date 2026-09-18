#ifndef KOS_SYNC_H
#define KOS_SYNC_H

/*
 * KOS Synchronization Subsystem (K12.5 - K12.7)
 * Header umbrella forwarding to modular synchronization components:
 * - <kos/atomic.h>: Standardized Atomic Primitives & Memory Barriers (K12.5)
 * - <kos/spinlock.h>: Spinlocks with IRQ safety (K12.6)
 */

#include <kos/atomic.h>
#include <kos/spinlock.h>

#endif /* KOS_SYNC_H */
