#ifndef KOS_HANDLE_H
#define KOS_HANDLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/object.h>
#include <kos/spinlock.h>

/*
 * Rights and Access Masks (K12.15)
 */
#define KOS_RIGHT_NONE        0x00000000U
#define KOS_RIGHT_READ        (1U << 0)
#define KOS_RIGHT_WRITE       (1U << 1)
#define KOS_RIGHT_EXECUTE     (1U << 2)
#define KOS_RIGHT_WAIT        (1U << 3)
#define KOS_RIGHT_SIGNAL      (1U << 4)
#define KOS_RIGHT_DUPLICATE   (1U << 5)
#define KOS_RIGHT_TRANSFER    (1U << 6)
#define KOS_RIGHT_DESTROY     (1U << 7)
#define KOS_RIGHT_ALL         0xFFFFFFFFU

/*
 * Handle Encoding (K12.15):
 * 32-bit handle = 16-bit Generation (upper) + 16-bit Table Index (lower).
 * Prevents stale handle access / ABA handle reuse.
 */
typedef uint32_t handle_t;

#define KOS_INVALID_HANDLE    0U

#define KOS_HANDLE_INDEX_MASK 0x0000FFFFU
#define KOS_HANDLE_GEN_MASK   0xFFFF0000U
#define KOS_HANDLE_GEN_SHIFT  16U

#define KOS_HANDLE_INDEX(h)   ((uint16_t)((h) & KOS_HANDLE_INDEX_MASK))
#define KOS_HANDLE_GEN(h)     ((uint16_t)(((h) >> KOS_HANDLE_GEN_SHIFT) & 0xFFFFU))
#define KOS_MAKE_HANDLE(idx, gen) \
    (((uint32_t)(gen) << KOS_HANDLE_GEN_SHIFT) | ((uint32_t)(idx) & KOS_HANDLE_INDEX_MASK))

#define KOS_HANDLE_TABLE_CAPACITY 64

struct handle_entry {
    struct kos_object_header *object;
    uint32_t rights;
    uint16_t generation;
    bool in_use;
};

struct handle_table {
    struct handle_entry entries[KOS_HANDLE_TABLE_CAPACITY];
    kos_spinlock_t lock;
    uint32_t count;
};

/* Forward declaration */
struct process;

/* Handle Table Management APIs */
struct handle_table *handle_table_create(void);
void handle_table_destroy(struct handle_table *table);

/* Handle Lifecycle and Rights APIs */
handle_t handle_create(struct process *proc, void *object, uint32_t rights);
void *handle_lookup(struct process *proc, handle_t handle, uint32_t required_rights);
void *handle_lookup_type(struct process *proc, handle_t handle, enum kos_object_type type, uint32_t required_rights);
bool handle_close(struct process *proc, handle_t handle);
handle_t handle_duplicate(struct process *src_proc, struct process *dst_proc, handle_t handle, uint32_t new_rights);

#endif /* KOS_HANDLE_H */
