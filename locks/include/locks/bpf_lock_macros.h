/*
 * BPF Lock Contention Monitoring - Macro Engine
 *
 * This header provides a multi-pass macro-based system for generating
 * enums and functions to identify and name kernel locks. The design is
 * inspired by the Linux kernel's TRACE_EVENT() macro system.
 *
 * It works in conjunction with bpf_lock_list.h, which defines the lists
 * of locks to be traced using the __GL (Global Lock) and __DL (Dynamic Lock)
 * macros. This engine then consumes those lists to generate the necessary
 * BPF helper code.
 */

#ifndef _BPF_LOCK_MACROS_H
#define _BPF_LOCK_MACROS_H

#include "bpf_lock_list.h"

// This header is self-contained and generates code in multiple passes.

// --- Pass 1: Generate ENUMs for both Global and Dynamic locks ---
#undef __GL
#define __GL(lock) ENUM_##lock,
#undef __DL
#define __DL(lock, path) ENUM_##lock,

enum lock_ids { GLOBAL_LOCKS_LIST DYNAMIC_LOCKS_LIST LOCK_ID_UNKNOWN };

// --- Pass 2: Generate extern symbol declarations (conditional) ---
#undef __GL
// Allow weak symbols to accommodate renames of global locks across kernel
// versions.
#define __GL(lock) extern void lock __ksym __weak;
#undef __DL
#define __DL(lock, path) /* Dynamic locks don't need separate declarations */
GLOBAL_LOCKS_LIST

// --- Pass 3: Generate the get_lock_id() function ---
#undef __GL
#define __GL(lock) \
    if ((uint64_t)&lock == lock_addr) return ENUM_##lock;
#undef __DL
#define __DL(lock, path) \
    if ((uint64_t)&task->path == lock_addr) return ENUM_##lock;

static inline uint64_t get_lock_id(uint64_t lock_addr, struct task_struct* task) {
    // Global locks are checked first
    GLOBAL_LOCKS_LIST

    // Then, check dynamic locks relative to the task struct
    if (task) {
        DYNAMIC_LOCKS_LIST
    }

    return LOCK_ID_UNKNOWN;
}

// --- Pass 4: Generate the get_lock_name() function ---
#undef __GL
#define __GL(lock) \
    if (lock_id == ENUM_##lock) return #lock;
#undef __DL
#define __DL(lock, path) \
    if (lock_id == ENUM_##lock) return #lock;

static const char* get_lock_name(uint64_t lock_id) {
    GLOBAL_LOCKS_LIST
    DYNAMIC_LOCKS_LIST
    if (lock_id == LOCK_ID_UNKNOWN) return "UNKNOWN";
    return "ERROR";
}

// --- Cleanup ---
#undef __GL
#undef __DL

#endif /* _BPF_LOCK_MACROS_H */
