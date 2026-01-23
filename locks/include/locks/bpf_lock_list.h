/*
 * BPF Lock Contention Monitoring - Lock Definitions
 *
 * This file defines the lists of kernel locks to be monitored by the BPF
 * lock contention program. It is consumed by bpf_lock_macros.h to
 * generate the necessary BPF code.
 *
 * To add a new lock, use the following macros:
 *   __GL(lock_name): For global kernel symbols.
 *   __DL(lock_name, path_from_task_struct): For locks within a struct
 *                                           accessible from task_struct.
 */

// Global Locks (Resolved from kernel symbols)
#ifndef GLOBAL_LOCKS_LIST
#define GLOBAL_LOCKS_LIST       \
    __GL(tasklist_lock)         \
    __GL(cgroup_mutex)          \
    __GL(rtnl_mutex)            \
    __GL(rcu_state)             \
    __GL(pcpu_drain_mutex)      \
    __GL(vmap_purge_lock)       \
    __GL(freezer_mutex)         \
    __GL(buslock_sem)           \
    __GL(console_sem)           \
    __GL(dm_bufio_clients_lock) \
    __GL(list_lrus_mutex)
#endif

// Dynamic Locks (Resolved from task_struct fields)
#ifndef DYNAMIC_LOCKS_LIST
#define DYNAMIC_LOCKS_LIST                                       \
    /* Lock Name, Path from task_struct (e.g., mm->mmap_lock) */ \
    __DL(mmap_lock, mm->mmap_lock)                               \
    __DL(page_table_lock, mm->page_table_lock)                   \
    __DL(pi_lock, pi_lock)                                       \
    __DL(alloc_lock, alloc_lock)                                 \
    __DL(futex_exit_mutex, futex_exit_mutex)                     \
    __DL(perf_event_mutex, perf_event_mutex)
#endif
