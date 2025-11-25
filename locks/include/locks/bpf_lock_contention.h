/*
 * BPF Lock Contention Monitoring - Data Structures
 *
 * This file defines the core data structures used in the BPF maps for
 * tracking lock contention.
 */

#ifndef _BPF_LOCK_CONTENTION_H
#define _BPF_LOCK_CONTENTION_H

#include <vmlinux.h>  // For TASK_COMM_LEN

// Latency aggregation value (Per-TGID aggregation)
typedef struct {
    uint64_t sum;
    uint64_t count;
    uint64_t max;
    uint64_t min;
    char comm[TASK_COMM_LEN];
} latency_t;

#define LOCK_NAME_LEN 32

// Map Key: Lock Name + PID + TID (For per-thread latency tracking)
typedef struct {
    uint32_t pid;                   // Process ID (TGID in kernel)
    uint32_t tid;                   // Thread ID (PID in kernel),
                                    // needed for tracking contention
                                    // among multiple threads.
    char lock_name[LOCK_NAME_LEN];  // The lock name
} contention_key_t;

// Map Key: Lock Name + PID (For per-process latency aggregation)
typedef struct {
    uint32_t pid;                   // Process ID (TGID in kernel)
    char lock_name[LOCK_NAME_LEN];  // The lock name
} latency_key_t;

#endif /* _BPF_LOCK_CONTENTION_H */
