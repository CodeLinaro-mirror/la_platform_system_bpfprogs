/*
 * Lock Contention - eBPF programs for Global Locks
 *
 * This program measures contention latency on selected global kernel locks,
 * leveraging a multi-pass macro system for easy maintenance.
 */
#include <android_bpf_defs.h>
#include <bpf/bpf_helpers.h>
#include <vmlinux.h>  // Provides task_struct, etc.

// The macro engine to generate the lock enum and functions
#include <locks/bpf_lock_macros.h>

// Data structures for BPF maps
#include <locks/bpf_lock_contention.h>

// --- BPF Maps ---

// Contention Latency Map (Aggregation: keyed by {tgid, 0, lock_name})
DEFINE_BPF_MAP_GRW(contention_latency_map, HASH, latency_key_t, latency_t, 4096, AID_SYSTEM)

// Contention Start Map (In-flight tracking: keyed by {tgid, tid, lock_name})
// This map stores the start timestamp (uint64_t)
DEFINE_BPF_MAP_GRW(contention_start_map, HASH, contention_key_t, uint64_t, 4096, AID_SYSTEM)

// --- Tracepoint Handlers ---

DEFINE_BPF_PROG("tp/lock/contention_begin", AID_ROOT, AID_SYSTEM,
                tracepoint_lock_contention_begin)(struct trace_event_raw_contention_begin* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
    if (!task) return 0;

    uint64_t lock_addr = (uint64_t)ctx->lock_addr;

    // Use the generated function to map address to ID
    uint64_t lock_id = get_lock_id(lock_addr, task);
    if (lock_id == LOCK_ID_UNKNOWN) return 0;

    // Capture the contention start time
    uint64_t now = bpf_ktime_get_ns();

    // Key for contention_start_map (Per-Thread Tracking)
    contention_key_t key = {
            .pid = task->tgid,
            .tid = task->pid,
    };

    bpf_probe_read_kernel_str(key.lock_name, LOCK_NAME_LEN, get_lock_name(lock_id));

    // Store the start time
    bpf_contention_start_map_update_elem(&key, &now, BPF_ANY);

    return 0;
}

DEFINE_BPF_PROG("tp/lock/contention_end", AID_ROOT, AID_SYSTEM,
                tracepoint_lock_contention_end)(struct trace_event_raw_contention_end* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
    if (!task) return 0;

    uint64_t lock_addr = (uint64_t)ctx->lock_addr;
    uint64_t lock_id = get_lock_id(lock_addr, task);
    if (lock_id == LOCK_ID_UNKNOWN) return 0;

    // Capture the contention end time
    uint64_t now = bpf_ktime_get_ns();

    // 1. Key for start_map lookup and delete (Per-Thread Key)
    contention_key_t start_key = {
            .pid = task->tgid,
            .tid = task->pid,
    };
    bpf_probe_read_kernel_str(start_key.lock_name, LOCK_NAME_LEN, get_lock_name(lock_id));

    uint64_t* prev_start_time_ptr = bpf_contention_start_map_lookup_elem(&start_key);

    // Did not find the start event
    if (!prev_start_time_ptr) return 0;

    // Copy the value before deleting the map entry
    uint64_t prev_start_time = *prev_start_time_ptr;

    // Delete the element immediately after lookup
    bpf_contention_start_map_delete_elem(&start_key);

    uint64_t delta = now - prev_start_time;

    // 2. Key for latency_map aggregation (Per-Process Key)
    latency_key_t latency_key = {
            .pid = start_key.pid,
    };
    bpf_probe_read_kernel_str(latency_key.lock_name, LOCK_NAME_LEN, start_key.lock_name);

    latency_t* prev_latency = bpf_contention_latency_map_lookup_elem(&latency_key);

    if (!prev_latency) {
        // First time: initialize the entry
        latency_t new_latency = {
                .sum = delta,
                .count = 1,
                .max = delta,
                .min = delta,
        };
        // Capture comm only on creation
        bpf_get_current_comm(new_latency.comm, TASK_COMM_LEN);
        bpf_contention_latency_map_update_elem(&latency_key, &new_latency, BPF_NOEXIST);
        return 0;
    }

    // Update sum and count atomically
    __sync_fetch_and_add(&prev_latency->sum, delta);
    __sync_fetch_and_add(&prev_latency->count, 1);

    // Use racy but simpler updates for min/max
    if (delta > prev_latency->max) prev_latency->max = delta;
    if (delta < prev_latency->min) prev_latency->min = delta;

    // Commit changes
    bpf_contention_latency_map_update_elem(&latency_key, prev_latency, BPF_EXIST);

    return 0;
}

LICENSE("GPL");
