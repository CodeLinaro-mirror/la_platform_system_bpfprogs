/*
 * cyclePerUid eBPF program
 *
 * Copyright (C) 2025 Google
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <android_bpf_defs.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

#ifdef USE_VMLINUX
#include <vmlinux.h>
#endif

#include <bpf_cycleperuid.h>

DEFINE_BPF_MAP_GRW(last_recorded_cycle_map, PERCPU_ARRAY, uint32_t, uint64_t, 1, AID_SYSTEM)
DEFINE_BPF_MAP_GRW(last_running_pid_map, PERCPU_ARRAY, uint32_t, pid_t, 1, AID_SYSTEM)
DEFINE_BPF_MAP_GRW(uid_cpu_cycle_map, LRU_PERCPU_HASH, uint32_t, uint64_t, MAX_TRACKED_UIDS,
                   AID_SYSTEM)
DEFINE_BPF_MAP_GRW(tsc_events, PERF_EVENT_ARRAY, uint32_t, int, MAX_CPUS, AID_SYSTEM)
DEFINE_BPF_MAP_GRW(desync_counter, PERCPU_ARRAY, uint32_t, uint64_t, 1, AID_SYSTEM)

/**
 * This BPF program is attached to the sched:sched_switch tracepoint.
 * On each context switch, it calculates the CPU cycles consumed by the
 * task that is being switched out (prev) and attributes those
 * cycles to its UID.
 */
DEFINE_BPF_PROG("tp_btf/sched_switch", AID_ROOT, AID_SYSTEM, tp_sched_switch)
(uint64_t* args) {
    const int ALLOW = 1;  // return 1 to avoid blocking simpleperf from receiving events.
    uint32_t zero = 0;
    uint32_t cpu_id = bpf_get_smp_processor_id();
    if (cpu_id >= MAX_CPUS) return ALLOW;

    // Read the current TSC value from the perf event for the current CPU
    struct bpf_perf_event_value tsc_val;
    long ret = bpf_perf_event_read_value(&tsc_events, cpu_id, &tsc_val, sizeof(tsc_val));
    if (ret != 0) {
        // Perf event for this CPU might not be set up, or another error occurred.
        return ALLOW;
    }
    uint64_t current_cycle = tsc_val.counter;

    // Query and update last cycle that we see this CPU.
    // |delta_cycle| is the number of CPU cycles consumed by the last running pid.
    uint64_t* last_recorded_cycle_ptr = bpf_last_recorded_cycle_map_lookup_elem(&zero);
    if (!last_recorded_cycle_ptr) return ALLOW;
    uint64_t last_recorded_cycle = *last_recorded_cycle_ptr;
    *last_recorded_cycle_ptr = current_cycle;

    // After resuming from suspend, the sched_switch event for the newly
    // scheduled task can have a prev_pid of 0 twice. We store the last seen PID
    // to detect this so that we can attribute cycles when the pid of the
    // task being unscheduled matches the previous one scheduled.
    pid_t* last_pid_ptr = bpf_last_running_pid_map_lookup_elem(&zero);
    if (!last_pid_ptr) return ALLOW;
    pid_t last_pid = *last_pid_ptr;

    // tp_btf/sched_switch(bool preempt, struct task_struct *prev, struct task_struct *next,
    // unsigned int prev_state)
    struct task_struct* prev = (struct task_struct*)args[1];
    struct task_struct* next = (struct task_struct*)args[2];
    *last_pid_ptr = next->pid;
    pid_t pid = prev->pid;

    // We can only account for cycles if we have a valid previous pid and a previous
    // cycle count to diff against.
    // * pid = 0 means the CPU was idle, so we can't attribute cycles.
    // * last_recorded_cycle = 0 means this is the first event on this CPU.
    // * pid != last_pid: See the detailed explanation above regarding suspend/resume.
    if (!pid || !last_recorded_cycle || pid != last_pid) {
        if (pid != last_pid) {
            uint64_t* desync_count = bpf_desync_counter_lookup_elem(&zero);
            if (desync_count) {
                *desync_count += 1;
            }
        }
        return ALLOW;
    }

    // In the sched_switch tracepoint, the current is the task being switched out.
    // So this is the uid_gid of the prev_pid.
    unsigned long long uid_gid = bpf_get_current_uid_gid();
    if (uid_gid == (unsigned long long)(-EINVAL)) return ALLOW;

    // Extract the uid part of the uid_gid value returned from the kernel.
    uint32_t uid = uid_gid & 0xFFFFFFFF;

    // The Time Stamp Counter (TSC) is a 64-bit counter. Wraparound is not a practical
    // concern as it would take over 100 years for a 5GHz CPU.
    uint64_t delta_cycle = current_cycle - last_recorded_cycle;

    // Retrieve the UID's existing cycle count, add the delta, and update the map.
    uint64_t* uid_cpu_cycle_ptr = bpf_uid_cpu_cycle_map_lookup_elem(&uid);
    if (uid_cpu_cycle_ptr) {
        *uid_cpu_cycle_ptr += delta_cycle;
    } else {
        bpf_uid_cpu_cycle_map_update_elem(&uid, &delta_cycle, BPF_NOEXIST);
    }

    return ALLOW;
}

LICENSE("GPL");
