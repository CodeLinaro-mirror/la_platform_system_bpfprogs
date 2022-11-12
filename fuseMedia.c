/*
 * fuseMedia eBPF program
 *
 * Copyright (C) 2021 Google
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

#include <bpf_helpers.h>

#include <stdint.h>

#define __KERNEL__
#include <fuse_kernel.h>

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

DEFINE_BPF_PROG("fuse/media", AID_ROOT, AID_MEDIA_RW, fuse_media)
(struct fuse_bpf_args* fa) {
    switch (fa->opcode) {
        case FUSE_LOOKUP | FUSE_PREFILTER: {
            const char* name = fa->in_args[0].value;

            bpf_printk("LOOKUP_PREFILTER: %lx %s", fa->nodeid, name);
            // Using backing implementation but remove bpf_action for children files/directories
            // in the postfilter.
            return FUSE_BPF_BACKING | FUSE_BPF_POST_FILTER;
        }

        case FUSE_LOOKUP | FUSE_POSTFILTER: {
            struct fuse_entry_bpf_out* febo = fa->out_args[1].value;

            febo->bpf_action = FUSE_ACTION_REMOVE;
            return FUSE_BPF_BACKING;
        }

        default:
            return FUSE_BPF_BACKING;
    }
}

LICENSE("GPL");
