//go:build ignore

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef unsigned long long u64; // Correcting the definition for u64
typedef int pid_t;
const pid_t pid_filter = 0;

struct bpf_map_def SEC("maps") counter_table = {
    // Hash Map
    .type = BPF_MAP_TYPE_HASH,
    // Key size 32bits
    .key_size = sizeof(u32),
    // Value size 64bits
    .value_size = sizeof(u64),
    // max entries in map is 1024
    .max_entries = 1024,
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // bpf_get_current_uid_gid() retrieves the current process's User ID (UID) and Group ID (GID), 
    // returning a 64-bit value where the lower 32 bits represent the UID and the upper 32 bits represent the GID.
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = bpf_map_lookup_elem(&counter_table, &uid);
    if (p) {
        counter = *p;
    }
    counter++;

    // BPF_ANY flag indicates that UPSERT
    bpf_map_update_elem(&counter_table, &uid, &counter, BPF_ANY);
    return 0;
}