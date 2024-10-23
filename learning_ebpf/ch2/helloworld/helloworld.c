//go:build ignore

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")

int handle_tp(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
 	if (pid_filter && pid != pid_filter)
  		return 0;
	char msg[] = "hello world";
	bpf_printk("%s from PID %d.\n", msg, pid);
	return 0;
}