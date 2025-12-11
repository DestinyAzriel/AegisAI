/*
 * AegisAI eBPF Kernel Monitor for Linux
 * Monitors file system operations and process events at the kernel level
 */

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uio.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Ring buffer for communicating with user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// File operation types
enum file_op_type {
    FILE_OP_CREATE = 1,
    FILE_OP_WRITE,
    FILE_OP_DELETE,
    FILE_OP_RENAME,
    FILE_OP_EXEC
};

// Event structure
struct file_event {
    u32 pid;
    u32 uid;
    u64 timestamp;
    enum file_op_type op_type;
    char filename[256];
    char comm[16]; // Process name
};

// Process event structure
struct process_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp;
    u32 event_type; // 1 = fork, 2 = exec, 3 = exit
    char comm[16]; // Process name
};

// Map for tracking file operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct file_event);
} file_ops SEC(".maps");

// Tracepoint for file creation/open
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.op_type = FILE_OP_CREATE;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event to ring buffer
    struct file_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        *e = event;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// Tracepoint for file writes
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.op_type = FILE_OP_WRITE;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event to ring buffer
    struct file_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        *e = event;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// Tracepoint for file unlink (delete)
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.op_type = FILE_OP_DELETE;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event to ring buffer
    struct file_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        *e = event;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// Tracepoint for process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    event.pid = pid;
    event.ppid = (u32)bpf_get_current_pid_tgid();
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 2; // exec
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event to ring buffer
    struct process_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        *e = event;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// Tracepoint for process creation (fork/clone)
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    event.pid = pid;
    event.ppid = (u32)bpf_get_current_pid_tgid();
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 1; // fork
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Submit event to ring buffer
    struct process_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        *e = event;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// License declaration
char _license[] SEC("license") = "GPL";