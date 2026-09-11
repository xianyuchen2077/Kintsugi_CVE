#!/usr/bin/env python3
"""
ebpf_code_gen_bcc.py - eBPF BCC Code Generator with Unified Handler

职责：
- 根据指定的系统调用列表生成完整的 eBPF C 代码
- 生成 BCC 格式（开发调试用）
- 实现统一处理框架：kprobe -> handle_syscall -> should_block_syscall
"""

import sys
import os
import yaml

from syscall_table import SYSCALL_TABLE


class EBPFCodeGenerator:
    """eBPF C 代码生成器（BCC 格式，统一处理框架）"""

    def __init__(self, syscalls):
        """
        Args:
            syscalls: 要监控的系统调用列表，如 ['read', 'write', 'open', 'mkdir']
        """
        if "prctl" in syscalls:
            raise ValueError("不允许直接监控 prctl 系统调用，因为它用于控制面命令传递")

        self.syscalls = syscalls
        self.syscall_map = {}

        # 验证并构建映射
        for name in syscalls:
            if name not in SYSCALL_TABLE:
                raise ValueError(f"未知的系统调用: {name}")
            self.syscall_map[name] = SYSCALL_TABLE[name]

    def generate(self):
        """生成完整的 eBPF C 代码（BCC 格式）"""
        code = ""
        code += self._generate_header()
        code += self._generate_maps()
        code += self._generate_control_plane()
        code += self._generate_filtering_logic()
        code += self._generate_fork_monitor()
        code += self._generate_kprobes()
        return code

    def _generate_header(self):
        """生成头部"""
        return f"""// Auto-generated eBPF code for syscall filtering (BCC format)
// Generated syscall hooks: {', '.join(self.syscalls)}
// Total: {len(self.syscalls)} syscalls
//
// Architecture:
//   Kprobes -> handle_syscall() -> should_block_syscall() -> check_*()

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

"""

    def _generate_maps(self):
        """生成 eBPF Maps（BCC 格式）"""
        return """// ========================================
// Constants
// ========================================

#define MAX_RULES 128            // 每次命令最多包含的规则数（扩容）
#define MAX_PATH_COUNT 32       // 单个系统调用最大路径白名单数（扩容）
#define MAX_PATH_LEN 256        // 路径最大长度（必须是8的倍数）
#define SYSCALL_SLOT_EMPTY 0xFFFF  // 空槽位标记

// ========================================
// Debug Control
// ========================================

// Global debug flag (set to 1 to enable debug logging, 0 to disable)
#define DEBUG_ENABLED 0

// NOTE: eBPF clang doesn't allow calling builtins (like bpf_trace_printk) inside macros
// So we must call bpf_trace_printk directly with if (DEBUG_ENABLED) check at each call site

// ========================================
// eBPF Maps
// ========================================

// Target Process/Thread List (Host PID/TID)
// Managed by userspace .so plugin via PID mapping
BPF_HASH(target_ids, u64, u8, 2048);
// key = host pid_tgid from bpf_get_current_pid_tgid()
// [63:32] = TGID (process ID - host view)
// [31:0]  = TID (thread ID - host view)
// value = 1 means monitored

// Per-Thread Syscall Rules
// Supports whitelist mode for fine-grained control
struct rule_key {
    u64 pid_tid;        // Thread identifier (8 bytes)
    u64 syscall_nr;     // Syscall number (8 bytes for alignment)
};

BPF_HASH(thr_wlist, struct rule_key, u8, 10240);
// key = (pid_tid, syscall_nr)
// value = 1 means this thread allows this syscall (whitelist mode)

// 批量传输数据结构（必须在 BPF_PERCPU_ARRAY 之前定义）
struct syscall_filter_packet {
    u32 cmd;                    // 命令类型
    u16 whitelist[MAX_RULES];   // 系统调用编号数组（0xFFFF表示空槽位）
    u32 path_hash[MAX_RULES];   // 路径哈希值数组（0表示无路径约束）
    u8 path_len[MAX_RULES];     // 路径长度数组（0表示无路径约束）
} __attribute__((aligned(8)));
// 总大小: 4 + 256 + 512 + 128 = 900字节

// Per-CPU Array for Packet Storage (避免栈溢出)
// 每个 CPU 核心独立副本，避免并发竞争
BPF_PERCPU_ARRAY(packet_storage, struct syscall_filter_packet, 1);
// 内存占用: sizeof(struct syscall_filter_packet) × CPU_cores
// 示例: 900 bytes × 8 CPUs = 7.2 KB

// Per-CPU 路径处理缓冲区（避免栈溢出）
// BPF 栈限制为 512 字节，path_buf + prefix_hash 会超出
struct path_work_buffer {
    char path_buf[MAX_PATH_LEN];           // 路径字符串缓冲区
    u32 prefix_hash[MAX_PATH_LEN + 1];     // 前缀哈希数组
} __attribute__((aligned(8)));

BPF_PERCPU_ARRAY(path_work_storage, struct path_work_buffer, 1);

// Path Hash Storage - Compact Design Using FNV-1a Hash
// Design: Store hash+length instead of full string to save memory (96% reduction)
struct path_hash_key {
    u64 pid_tid;        // Thread identifier (8 bytes)
    u64 syscall_nr;     // Syscall number (8 bytes)
    u32 path_idx;       // Path index 0-15 (4 bytes)
    u32 _padding;       // Alignment padding (4 bytes)
} __attribute__((aligned(8)));

struct path_hash_value {
    u32 hash;           // FNV-1a hash of path prefix (4 bytes)
    u8 len;             // Original path length (1 byte)
    u8 _padding[3];     // Alignment padding (3 bytes)
} __attribute__((aligned(8)));

BPF_HASH(path_hash_map, struct path_hash_key, struct path_hash_value, 262144);
// key = (pid_tid, syscall_nr, path_idx)
// value = (hash, len)
// Capacity: 262144 entries = supports 16 paths × 16384 rules
// Max memory: 262144 × (24 + 8) = 8.4 MB (vs 70 MB with string storage)

// Path Counter Map - Track how many paths each (pid_tid, syscall_nr) has
struct path_counter_key {
    u64 pid_tid;        // Thread identifier (8 bytes)
    u64 syscall_nr;     // Syscall number (8 bytes)
};

BPF_HASH(path_counters, struct path_counter_key, u32, 10240);
// key = (pid_tid, syscall_nr)
// value = current path count (0-15)
// Used during batch insert/delete to track path_idx without nested loops

// ========================================
// Cascading Process/Thread Monitoring Maps
// ========================================

// Forward Map: ancestor -> descendants
// Key: (ancestor_pid_tid, descendant_index)
// Value: descendant_pid_tid
struct descendant_key {
    u64 ancestor_pid_tid;  // The original monitored thread
    u32 desc_idx;          // Index 0-255 (max descendants per ancestor)
    u32 _padding;
} __attribute__((aligned(8)));

BPF_HASH(descendant_map, struct descendant_key, u64, 524288);
// Capacity: 2048 ancestors × 256 descendants = 524288 entries

// Descendant Counter: Track number of descendants per ancestor
BPF_HASH(descendant_count, u64, u32, 2048);
// key = ancestor_pid_tid, value = count (0-255)

// Reverse Map: descendant -> ancestor
// Key: descendant_pid_tid
// Value: ancestor_pid_tid (the original monitored thread)
BPF_HASH(reverse_map, u64, u64, 524288);
// Allows quick lookup: "which ancestor am I descended from?"

#define MAX_DESCENDANTS 128  // Max descendants per ancestor

// TODO: Add more maps for Requirement 2 (DFA)

"""

    def _generate_control_plane(self):
        """生成用于从用户空间接收命令的控制面逻辑(批量传输协议)"""
        return """// ========================================
// Control Plane via prctl() (Batch Transfer Protocol)
// ========================================

// Forward declarations for functions defined later
static inline void remove_all_descendants(u64 ancestor_pid_tid);

#define PR_SYSCALL_FILTER_CMD 999 // 自定义 prctl 命令 (避免与 PR_SET_FP_MODE=45 冲突)

enum command {
    CMD_FILTER_BEGIN,    // 开始过滤(激活监控) + 批量添加规则
    CMD_FILTER_END,      // 批量删除规则 + 停止监控
};

// 注意: struct syscall_filter_packet 已在 maps 部分定义

// FNV-1a 哈希算法 (与用户态保持一致)
static inline u32 hash_string(const char *str, u8 len)
{
    u32 hash = 2166136261u;  // FNV offset basis
    
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
        if (i < len)
        {
            hash ^= (u32)str[i];
            hash *= 16777619u;  // FNV prime
        }
    }

    return hash;
}

// 辅助函数: 批量插入规则到maps
static inline int batch_insert_rules(u64 pid_tid, struct syscall_filter_packet *pkt)
{
    u8 val = 1;
    u16 last_syscall_nr = SYSCALL_SLOT_EMPTY;  // 跟踪上一个syscall_nr
    u32 pid = pid_tid >> 32;
    u32 tid = (u32)pid_tid;

    if (DEBUG_ENABLED) bpf_trace_printk("[INSERT] batch_insert_rules: pid=%u tid=%u\\n", pid, tid);

    // 遍历规则数组 (展开循环以降低复杂度)
    for (int i = 0; i < MAX_RULES; i++) {
        u16 syscall_nr = pkt->whitelist[i];
        if (syscall_nr == SYSCALL_SLOT_EMPTY) break;  // 遇到空槽位停止

        // 1. 添加系统调用到白名单 (只在第一次遇到时添加)
        if (syscall_nr != last_syscall_nr) {
            struct rule_key wlist_key = {.pid_tid = pid_tid, .syscall_nr = syscall_nr};
            thr_wlist.update(&wlist_key, &val);
            if (DEBUG_ENABLED) bpf_trace_printk("[INSERT] Added syscall=%d to whitelist for pid=%u tid=%u\\n", syscall_nr, pid, tid);
            last_syscall_nr = syscall_nr;
        }

        // 2. 处理路径约束
        u32 path_hash = pkt->path_hash[i];
        u8 path_len = pkt->path_len[i];

        if (path_hash == 0) {
            // 无路径约束: 不添加path_hash_map条目 (通过不存在来表示)
            if (DEBUG_ENABLED) bpf_trace_printk("[INSERT] syscall=%d pid=%u tid=%u: No path constraint\\n", syscall_nr, pid, tid);
            continue;
        }

        // 有路径约束: 添加哈希条目
        // 查询计数器获取当前path_idx
        struct path_counter_key counter_key = {
            .pid_tid = pid_tid,
            .syscall_nr = syscall_nr
        };

        u32 *count_ptr = path_counters.lookup(&counter_key);
        u32 path_idx = count_ptr ? *count_ptr : 0;

        // 更新计数器
        u32 new_count = path_idx + 1;
        path_counters.update(&counter_key, &new_count);

        // 插入新哈希条目
        struct path_hash_key hash_key = {
            .pid_tid = pid_tid,
            .syscall_nr = syscall_nr,
            .path_idx = path_idx,
            ._padding = 0
        };

        struct path_hash_value hash_val = {
            .hash = path_hash,
            .len = path_len,
            ._padding = {0}
        };

        path_hash_map.update(&hash_key, &hash_val);
        if (DEBUG_ENABLED) {
            bpf_trace_printk("[INSERT] syscall=%d pid=%u tid=%u: Added path constraint\\n", syscall_nr, pid, tid);
        }
    }

    if (DEBUG_ENABLED) bpf_trace_printk("[INSERT] batch_insert_rules completed for pid=%u tid=%u\\n", pid, tid);
    return 0;
}

// 辅助函数: 批量删除规则
static inline int batch_delete_rules(u64 pid_tid, struct syscall_filter_packet *pkt)
{
    u16 last_syscall_nr = SYSCALL_SLOT_EMPTY;  // 跟踪上一个处理的syscall_nr
    u32 pid = pid_tid >> 32;
    u32 tid = (u32)pid_tid;

    if (DEBUG_ENABLED) bpf_trace_printk("[DELETE] batch_delete_rules: pid=%u tid=%u\\n", pid, tid);

    // 0. Remove all descendants FIRST (before deleting rules)
    // remove_all_descendants(pid_tid);
    // if (DEBUG_ENABLED) bpf_trace_printk("[DELETE] Removed all descendants for pid=%u tid=%u\\n", pid, tid);

    // 遍历规则数组
    for (int i = 0; i < MAX_RULES; i++) {
        u16 syscall_nr = pkt->whitelist[i];
        if (syscall_nr == SYSCALL_SLOT_EMPTY) break;  // 遇到空槽位停止

        // 如果这个syscall_nr已经删过了,跳过
        if (syscall_nr == last_syscall_nr) continue;
        last_syscall_nr = syscall_nr;

        if (DEBUG_ENABLED) bpf_trace_printk("[DELETE] Deleting syscall=%d for pid=%u tid=%u\\n", syscall_nr, pid, tid);

        // 1. 删除该syscall的所有path_hash条目 (遍历0到MAX_PATH_COUNT)
        for (int j = 0; j < MAX_PATH_COUNT; j++) {
            struct path_hash_key hash_key = {
                .pid_tid = pid_tid,
                .syscall_nr = syscall_nr,
                .path_idx = j,
                ._padding = 0
            };
            path_hash_map.delete(&hash_key);
        }

        // 2. 删除计数器
        struct path_counter_key counter_key = {
            .pid_tid = pid_tid,
            .syscall_nr = syscall_nr
        };
        path_counters.delete(&counter_key);

        // 3. 删除syscall白名单
        struct rule_key wlist_key = {.pid_tid = pid_tid, .syscall_nr = syscall_nr};
        thr_wlist.delete(&wlist_key);

        if (DEBUG_ENABLED) bpf_trace_printk("[DELETE] Deleted syscall=%d from whitelist for pid=%u tid=%u\\n", syscall_nr, pid, tid);
    }

    if (DEBUG_ENABLED) bpf_trace_printk("[DELETE] batch_delete_rules completed for pid=%u tid=%u\\n", pid, tid);
    return 0;
}

// prctl 的 kprobe 处理函数
int kprobe____x64_sys_prctl(struct pt_regs *ctx)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    int option;
    bpf_probe_read_kernel(&option, sizeof(option), &syscall_regs->di);

    // 检查是否是我们自定义的命令
    if (option != PR_SYSCALL_FILTER_CMD) {
        return 0;
    }

    // 获取用户空间packet指针
    void *pkt_ptr;
    bpf_probe_read_kernel(&pkt_ptr, sizeof(pkt_ptr), &syscall_regs->si);

    // 从 Per-CPU Map 获取指针（只占用 8 bytes 栈空间）
    u32 key = 0;
    struct syscall_filter_packet *pkt = packet_storage.lookup(&key);
    if (!pkt) {
        return 0;  // Map lookup 失败（不应该发生）
    }

    // 读取用户空间数据到 map 中的 packet
    if (bpf_probe_read_user(pkt, sizeof(*pkt), pkt_ptr) != 0) {
        return 0;  // 读取失败
    }

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_tid >> 32;
    u32 tid = (u32)pid_tid;
    u8 val = 1;

    // 分支处理
    if (pkt->cmd == CMD_FILTER_BEGIN) {
        bpf_trace_printk("[PRCTL] CMD_FILTER_BEGIN received: pid=%u tid=%u\\n", pid, tid);

        // 1. 自动添加 prctl(157) 到白名单
        struct rule_key prctl_key = {.pid_tid = pid_tid, .syscall_nr = 157};
        thr_wlist.update(&prctl_key, &val);
        if (DEBUG_ENABLED) bpf_trace_printk("[PRCTL] Added prctl(157) to whitelist for pid=%u tid=%u\\n", pid, tid);

        // 2. 批量插入规则（传递指针，不是 &pkt）
        batch_insert_rules(pid_tid, pkt);

        // 3. 激活监控 (最后开启,避免规则未完全添加时就开始过滤)
        target_ids.update(&pid_tid, &val);
        if (DEBUG_ENABLED) bpf_trace_printk("[PRCTL] Monitoring ACTIVATED for pid=%u tid=%u\\n", pid, tid);

    } else if (pkt->cmd == CMD_FILTER_END) {
        bpf_trace_printk("[PRCTL] CMD_FILTER_END received: pid=%u tid=%u\\n", pid, tid);

        // 1. 停止监控 (先关闭,避免删除规则时被过滤导致死锁)
        target_ids.delete(&pid_tid);
        if (DEBUG_ENABLED) bpf_trace_printk("[PRCTL] Monitoring DEACTIVATED for pid=%u tid=%u\\n", pid, tid);

        // 2. 批量删除规则（传递指针）
        batch_delete_rules(pid_tid, pkt);

        // 3. 删除 prctl 白名单
        struct rule_key prctl_key = {.pid_tid = pid_tid, .syscall_nr = 157};
        thr_wlist.delete(&prctl_key);
        if (DEBUG_ENABLED) bpf_trace_printk("[PRCTL] Deleted prctl(157) from whitelist for pid=%u tid=%u\\n", pid, tid);
    }

    // 覆盖返回值,告诉用户空间成功
    bpf_override_return(ctx, 0);
    return 0;
}

"""

    def _generate_filtering_logic(self):
        """生成过滤逻辑函数（统一处理框架）"""
        return """// ========================================
// Filtering Logic Functions
// ========================================

// ========================================
// Descendant Tracking Helper Functions
// ========================================

// Get the ancestor pid_tid for current thread
// Returns: ancestor_pid_tid if descendant, or own pid_tid if root monitored, or 0 if not monitored
static inline u64 get_ancestor_pid_tid(u64 pid_tid)
{
    // Check if this thread is a descendant
    u64 *ancestor_ptr = reverse_map.lookup(&pid_tid);
    if (ancestor_ptr) {
        return *ancestor_ptr;  // Return the ancestor
    }

    // Not a descendant, check if it's a root monitored thread
    u8 *monitored = target_ids.lookup(&pid_tid);
    if (monitored && *monitored == 1) {
        return pid_tid;  // It's a root, return itself
    }

    return 0;  // Not monitored at all
}

// Check if current thread is monitored (directly or as descendant)
// Returns: 1 if monitored, 0 otherwise
static inline int is_monitored_or_descendant(u64 pid_tid)
{
    // Check direct monitoring
    u8 *monitored = target_ids.lookup(&pid_tid);
    if (monitored && *monitored == 1) {
        return 1;
    }

    // Check if it's a descendant
    u64 *ancestor_ptr = reverse_map.lookup(&pid_tid);
    if (ancestor_ptr) {
        return 1;  // Is a descendant
    }

    return 0;
}

// Add a descendant to the forward and reverse maps
// Returns: 0 on success, -1 on failure
static inline int add_descendant(u64 ancestor_pid_tid, u64 child_pid_tid)
{
    u32 pid = child_pid_tid >> 32;
    u32 tid = (u32)child_pid_tid;

    if (DEBUG_ENABLED) {
        bpf_trace_printk("[DESCENDANT] Adding child pid=%u tid=%u to ancestor=%llu\\n",
                         pid, tid, ancestor_pid_tid);
    }

    // Get current descendant count
    u32 *count_ptr = descendant_count.lookup(&ancestor_pid_tid);
    u32 desc_idx = count_ptr ? *count_ptr : 0;

    // Check limit
    if (desc_idx >= MAX_DESCENDANTS) {
        if (DEBUG_ENABLED) {
            bpf_trace_printk("[DESCENDANT] ERROR: Max descendants reached for ancestor=%llu\\n",
                             ancestor_pid_tid);
        }
        return -1;
    }

    // Add to forward map
    struct descendant_key fwd_key = {
        .ancestor_pid_tid = ancestor_pid_tid,
        .desc_idx = desc_idx,
        ._padding = 0
    };
    descendant_map.update(&fwd_key, &child_pid_tid);

    // Update counter
    u32 new_count = desc_idx + 1;
    descendant_count.update(&ancestor_pid_tid, &new_count);

    // Add to reverse map (sufficient for monitoring check via is_monitored_or_descendant)
    // NOTE: We do NOT add to target_ids - it only stores root monitored threads
    reverse_map.update(&child_pid_tid, &ancestor_pid_tid);

    if (DEBUG_ENABLED) {
        bpf_trace_printk("[DESCENDANT] Successfully added descendant #%d\\n", desc_idx);
    }

    return 0;
}

// Remove all descendants for a given ancestor
// Called during CMD_FILTER_END
static inline void remove_all_descendants(u64 ancestor_pid_tid)
{
    if (DEBUG_ENABLED) {
        bpf_trace_printk("[DESCENDANT] Removing all descendants for ancestor=%llu\\n", ancestor_pid_tid);
    }

    // Get descendant count
    u32 *count_ptr = descendant_count.lookup(&ancestor_pid_tid);
    if (!count_ptr) {
        return;  // No descendants
    }

    u32 count = *count_ptr;

    // Iterate through all descendants
    for (u32 i = 0; i < MAX_DESCENDANTS; i++) {
        if (i < count)
        {
            struct descendant_key fwd_key = {
            .ancestor_pid_tid = ancestor_pid_tid,
            .desc_idx = i,
            ._padding = 0
            };

            u64 *child_ptr = descendant_map.lookup(&fwd_key);
            if (!child_ptr) continue;

            u64 child_pid_tid = *child_ptr;

            // Remove from reverse map (no need to touch target_ids - descendants were never added there)
            reverse_map.delete(&child_pid_tid);

            // Remove from forward map
            descendant_map.delete(&fwd_key);

            if (DEBUG_ENABLED) {
                u32 pid = child_pid_tid >> 32;
                u32 tid = (u32)child_pid_tid;
                bpf_trace_printk("[DESCENDANT] Removed descendant pid=%u tid=%u\\n", pid, tid);
            }
        }
    }

    // Remove counter
    descendant_count.delete(&ancestor_pid_tid);
}

// ========================================
// Monitoring and Filtering Functions
// ========================================

// Check if current process/thread should be monitored
// NOW SUPPORTS CASCADING: checks both direct monitoring and descendant status
static inline int should_monitor(void)
{
    u64 host_pid_tgid = bpf_get_current_pid_tgid();

    // Check direct monitoring or descendant status
    return is_monitored_or_descendant(host_pid_tgid);
}

// Check syscall whitelist for current thread
// NOW SUPPORTS CASCADING: uses ancestor's rules for descendants
// Returns: 1 = block, 0 = allow
static inline int check_syscall_whitelist(u32 syscall_nr)
{
    u64 pid_tid = bpf_get_current_pid_tgid();

    // Get the ancestor pid_tid (or own if root)
    u64 ancestor_pid_tid = get_ancestor_pid_tid(pid_tid);
    if (ancestor_pid_tid == 0) {
        return 1;  // Not monitored, should not happen if should_monitor() passed
    }

    // Construct lookup key using ancestor's pid_tid
    struct rule_key key = {
        .pid_tid = ancestor_pid_tid,
        .syscall_nr = syscall_nr
    };

    // Check if syscall is in whitelist
    u8 *allowed = thr_wlist.lookup(&key);

    if (allowed && *allowed == 1) {
        return 0;  // In whitelist, allow
    }

    return 1;  // Not in whitelist, block
}

// Check path whitelist for current syscall (Hash-based design with prefix optimization)
// NOW SUPPORTS CASCADING: uses ancestor's path rules
// Returns: 1 = block, 0 = allow
static inline int check_path_whitelist(u32 syscall_nr, const char *path_arg)
{
    u64 pid_tid = bpf_get_current_pid_tgid();

    // Get the ancestor pid_tid (or own if root)
    u64 ancestor_pid_tid = get_ancestor_pid_tid(pid_tid);
    if (ancestor_pid_tid == 0) {
        return 1;  // Not monitored
    }

    // 查询计数器,判断是否有路径规则 (使用ancestor的规则)
    struct path_counter_key counter_key = {
        .pid_tid = ancestor_pid_tid,
        .syscall_nr = syscall_nr
    };

    u32 *count_ptr = path_counters.lookup(&counter_key);

    // 如果没有计数器或计数为0,表示无路径约束,允许所有路径
    if (!count_ptr || *count_ptr == 0) {
        return 0;
    }

    u32 path_count = *count_ptr;

    // 从 per-cpu map 获取工作缓冲区（避免栈溢出）
    u32 zero = 0;
    struct path_work_buffer *work = path_work_storage.lookup(&zero);
    if (!work) {
        return 0;  // 获取缓冲区失败，放行
    }

    // 读取用户空间路径字符串
    int read_ret = bpf_probe_read_user_str(work->path_buf, sizeof(work->path_buf), path_arg);

    // 如果读取失败（如 -EFAULT），说明指针无效，直接放行
    if (read_ret < 0) {
        bpf_trace_printk("[PATH] Read failed ret=%d\\n", read_ret);
        return 0;  // 允许
    }

    // DEBUG: 打印要检查的路径
    bpf_trace_printk("[PATH_DEBUG] syscall=%d cnt=%d\\n", syscall_nr, path_count);
    bpf_trace_printk("[PATH_DEBUG] path=%s\\n", work->path_buf);

    // ========== Loop 1: 预计算所有前缀哈希 ==========
    work->prefix_hash[0] = 2166136261u;  // FNV offset basis

    for (int i = 0; i < MAX_PATH_LEN; i++) {
        work->prefix_hash[i + 1] = (work->prefix_hash[i] ^ (u32)work->path_buf[i]) * 16777619u;
    }

    // ========== Loop 2: 匹配存储的哈希条目 ==========
    for (int i = 0; i < MAX_PATH_COUNT; i++) {
        if (i < path_count)
        {
            struct path_hash_key hash_key = {
            .pid_tid = ancestor_pid_tid,
            .syscall_nr = syscall_nr,
            .path_idx = i,
            ._padding = 0
            };

            struct path_hash_value *entry = path_hash_map.lookup(&hash_key);

            if (!entry) {
                bpf_trace_printk("[PATH_DEBUG] idx=%d not found\\n", i);
                continue;
            }

            if (entry->len > MAX_PATH_LEN) {
                bpf_trace_printk("[PATH_DEBUG] idx=%d len too big=%d\\n", i, entry->len);
                continue;
            }

            u32 actual_hash = work->prefix_hash[entry->len];

            // DEBUG: 分两行打印哈希比较
            bpf_trace_printk("[PATH_DEBUG] idx=%d len=%d\\n", i, entry->len);
            bpf_trace_printk("[PATH_DEBUG] expect=%u actual=%u\\n", entry->hash, actual_hash);

            if (actual_hash == entry->hash) {
                bpf_trace_printk("[PATH_DEBUG] MATCH idx=%d\\n", i);
                return 0;
            }
        }
    }

    bpf_trace_printk("[PATH_DEBUG] NO MATCH, block\\n");
    return 1;
}

// Extract path parameter from syscall registers
// Returns path pointer from appropriate register based on syscall
// TODO: Currently only supports first path parameter
// TODO: Future enhancement - support multi-path syscalls
static inline const char *get_path_arg(struct pt_regs *ctx, u32 syscall_nr)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char *path_ptr = NULL;

    // Core 11 syscalls with path parameters (hardcoded positions)
    // Based on x86-64 ABI: arg0=RDI, arg1=RSI, arg2=RDX

    switch (syscall_nr) {
        // Group 1: First parameter is path (arg0 = RDI)
        case 2:    // open(const char *filename, ...)
        case 59:   // execve(const char *filename, ...)
        case 87:   // unlink(const char *pathname)
        case 83:   // mkdir(const char *pathname, ...)
        case 82:   // rename(const char *oldname, ...)
            bpf_probe_read_kernel(&path_ptr, sizeof(path_ptr), &regs->di);
            break;

        // Group 2: Second parameter is path (arg1 = RSI) - "at" syscalls
        case 257:  // openat(int dfd, const char *filename, ...)
        case 258:  // mkdirat(int dfd, const char *pathname, ...)
        case 263:  // unlinkat(int dfd, const char *pathname, ...)
        case 264:  // renameat(int olddfd, const char *oldname, ...)
        case 316:  // renameat2(int olddfd, const char *oldname, ...)
        case 322:  // execveat(int dfd, const char *filename, ...)
            bpf_probe_read_kernel(&path_ptr, sizeof(path_ptr), &regs->si);
            break;

        default:
            // Not a path-based syscall, or not in our 11-syscall list
            return NULL;
    }

    // Debug: Print path for open syscall
    if (syscall_nr == 2) {
        if (path_ptr != NULL) {
            char path_debug[64];
            int ret = bpf_probe_read_user_str(path_debug, sizeof(path_debug), path_ptr);
            bpf_trace_printk("[PATH_DEBUG] open() ret=%d path=%s\\n", ret, path_debug);
        } else {
            bpf_trace_printk("[PATH_DEBUG] open() ptr=NULL\\n");
        }
    }

    // Debug: Print path for openat syscall
    if (syscall_nr == 257) {
        if (path_ptr != NULL) {
            char path_debug[64];
            int ret = bpf_probe_read_user_str(path_debug, sizeof(path_debug), path_ptr);
            bpf_trace_printk("[PATH_DEBUG] openat() ret=%d path=%s\\n", ret, path_debug);
        } else {
            bpf_trace_printk("[PATH_DEBUG] openat() ptr=NULL\\n");
        }
    }

    return path_ptr;
}

// Unified filtering entry point with path support
// Implements per-thread whitelist + path filtering
// Returns: 1 = block, 0 = allow
static inline int should_block_syscall_with_path(struct pt_regs *ctx, u32 syscall_nr)
{
    // Log function entry with full context
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_tid >> 32;
    u32 tid = (u32)pid_tid;
    // if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] check_block: syscall=%d pid=%u tid=%u\\n", syscall_nr, pid, tid);

    // Check if thread should be monitored
    if (!should_monitor()) {
        // if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: Not monitored, allowing\\n", syscall_nr, pid, tid);
        return 0;  // Not monitored, allow all
    }
    if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: Process IS monitored\\n", syscall_nr, pid, tid);

    // Check syscall whitelist - must pass this first
    int wl_result = check_syscall_whitelist(syscall_nr);
    if (wl_result) {
        if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: NOT in whitelist, blocking\\n", syscall_nr, pid, tid);
        return 1;  // Not in whitelist, block
    }
    if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: IS in whitelist\\n", syscall_nr, pid, tid);

    // Syscall is in whitelist - now check path constraints
    const char *path_arg = get_path_arg(ctx, syscall_nr);

    if (path_arg != NULL) {
        if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: Checking path constraints\\n", syscall_nr, pid, tid);
        // This is a path-based syscall, check path whitelist
        if (check_path_whitelist(syscall_nr, path_arg)) {
            if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: Path check FAILED, blocking\\n", syscall_nr, pid, tid);
            return 1;  // Path not in whitelist, block
        }
        if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: Path check PASSED\\n", syscall_nr, pid, tid);
    }

    if (DEBUG_ENABLED) bpf_trace_printk("[DEBUG] syscall=%d pid=%u tid=%u: All checks passed, allowing\\n", syscall_nr, pid, tid);
    return 0;  // All checks passed, allow
}

// Unified syscall handler
// Called by all kprobe hooks
static inline int handle_syscall(struct pt_regs *ctx, u32 syscall_nr)
{
    // Check all filtering rules (syscall + path)
    if (should_block_syscall_with_path(ctx, syscall_nr)) {
        // Get process info for logging
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        // Log the blocked syscall
        // View with: sudo cat /sys/kernel/debug/tracing/trace_pipe
        // if (DEBUG_ENABLED) 
        bpf_trace_printk("[BLOCKED] syscall=%d pid=%d comm=%s\\n", syscall_nr, pid, comm);

        // Debug: Print sendto destination info (syscall 44)
        if (syscall_nr == 44) {
            struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
            // sendto args: sockfd(di), buf(si), len(dx), flags(r10), dest_addr(r8), addrlen(r9)
            int sockfd;
            bpf_probe_read_kernel(&sockfd, sizeof(sockfd), &regs->di);

            void *dest_addr;
            bpf_probe_read_kernel(&dest_addr, sizeof(dest_addr), &regs->r8);

            if (dest_addr != NULL) {
                // Read sockaddr structure (first 16 bytes)
                // struct sockaddr_in: sa_family(2) + port(2) + ip(4) + zero(8)
                unsigned char addr_buf[16];
                if (bpf_probe_read_user(addr_buf, sizeof(addr_buf), dest_addr) == 0) {
                    u16 family = *(u16*)&addr_buf[0];
                    u16 port = __builtin_bswap16(*(u16*)&addr_buf[2]);  // Network byte order
                    u32 ip = *(u32*)&addr_buf[4];
                    // bpf_trace_printk only supports up to 3 format args, split into multiple calls
                    bpf_trace_printk("[SENDTO] sockfd=%d port=%d\\n", sockfd, port);
                    bpf_trace_printk("[SENDTO] ip_raw=0x%x (decimal below)\\n", ip);
                    bpf_trace_printk("[SENDTO] ip=%d.%d.x.x\\n", ip & 0xFF, (ip >> 8) & 0xFF);
                    bpf_trace_printk("[SENDTO] ip=x.x.%d.%d\\n", (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
                } else {
                    bpf_trace_printk("[SENDTO] sockfd=%d dest_addr read failed\\n", sockfd);
                }
            } else {
                bpf_trace_printk("[SENDTO] sockfd=%d dest_addr=NULL\\n", sockfd);
            }
        }

        // Block the syscall by overriding return value to -EPERM
        bpf_override_return(ctx, -1);
    }

    return 0;
}

"""

    def _generate_fork_monitor(self):
        """生成统一的fork监控代码(hook wake_up_new_task)"""
        return """// ========================================
// Fork/Clone Monitor (Unified via wake_up_new_task)
// ========================================
// All fork/vfork/clone/clone3 syscalls go through wake_up_new_task()
// This hook is triggered BEFORE the child process is scheduled, ensuring no race condition

int kprobe__wake_up_new_task(struct pt_regs *ctx)
{
    // Parameter 1: child task_struct pointer
    struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (!child) {
        return 0;
    }

    // Read child process information from task_struct
    u32 child_pid, child_tid;
    bpf_probe_read_kernel(&child_pid, sizeof(u32), &child->tgid);
    bpf_probe_read_kernel(&child_tid, sizeof(u32), &child->pid);
    u64 child_pid_tid = ((u64)child_pid << 32) | (u64)child_tid;

    // Read parent process information
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(void*), &child->real_parent);
    if (!parent) {
        return 0;
    }

    u32 parent_pid, parent_tid;
    bpf_probe_read_kernel(&parent_pid, sizeof(u32), &parent->tgid);
    bpf_probe_read_kernel(&parent_tid, sizeof(u32), &parent->pid);
    u64 parent_pid_tid = ((u64)parent_pid << 32) | (u64)parent_tid;

    // Check if parent is monitored or is a descendant
    if (!is_monitored_or_descendant(parent_pid_tid)) {
        return 0;  // Parent not monitored, ignore child
    }

    // Get the ancestor (root monitored thread)
    u64 ancestor_pid_tid = get_ancestor_pid_tid(parent_pid_tid);
    if (ancestor_pid_tid == 0) {
        return 0;  // Should not happen if is_monitored_or_descendant returned true
    }

    // Add child to descendant tracking
    int result = add_descendant(ancestor_pid_tid, child_pid_tid);

    if (DEBUG_ENABLED) {
        if (result == 0) {
            bpf_trace_printk("[FORK] child=%u:%u ancestor=%llu SUCCESS\\n",
                             child_pid, child_tid, ancestor_pid_tid);
        } else {
            bpf_trace_printk("[FORK] child=%u:%u FAILED (limit reached)\\n",
                             child_pid, child_tid);
        }
    }

    return 0;
}

"""

    def _generate_kprobes(self):
        """为每个系统调用生成 kprobe 钩子函数"""
        code = "// ========================================\n"
        code += "// Syscall Hook Implementations (Kprobes)\n"
        code += "// ========================================\n"
        code += (
            "// Each syscall has its own kprobe function that calls handle_syscall()\n"
        )
        code += "// This allows easy extension - just copy the template and change syscall number\n\n"

        for name, nr in sorted(self.syscall_map.items(), key=lambda x: x[1]):
            code += f"""// Kprobe: {name}() - syscall nr {nr}
int kprobe____x64_sys_{name}(struct pt_regs *ctx)
{{
    return handle_syscall(ctx, {nr});
}}

"""

        return code

    def save(self, filename):
        """保存到文件"""
        import sys
        code = self.generate()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"✅ 已生成代码: {filename} (BCC 格式)", file=sys.stderr)
        print(f"   监控系统调用: {len(self.syscalls)} 个", file=sys.stderr)
        print(f"   架构: Kprobes -> handle_syscall() -> should_block_syscall()", file=sys.stderr)
        return filename
