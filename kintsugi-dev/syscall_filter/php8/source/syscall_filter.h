/*
 * syscall_filter.h - Header file for syscall_filter PHP extension
 * 支持路径参数白名单的系统调用过滤 (批量传输协议)
 */

#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#define PR_SYSCALL_FILTER_CMD 999  // 避免与 PR_SET_FP_MODE=45 冲突
#define MAX_RULES 128               // 最大规则数量（扩容到 128）
#define MAX_PATH_LEN 256            // 路径最大长度(必须是8的倍数)
#define SYSCALL_SLOT_EMPTY 0xFFFF   // 空槽位标记（syscall nr 最大值为~450）

enum command {
    CMD_FILTER_BEGIN,    // 开始过滤(激活监控) + 批量添加规则
    CMD_FILTER_END,      // 批量删除规则 + 停止监控
};

// 批量传输数据结构(单次prctl发送所有规则)
struct syscall_filter_packet {
    uint32_t cmd;                    // 命令类型
    uint16_t whitelist[MAX_RULES];   // 系统调用编号数组(0xFFFF表示空槽位)
    uint32_t path_hash[MAX_RULES];   // 路径哈希值数组(0表示无路径约束)
    uint8_t path_len[MAX_RULES];     // 路径长度数组(0表示无路径约束)
} __attribute__((aligned(8)));
// 总大小: 4 + 256 + 512 + 128 = 900字节

#endif /* SYSCALL_FILTER_H */
