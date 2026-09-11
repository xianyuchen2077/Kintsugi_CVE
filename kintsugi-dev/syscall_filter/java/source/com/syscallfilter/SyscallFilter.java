package com.syscallfilter;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 系统调用过滤器 - 与 eBPF 通信的 Java 接口
 *
 * <p>使用示例:</p>
 * <pre>
 * // 函数式 API
 * SyscallFilter.begin(Map.of(
 *     "read", List.of(),                    // 无路径约束
 *     "openat", List.of("/etc/", "/tmp/")   // 路径白名单
 * ));
 *
 * // ... 受保护代码 ...
 *
 * SyscallFilter.end(Map.of(
 *     "read", List.of(),
 *     "openat", List.of("/etc/", "/tmp/")
 * ));
 *
 * // try-with-resources
 * try (var filter = new SyscallFilter(Map.of(
 *     "execve", List.of("/usr/bin/php")
 * ))) {
 *     // 受保护代码
 * }
 * </pre>
 */
public class SyscallFilter implements AutoCloseable {

    /** prctl 自定义命令编号 (避免与 PR_SET_FP_MODE=45 冲突) */
    private static final int PR_SYSCALL_FILTER_CMD = 999;

    /** prctl 系统调用号 (用于自动添加到白名单) */
    private static final int SYSCALL_PRCTL = 157;

    /** libc 接口 */
    private interface LibC extends Library {
        LibC INSTANCE = Native.load("c", LibC.class);

        int prctl(int option, Pointer arg2, long arg3, long arg4, long arg5);
    }

    /** 当前实例的规则 (用于 close 时删除) */
    private final Map<String, List<String>> rules;

    /** 是否已激活 */
    private boolean active = false;

    /**
     * 构造函数 - 创建并激活过滤器
     * @param rules 过滤规则
     */
    public SyscallFilter(Map<String, List<String>> rules) {
        this.rules = rules;
        if (begin(rules)) {
            this.active = true;
        }
    }

    /**
     * 关闭过滤器 - 删除规则
     */
    @Override
    public void close() {
        if (active) {
            end(rules);
            active = false;
        }
    }

    /**
     * 启用系统调用过滤
     * @param rules 过滤规则: Map<系统调用名称, List<路径白名单>>
     * @return 是否成功
     */
    public static boolean begin(Map<String, List<String>> rules) {
        return sendPackets(SyscallFilterPacketNative.CMD_FILTER_BEGIN, rules);
    }

    /**
     * 禁用系统调用过滤
     * @param rules 过滤规则 (用于精确删除)
     * @return 是否成功
     */
    public static boolean end(Map<String, List<String>> rules) {
        return sendPackets(SyscallFilterPacketNative.CMD_FILTER_END, rules);
    }

    /**
     * 发送数据包到 eBPF
     */
    private static boolean sendPackets(int cmd, Map<String, List<String>> rules) {
        // 将规则转换为扁平列表 (syscall_nr, path_hash, path_len)
        List<RuleEntry> entries = new ArrayList<>();

        // 自动添加 prctl 到白名单 (否则无法调用 END)
        if (cmd == SyscallFilterPacketNative.CMD_FILTER_BEGIN) {
            entries.add(new RuleEntry(SYSCALL_PRCTL, 0, 0));
        }

        for (Map.Entry<String, List<String>> entry : rules.entrySet()) {
            String syscallName = entry.getKey();
            List<String> paths = entry.getValue();

            int syscallNr = SyscallTable.get(syscallName);
            if (syscallNr < 0) {
                System.err.println("Unknown syscall: " + syscallName);
                continue;
            }

            if (paths == null || paths.isEmpty()) {
                // 无路径约束
                entries.add(new RuleEntry(syscallNr, 0, 0));
            } else {
                // 有路径约束
                for (String path : paths) {
                    FnvHash.HashResult hr = FnvHash.hashWithLength(path, SyscallFilterPacketNative.MAX_PATH_LEN);
                    entries.add(new RuleEntry(syscallNr, hr.getHash(), hr.getLength()));
                }
            }
        }

        // 分批发送 (每批最多 MAX_RULES 条)
        int batchSize = SyscallFilterPacketNative.MAX_RULES;
        for (int i = 0; i < entries.size(); i += batchSize) {
            int end = Math.min(i + batchSize, entries.size());
            List<RuleEntry> batch = entries.subList(i, end);

            if (!sendSinglePacket(cmd, batch)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 发送单个数据包 (使用原生内存避免 JVM crash)
     */
    private static boolean sendSinglePacket(int cmd, List<RuleEntry> entries) {
        // 使用原生内存分配 (malloc) 而非 JVM heap
        // 避免 eBPF 与 JVM GC 内存的兼容性问题
        SyscallFilterPacketNative packet = new SyscallFilterPacketNative();
        packet.setCmd(cmd);

        // 填充规则槽位
        for (int i = 0; i < entries.size() && i < 32; i++) {
            RuleEntry entry = entries.get(i);
            packet.setWhitelist(i, (short) entry.syscallNr);
            packet.setPathHash(i, entry.pathHash);
            packet.setPathLen(i, (byte) entry.pathLen);
        }

        // 调用 prctl
        int result = LibC.INSTANCE.prctl(
            PR_SYSCALL_FILTER_CMD,
            packet.getPointer(),
            0L, 0L, 0L
        );

        return result == 0;
    }

    /**
     * 内部规则条目
     */
    private static class RuleEntry {
        final int syscallNr;
        final int pathHash;
        final int pathLen;

        RuleEntry(int syscallNr, int pathHash, int pathLen) {
            this.syscallNr = syscallNr;
            this.pathHash = pathHash;
            this.pathLen = pathLen;
        }
    }
}
