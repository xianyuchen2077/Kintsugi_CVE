package com.syscallfilter;

import java.nio.charset.StandardCharsets;

/**
 * FNV-1a 哈希算法实现
 * 与 eBPF 侧保持一致
 */
public final class FnvHash {

    /** FNV offset basis (32-bit) */
    private static final int FNV_OFFSET_BASIS = 0x811c9dc5;  // 2166136261

    /** FNV prime (32-bit) */
    private static final int FNV_PRIME = 0x01000193;  // 16777619

    private FnvHash() {
        // Utility class
    }

    /**
     * 计算字符串的 FNV-1a 哈希值
     * @param path 路径字符串
     * @param maxLen 最大处理长度
     * @return 32位哈希值
     */
    public static int hash(String path, int maxLen) {
        int hash = FNV_OFFSET_BASIS;
        byte[] bytes = path.getBytes(StandardCharsets.UTF_8);
        int len = Math.min(bytes.length, maxLen);

        for (int i = 0; i < len; i++) {
            hash ^= (bytes[i] & 0xFF);
            hash *= FNV_PRIME;
        }

        return hash;
    }

    /**
     * 计算字符串的 FNV-1a 哈希值（默认最大长度 64）
     * @param path 路径字符串
     * @return 32位哈希值
     */
    public static int hash(String path) {
        return hash(path, 64);
    }

    /**
     * 计算字符串的哈希值和实际长度
     * @param path 路径字符串
     * @param maxLen 最大处理长度
     * @return 包含哈希值和长度的结果
     */
    public static HashResult hashWithLength(String path, int maxLen) {
        byte[] bytes = path.getBytes(StandardCharsets.UTF_8);
        int len = Math.min(bytes.length, maxLen);

        int hash = FNV_OFFSET_BASIS;
        for (int i = 0; i < len; i++) {
            hash ^= (bytes[i] & 0xFF);
            hash *= FNV_PRIME;
        }

        return new HashResult(hash, len);
    }

    /**
     * 哈希结果类
     */
    public static class HashResult {
        private final int hash;
        private final int length;

        public HashResult(int hash, int length) {
            this.hash = hash;
            this.length = length;
        }

        public int getHash() {
            return hash;
        }

        public int getLength() {
            return length;
        }
    }
}
