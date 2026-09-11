package com.syscallfilter;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

/**
 * Native memory-based syscall filter packet
 *
 * Uses JNA Memory (malloc) instead of JVM heap to avoid GC and memory permission issues
 * that cause JVM crashes when passed to eBPF via prctl().
 *
 * Memory layout (228 bytes total):
 * - Offset 0:   cmd (4 bytes, uint32)
 * - Offset 4:   whitelist[32] (64 bytes, 32 * uint16)
 * - Offset 68:  path_hash[32] (128 bytes, 32 * uint32)
 * - Offset 196: path_len[32] (32 bytes, 32 * uint8)
 */
public class SyscallFilterPacketNative {

    /** Memory allocated via malloc (not JVM heap) */
    private final Memory memory;

    /** Command offset */
    private static final int OFFSET_CMD = 0;

    /** Whitelist array offset */
    private static final int OFFSET_WHITELIST = 4;

    /** Path hash array offset */
    private static final int OFFSET_PATH_HASH = 68;

    /** Path length array offset */
    private static final int OFFSET_PATH_LEN = 196;

    /** Total packet size */
    private static final int PACKET_SIZE = 228;

    /** Allocated size (aligned to 256 for safety) */
    private static final int ALLOC_SIZE = 256;

    /** Maximum rules per packet */
    public static final int MAX_RULES = 32;

    /** Maximum path length */
    public static final int MAX_PATH_LEN = 255;

    /** Command: Begin filtering */
    public static final int CMD_FILTER_BEGIN = 0;

    /** Command: End filtering */
    public static final int CMD_FILTER_END = 1;

    /** Empty slot marker */
    private static final short SYSCALL_SLOT_EMPTY = (short) 0xFFFF;

    /**
     * Allocate native memory for packet structure
     *
     * Memory is allocated via malloc (not JVM heap) to ensure:
     * - Stable addresses (no GC movement)
     * - Standard memory permissions
     * - eBPF compatibility
     */
    public SyscallFilterPacketNative() {
        // Allocate 256 bytes for alignment safety (actual size 228)
        this.memory = new Memory(ALLOC_SIZE);

        // Zero-initialize all bytes
        memory.clear();

        // Initialize whitelist slots to 0xFFFF (empty)
        for (int i = 0; i < MAX_RULES; i++) {
            setWhitelist(i, SYSCALL_SLOT_EMPTY);
        }
    }

    /**
     * Set command field (CMD_FILTER_BEGIN or CMD_FILTER_END)
     *
     * @param cmd Command value (0 or 1)
     */
    public void setCmd(int cmd) {
        memory.setInt(OFFSET_CMD, cmd);
    }

    /**
     * Set syscall number in whitelist array
     *
     * @param index Slot index (0-31)
     * @param value Syscall number (or 0xFFFF for empty)
     */
    public void setWhitelist(int index, short value) {
        if (index < 0 || index >= MAX_RULES) {
            throw new IndexOutOfBoundsException("Whitelist index must be 0-31, got: " + index);
        }
        memory.setShort(OFFSET_WHITELIST + index * 2, value);
    }

    /**
     * Set path hash in path_hash array
     *
     * @param index Slot index (0-31)
     * @param value FNV-1a hash of path (or 0 for no constraint)
     */
    public void setPathHash(int index, int value) {
        if (index < 0 || index >= MAX_RULES) {
            throw new IndexOutOfBoundsException("PathHash index must be 0-31, got: " + index);
        }
        memory.setInt(OFFSET_PATH_HASH + index * 4, value);
    }

    /**
     * Set path length in path_len array
     *
     * @param index Slot index (0-31)
     * @param value Path length (or 0 for no constraint)
     */
    public void setPathLen(int index, byte value) {
        if (index < 0 || index >= MAX_RULES) {
            throw new IndexOutOfBoundsException("PathLen index must be 0-31, got: " + index);
        }
        memory.setByte(OFFSET_PATH_LEN + index, value);
    }

    /**
     * Get pointer to native memory for prctl() call
     *
     * @return Native memory pointer (malloc'd, not JVM heap)
     */
    public Pointer getPointer() {
        return memory;
    }

    /**
     * Get allocated memory size
     *
     * @return Total allocated size in bytes
     */
    public int size() {
        return ALLOC_SIZE;
    }

    /**
     * Get actual packet size
     *
     * @return Packet structure size (228 bytes)
     */
    public int packetSize() {
        return PACKET_SIZE;
    }

    /**
     * Get memory dump for debugging
     *
     * @param length Number of bytes to dump
     * @return Byte array containing memory contents
     */
    public byte[] dump(int length) {
        return memory.getByteArray(0, Math.min(length, ALLOC_SIZE));
    }
}
