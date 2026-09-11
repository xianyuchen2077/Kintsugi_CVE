#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Syscall Filter - eBPF-based syscall filtering via prctl(999)

Protocol 4.0.0 - Path parameter whitelist support

This module provides Python bindings for the eBPF syscall filtering system,
allowing Python applications to control which syscalls are permitted at runtime
with optional path prefix constraints.

Usage:
    from syscall_filter import syscall_filter_begin, syscall_filter_end

    # Enable filtering with whitelist (dict syntax)
    syscall_filter_begin({
        'read': [],                    # No path constraint
        'openat': ['/etc/', '/tmp/'],  # Path prefix whitelist
    })
    # ... code that should only use whitelisted syscalls ...
    syscall_filter_end({
        'read': [],
        'openat': ['/etc/', '/tmp/'],
    })

Requirements:
    - eBPF loader must be running on the host: sudo python3 ebpf_load.py
    - syscall_table.py must be available
"""

import ctypes
import sys
import os

# ============================================================================
# Load libc for prctl() syscall
# ============================================================================

try:
    libc = ctypes.CDLL(None)
except Exception as e:
    print("[syscall_filter] Error: Could not load libc: {}".format(e), file=sys.stderr)
    libc = None

# ============================================================================
# Constants (must match syscall_filter.h - Protocol 4.0.0)
# ============================================================================

PR_SYSCALL_FILTER_CMD = 999  # 避免与 PR_SET_FP_MODE=45 冲突
MAX_RULES = 128  # 必须与 syscall_filter.h 和 ebpf_code_gen.py 保持一致
MAX_PATH_LEN = 256
SYSCALL_SLOT_EMPTY = 0xFFFF

# Commands
CMD_FILTER_BEGIN = 0
CMD_FILTER_END = 1

# ============================================================================
# C structure definition (must match syscall_filter.h - Protocol 4.0.0)
# ============================================================================

class SyscallFilterPacket(ctypes.Structure):
    """
    Syscall filter packet structure for prctl(45) communication.

    Protocol 4.0.0 batch transfer format with path parameter support.

    Must exactly match the C structure:
        struct syscall_filter_packet {
            uint32_t cmd;
            uint16_t whitelist[MAX_RULES];
            uint32_t path_hash[MAX_RULES];
            uint8_t path_len[MAX_RULES];
        } __attribute__((aligned(8)));
    """
    _pack_ = 8
    _fields_ = [
        ("cmd", ctypes.c_uint32),                          # CMD_FILTER_BEGIN or CMD_FILTER_END
        ("whitelist", ctypes.c_uint16 * MAX_RULES),        # Syscall numbers (0xFFFF = empty)
        ("path_hash", ctypes.c_uint32 * MAX_RULES),        # FNV-1a hash of path prefix
        ("path_len", ctypes.c_uint8 * MAX_RULES),          # Length of path prefix (0 = no constraint)
    ]

# ============================================================================
# Import syscall table
# ============================================================================

# Add parent directory to path to import syscall_table
_parent_dir = os.path.join(os.path.dirname(__file__), '../..')
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

try:
    from syscall_table import SYSCALL_TABLE
except ImportError:
    print("[syscall_filter] Error: Could not import syscall_table", file=sys.stderr)
    print("[syscall_filter] Please ensure syscall_table.py is in syscall_filter/", file=sys.stderr)
    SYSCALL_TABLE = {}

# ============================================================================
# Hash function (FNV-1a algorithm, matches PHP/C implementation)
# ============================================================================

def hash_string(path):
    """
    Compute FNV-1a hash of path string for kernel matching.

    Args:
        path: Path string to hash

    Returns:
        tuple: (hash_value, path_len) where hash_value is uint32 and path_len is uint8
    """
    path_bytes = path.encode('utf-8')
    path_len = min(len(path_bytes), MAX_PATH_LEN)

    hash_value = 2166136261  # FNV offset basis
    for i in range(path_len):
        hash_value ^= path_bytes[i]
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF  # FNV prime, keep 32-bit

    return hash_value, path_len

# ============================================================================
# Core API functions
# ============================================================================

def syscall_filter_begin(syscall_rules):
    """
    Enable syscall filtering with whitelist mode and optional path constraints.

    Only the specified syscalls will be allowed. Syscalls with path parameters
    can be further restricted by path prefix whitelist. All other syscalls will
    be blocked with -EPERM. This is a per-thread filter managed by eBPF.

    Args:
        syscall_rules: Dict mapping syscall names to path lists.
                      Empty list [] means no path constraint.
                      Non-empty list ['/etc/', '/tmp/'] restricts to those prefixes.
                      Example: {'read': [], 'openat': ['/etc/', '/tmp/']}

    Returns:
        bool: True if successful, False otherwise

    Raises:
        ValueError: If a syscall name is not recognized
        RuntimeError: If libc is not available
        TypeError: If syscall_rules is not a dict

    Example:
        >>> syscall_filter_begin({'read': [], 'openat': ['/etc/']})
        True
    """
    if libc is None:
        raise RuntimeError("libc not available")

    if not isinstance(syscall_rules, dict):
        raise TypeError("syscall_rules must be a dict (e.g., {'read': [], 'openat': ['/etc/']})")

    # Initialize packet: whitelist filled with 0xFFFF, others with 0
    pkt = SyscallFilterPacket()
    pkt.cmd = CMD_FILTER_BEGIN
    for i in range(MAX_RULES):
        pkt.whitelist[i] = SYSCALL_SLOT_EMPTY
        pkt.path_hash[i] = 0
        pkt.path_len[i] = 0

    rule_idx = 0

    # Process each syscall and its path constraints
    for syscall_name, path_list in syscall_rules.items():
        if syscall_name not in SYSCALL_TABLE:
            raise ValueError("Unknown syscall: {}".format(syscall_name))

        syscall_nr = SYSCALL_TABLE[syscall_name]

        if not isinstance(path_list, (list, tuple)):
            raise TypeError("Value for '{}' must be a list or tuple".format(syscall_name))

        if len(path_list) == 0:
            # Case A: No path constraint (empty list [])
            if rule_idx >= MAX_RULES:
                raise RuntimeError("Exceeded max rules limit ({})".format(MAX_RULES))

            pkt.whitelist[rule_idx] = syscall_nr
            pkt.path_hash[rule_idx] = 0
            pkt.path_len[rule_idx] = 0
            rule_idx += 1

        else:
            # Case B: Has path constraints - each path takes one slot
            for path in path_list:
                if rule_idx >= MAX_RULES:
                    raise RuntimeError("Exceeded max rules limit ({})".format(MAX_RULES))

                if not isinstance(path, str):
                    raise TypeError("Path must be string for {}".format(syscall_name))

                if len(path) >= MAX_PATH_LEN:
                    print("[syscall_filter] Warning: Path too long (max {}): {}".format(MAX_PATH_LEN-1, path), file=sys.stderr)
                    continue

                # Compute hash and fill packet
                path_hash, path_len = hash_string(path)
                pkt.whitelist[rule_idx] = syscall_nr
                pkt.path_hash[rule_idx] = path_hash
                pkt.path_len[rule_idx] = path_len
                rule_idx += 1

    # Automatically add 'prctl' to whitelist (otherwise END cannot be called)
    prctl_nr = SYSCALL_TABLE.get('prctl')
    if prctl_nr and rule_idx < MAX_RULES:
        # Check if prctl already in whitelist
        prctl_exists = False
        for i in range(rule_idx):
            if pkt.whitelist[i] == prctl_nr and pkt.path_len[i] == 0:
                prctl_exists = True
                break

        if not prctl_exists:
            pkt.whitelist[rule_idx] = prctl_nr
            pkt.path_hash[rule_idx] = 0
            pkt.path_len[rule_idx] = 0
            rule_idx += 1

    # Call prctl(PR_SYSCALL_FILTER_CMD, &pkt, 0, 0, 0)
    try:
        result = libc.prctl(PR_SYSCALL_FILTER_CMD, ctypes.byref(pkt), 0, 0, 0)

        if result != 0:
            print("[syscall_filter] Warning: prctl() returned {}".format(result), file=sys.stderr)
            # Note: eBPF may override return value to 0, so non-zero could mean eBPF not loaded

        return result == 0
    except Exception as e:
        print("[syscall_filter] Error calling prctl: {}".format(e), file=sys.stderr)
        return False

def syscall_filter_end(syscall_rules):
    """
    Disable syscall filtering for the current thread.

    This removes the thread from eBPF monitoring and allows all syscalls again.
    The syscall_rules parameter should match the begin() call for proper cleanup.

    Args:
        syscall_rules: Dict of syscall rules (should match the begin() call)

    Returns:
        bool: True if successful, False otherwise

    Example:
        >>> syscall_filter_end({'read': [], 'openat': ['/etc/']})
        True
    """
    if libc is None:
        raise RuntimeError("libc not available")

    if not isinstance(syscall_rules, dict):
        raise TypeError("syscall_rules must be a dict")

    # Initialize packet (mirror begin logic)
    pkt = SyscallFilterPacket()
    pkt.cmd = CMD_FILTER_END
    for i in range(MAX_RULES):
        pkt.whitelist[i] = SYSCALL_SLOT_EMPTY
        pkt.path_hash[i] = 0
        pkt.path_len[i] = 0

    rule_idx = 0

    # Process rules (same as begin)
    for syscall_name, path_list in syscall_rules.items():
        if syscall_name not in SYSCALL_TABLE:
            continue

        syscall_nr = SYSCALL_TABLE[syscall_name]

        if not isinstance(path_list, (list, tuple)):
            continue

        if len(path_list) == 0:
            # Case A: No path constraint
            if rule_idx >= MAX_RULES:
                raise RuntimeError("Exceeded max rules limit ({})".format(MAX_RULES))

            pkt.whitelist[rule_idx] = syscall_nr
            pkt.path_hash[rule_idx] = 0
            pkt.path_len[rule_idx] = 0
            rule_idx += 1

        else:
            # Case B: Has path constraints
            for path in path_list:
                if rule_idx >= MAX_RULES:
                    raise RuntimeError("Exceeded max rules limit ({})".format(MAX_RULES))

                if not isinstance(path, str):
                    continue

                if len(path) >= MAX_PATH_LEN:
                    continue

                # Compute hash (must match begin)
                path_hash, path_len = hash_string(path)
                pkt.whitelist[rule_idx] = syscall_nr
                pkt.path_hash[rule_idx] = path_hash
                pkt.path_len[rule_idx] = path_len
                rule_idx += 1

    # Add prctl (mirror begin logic)
    prctl_nr = SYSCALL_TABLE.get('prctl')
    if prctl_nr and rule_idx < MAX_RULES:
        prctl_exists = False
        for i in range(rule_idx):
            if pkt.whitelist[i] == prctl_nr and pkt.path_len[i] == 0:
                prctl_exists = True
                break

        if not prctl_exists:
            pkt.whitelist[rule_idx] = prctl_nr
            pkt.path_hash[rule_idx] = 0
            pkt.path_len[rule_idx] = 0
            rule_idx += 1

    # Call prctl
    try:
        result = libc.prctl(PR_SYSCALL_FILTER_CMD, ctypes.byref(pkt), 0, 0, 0)

        if result != 0:
            print("[syscall_filter] Warning: prctl() returned {}".format(result), file=sys.stderr)

        return result == 0
    except Exception as e:
        print("[syscall_filter] Error calling prctl: {}".format(e), file=sys.stderr)
        return False

# ============================================================================
# Context manager
# ============================================================================

class SyscallFilter:
    """
    Context manager for syscall filtering with whitelist and path constraints.

    Protocol 4.0.0 - supports path parameter filtering.

    Usage:
        with SyscallFilter({'read': [], 'openat': ['/etc/', '/tmp/']}):
            # Code here can only use specified syscalls
            with open('/etc/hostname') as f:
                data = f.read()  # OK - /etc/ is whitelisted
            # open('/home/user/file') would fail with EPERM - /home/ not whitelisted

    Args:
        allowed_syscalls: Dict mapping syscall names to path lists

    Example:
        >>> with SyscallFilter({'read': [], 'write': [], 'openat': ['/tmp/']}):
        ...     with open('/tmp/test', 'w') as f:
        ...         f.write('test')  # Works
        >>> # Filter is automatically disabled after 'with' block
    """

    def __init__(self, allowed_syscalls):
        """
        Initialize the filter.

        Args:
            allowed_syscalls: Dict of syscall rules
        """
        if not isinstance(allowed_syscalls, dict):
            raise TypeError("allowed_syscalls must be a dict")

        self.allowed_syscalls = allowed_syscalls
        self._enabled = False

    def __enter__(self):
        """Enable syscall filtering."""
        syscall_filter_begin(self.allowed_syscalls)
        self._enabled = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Disable syscall filtering."""
        if self._enabled:
            syscall_filter_end(self.allowed_syscalls)
            self._enabled = False
        # Don't suppress exceptions
        return False

# ============================================================================
# Module metadata
# ============================================================================

__all__ = [
    'syscall_filter_begin',
    'syscall_filter_end',
    'SyscallFilter',
    'SyscallFilterPacket',
    'PR_SYSCALL_FILTER_CMD',
    'CMD_FILTER_BEGIN',
    'CMD_FILTER_END',
    'hash_string',
]

__version__ = '4.0.0'
