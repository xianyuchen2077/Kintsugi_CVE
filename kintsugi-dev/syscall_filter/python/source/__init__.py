#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Syscall Filter - eBPF-based syscall filtering for Python

This package provides Python bindings for the eBPF syscall filtering system,
allowing Python applications to control which syscalls are permitted at runtime.

Basic Usage:
    from syscall_filter import syscall_filter_begin, syscall_filter_end

    syscall_filter_begin(['read', 'write', 'open', 'close'])
    # ... code with restricted syscalls ...
    syscall_filter_end(['read', 'write', 'open', 'close'])

Context Manager Usage:
    from syscall_filter import SyscallFilter

    with SyscallFilter(['read', 'write']):
        # ... code with restricted syscalls ...
        pass

Requirements:
    - Linux kernel >= 4.4 (eBPF support)
    - eBPF loader running on host: sudo python3 syscall_filter/ebpf_load.py
    - x86-64 architecture (syscall numbers)

Author: LLM Vulnerability Repair Project
Version: 1.0.0
"""

# Import all from core module
from .syscall_filter import (
    syscall_filter_begin,
    syscall_filter_end,
    SyscallFilter,
    SyscallCmd,
    PR_SYSCALL_FILTER_CMD,
    CMD_BEGIN,
    CMD_END,
    __version__,
)

# Module metadata
__author__ = 'LLM Vulnerability Repair Project'
__all__ = [
    'syscall_filter_begin',
    'syscall_filter_end',
    'SyscallFilter',
    'SyscallCmd',
    'PR_SYSCALL_FILTER_CMD',
    'CMD_BEGIN',
    'CMD_END',
]
