#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetFilter - Thread-level dynamic network interception based on cgroup + iptables

Filters network traffic by adding the current thread to a specific cgroup, 
coordinated with iptables rules inside the container:
- external_only: Only allow external access (block internal IPs)
- internal_only: Only allow internal access (block external IPs)

Prerequisites:
- Host has run: setup.sh <container_name>
- Container mounted: /sys/fs/cgroup:/sys/fs/cgroup:rw

Usage:
    from net_filter import NetFilter

    with NetFilter(external_only=True):
        requests.get("http://example.com")     # OK
        requests.get("http://192.168.1.1")     # Blocked (Connection timeout)
"""

import ctypes

# cgroup paths
CGROUP_BASE = "/sys/fs/cgroup/net_cls"
CGROUP_EXTERNAL = "{}/net_filter_external/tasks".format(CGROUP_BASE)
CGROUP_INTERNAL = "{}/net_filter_internal/tasks".format(CGROUP_BASE)
CGROUP_ROOT = "{}/tasks".format(CGROUP_BASE)

# Syscall number (x86_64 Linux)
SYS_GETTID = 186


def _get_tid():
    """Get TID of current thread (Container TID, kernel maps it to host TID)"""
    libc = ctypes.CDLL(None)
    return libc.syscall(SYS_GETTID)


class NetFilter:
    """
    Network filtering context manager (thread-level)

    Args:
        external_only: Only allow external access, block internal IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
        internal_only: Only allow internal access, block external IPs

    Example:
        # Prevent SSRF attacks against internal network
        with NetFilter(external_only=True):
            response = requests.get(user_provided_url)
            # If URL points to internal network, connection is DROPPED by iptables

        # Restrict access to internal services only
        with NetFilter(internal_only=True):
            response = requests.get("http://internal-api/data")
            # External requests will be blocked
    """

    def __init__(self, external_only=False, internal_only=False):
        # if external_only == internal_only:
        #     raise ValueError("Must specify either external_only or internal_only")
        self.cgroup = CGROUP_EXTERNAL if external_only else CGROUP_INTERNAL

    def __enter__(self):
        """Enter: Add current thread to the restricted cgroup"""
        tid = _get_tid()
        with open(self.cgroup, 'w') as f:
            f.write(str(tid))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit: Move current thread back to root cgroup (unrestricted)"""
        tid = _get_tid()
        with open(CGROUP_ROOT, 'w') as f:
            f.write(str(tid))
        return False  # Do not suppress exceptions


# Module exports
__all__ = ['NetFilter']
__version__ = '2.0.0'
