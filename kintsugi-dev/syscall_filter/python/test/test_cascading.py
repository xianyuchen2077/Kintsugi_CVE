#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cascading monitoring tests for Python syscall_filter

Tests the new cascading process/thread monitoring feature that automatically
monitors child processes created by monitored parent processes.

Tests:
1. Sanity check - verify operations work without filter
2. Basic cascading - child inherits parent's monitoring
3. Double fork - grandchild also monitored
4. Bypass attempt - fork blocked when not in whitelist
5. Path filtering - child inherits parent's path whitelist restrictions
"""

import sys
import os
import socket
import signal
import struct

# Add module to path
sys.path.insert(0, '/tmp/python_syscall_filter')

from syscall_filter import (
    syscall_filter_begin,
    syscall_filter_end,
)

# Exit codes for child processes
EXIT_SUCCESS = 0
EXIT_ALLOWED_OP_FAILED = 1
EXIT_BLOCKED_OP_SUCCEEDED = 2
EXIT_BLOCKED_OP_WRONG_ERROR = 3

def print_test(name):
    print(f"\n{'='*70}")
    print(f" {name}")
    print(f"{'='*70}")

def try_socket_operation():
    """
    Try to create a socket - this should be blocked if not in whitelist.
    Returns: (success: bool, error_code: int or None)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        return True, None
    except OSError as e:
        return False, e.errno

def try_read_file(path):
    """
    Try to read a file - used to test allowed operations.
    Returns: (success: bool, content or error)
    """
    try:
        with open(path, 'r') as f:
            content = f.read(100)
        return True, content
    except Exception as e:
        return False, str(e)

def test_cascading_basic():
    """
    Test 1: Basic cascading - child process inherits parent's monitoring

    Scenario:
    1. Parent enables monitoring with whitelist (no socket)
    2. Parent forks child
    3. Child tries allowed operation (read /etc/hostname) -> should succeed
    4. Child tries blocked operation (socket) -> should fail with EPERM
    """
    print_test("TEST 1: Basic Cascading - Child Inherits Monitoring")

    # Whitelist: basic file ops + fork/wait, but NO socket
    # Keep under MAX_RULES (32) limit
    rules = {
        # Core file operations
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': ['/etc/', '/tmp/'],
        'lseek': [],
        'ioctl': [],
        'pipe': [],
        'pipe2': [],
        # Process operations
        'fork': [],
        'clone': [],
        'wait4': [],
        'exit_group': [],
        # Memory management
        'brk': [],
        'mmap': [],
        'munmap': [],
        'mprotect': [],
        # Essential runtime
        'arch_prctl': [],
        'futex': [],
        'rt_sigaction': [],
        'rt_sigprocmask': [],
        'getpid': [],
        # NOTE: socket is NOT in whitelist - should be blocked
    }

    print("Enabling filter with whitelist (socket NOT included)...")
    try:
        result = syscall_filter_begin(rules)
        if not result:
            print("  syscall_filter_begin() returned False")
            print("  (This is expected if eBPF loader is not running)")
            return False
        print("  Filter enabled")
    except Exception as e:
        print(f"  Filter enable failed: {e}")
        return False

    # Create pipe for child to report results
    read_fd, write_fd = os.pipe()

    print("\nForking child process...")
    pid = os.fork()

    if pid == 0:
        # ========== CHILD PROCESS ==========
        os.close(read_fd)

        results = []

        # Test 1: Allowed operation - read /etc/hostname
        success, content = try_read_file('/etc/hostname')
        if success:
            results.append(('read_hostname', 'PASS', content.strip()))
        else:
            results.append(('read_hostname', 'FAIL', content))

        # Test 2: Blocked operation - socket (should fail with EPERM)
        success, errno = try_socket_operation()
        if not success and errno == 1:  # EPERM
            results.append(('socket_blocked', 'PASS', 'EPERM'))
        elif not success:
            results.append(('socket_blocked', 'FAIL', f'wrong errno: {errno}'))
        else:
            results.append(('socket_blocked', 'FAIL', 'socket succeeded (should be blocked)'))

        # Send results to parent
        result_str = ';'.join([f"{r[0]}:{r[1]}:{r[2]}" for r in results])
        os.write(write_fd, result_str.encode())
        os.close(write_fd)

        # Exit based on results
        if all(r[1] == 'PASS' for r in results):
            os._exit(EXIT_SUCCESS)
        else:
            os._exit(EXIT_BLOCKED_OP_SUCCEEDED)

    else:
        # ========== PARENT PROCESS ==========
        os.close(write_fd)

        # Wait for child
        _, status = os.waitpid(pid, 0)
        exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

        # Read results from child
        results_data = os.read(read_fd, 4096).decode()
        os.close(read_fd)

        print(f"\nChild process exited with code: {exit_code}")
        print(f"Child results: {results_data}")

        # Parse and display results
        passed = True
        for item in results_data.split(';'):
            if item:
                parts = item.split(':')
                if len(parts) >= 3:
                    test_name, status, detail = parts[0], parts[1], ':'.join(parts[2:])
                    if status == 'PASS':
                        print(f"  [PASS] {test_name}: {detail}")
                    else:
                        print(f"  [FAIL] {test_name}: {detail}")
                        passed = False

        # Disable filter
        print("\nDisabling filter...")
        try:
            syscall_filter_end(rules)
            print("  Filter disabled")
        except Exception as e:
            print(f"  Filter disable failed: {e}")
            return False

        return passed

def test_cascading_double_fork():
    """
    Test 2: Double fork - grandchild also monitored

    Scenario:
    1. Parent enables monitoring
    2. Parent forks child
    3. Child forks grandchild
    4. Grandchild tries blocked operation -> should fail
    """
    print_test("TEST 2: Double Fork - Grandchild Also Monitored")

    # Keep under MAX_RULES (32) limit
    rules = {
        # Core file operations
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': ['/etc/'],
        'lseek': [],
        'ioctl': [],
        'pipe': [],
        'pipe2': [],
        # Process operations
        'fork': [],
        'clone': [],
        'wait4': [],
        'exit_group': [],
        # Memory management
        'brk': [],
        'mmap': [],
        'munmap': [],
        'mprotect': [],
        # Essential runtime
        'arch_prctl': [],
        'futex': [],
        'rt_sigaction': [],
        'rt_sigprocmask': [],
        'getpid': [],
        # socket NOT included
    }

    print("Enabling filter...")
    try:
        result = syscall_filter_begin(rules)
        if not result:
            print("  syscall_filter_begin() returned False")
            return False
        print("  Filter enabled")
    except Exception as e:
        print(f"  Filter enable failed: {e}")
        return False

    read_fd, write_fd = os.pipe()

    print("\nForking child process...")
    pid = os.fork()

    if pid == 0:
        # ========== CHILD PROCESS ==========
        os.close(read_fd)

        # Fork grandchild
        grandchild_read_fd, grandchild_write_fd = os.pipe()
        grandchild_pid = os.fork()

        if grandchild_pid == 0:
            # ========== GRANDCHILD PROCESS ==========
            os.close(grandchild_read_fd)
            os.close(write_fd)

            # Try blocked operation
            success, errno = try_socket_operation()
            if not success and errno == 1:
                result = "PASS:EPERM"
            elif not success:
                result = f"FAIL:wrong_errno_{errno}"
            else:
                result = "FAIL:socket_succeeded"

            os.write(grandchild_write_fd, result.encode())
            os.close(grandchild_write_fd)
            os._exit(0)

        else:
            # Child waits for grandchild
            os.close(grandchild_write_fd)
            os.waitpid(grandchild_pid, 0)
            grandchild_result = os.read(grandchild_read_fd, 1024).decode()
            os.close(grandchild_read_fd)

            # Send to parent
            os.write(write_fd, f"grandchild:{grandchild_result}".encode())
            os.close(write_fd)
            os._exit(0)

    else:
        # ========== PARENT PROCESS ==========
        os.close(write_fd)

        os.waitpid(pid, 0)
        results_data = os.read(read_fd, 4096).decode()
        os.close(read_fd)

        print(f"\nResults: {results_data}")

        passed = "PASS" in results_data
        if passed:
            print("  [PASS] Grandchild's socket operation was blocked")
        else:
            print("  [FAIL] Grandchild's socket operation was NOT blocked")

        print("\nDisabling filter...")
        syscall_filter_end(rules)
        print("  Filter disabled")

        return passed

def test_cascading_bypass_attempt():
    """
    Test 3: Bypass attempt - try to fork when fork is not in whitelist

    Scenario:
    1. Parent enables monitoring WITHOUT fork in whitelist
    2. Parent tries to fork -> should fail with EPERM
    """
    print_test("TEST 3: Bypass Attempt - Fork Blocked When Not Whitelisted")

    # Whitelist WITHOUT fork/clone - Keep under MAX_RULES (32) limit
    rules = {
        # Core file operations
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': [],
        'lseek': [],
        'ioctl': [],
        # Memory management
        'brk': [],
        'mmap': [],
        'munmap': [],
        'mprotect': [],
        # Essential runtime
        'arch_prctl': [],
        'futex': [],
        'rt_sigaction': [],
        'rt_sigprocmask': [],
        'getpid': [],
        'exit_group': [],
        # NOTE: fork/clone NOT included
    }

    print("Enabling filter WITHOUT fork/clone...")
    try:
        result = syscall_filter_begin(rules)
        if not result:
            print("  syscall_filter_begin() returned False")
            return False
        print("  Filter enabled")
    except Exception as e:
        print(f"  Filter enable failed: {e}")
        return False

    print("\nAttempting to fork (should fail)...")
    try:
        pid = os.fork()
        if pid == 0:
            # Child - should not reach here
            os._exit(1)
        else:
            # Parent - fork succeeded, this is a failure
            os.waitpid(pid, 0)
            print("  [FAIL] Fork succeeded (should have been blocked)")
            syscall_filter_end(rules)
            return False
    except OSError as e:
        if e.errno == 1:  # EPERM
            print(f"  [PASS] Fork blocked with EPERM")
            syscall_filter_end(rules)
            return True
        else:
            print(f"  [FAIL] Fork failed with unexpected error: {e}")
            syscall_filter_end(rules)
            return False
    except Exception as e:
        print(f"  [?] Unexpected exception: {e}")
        syscall_filter_end(rules)
        return False

def test_cascading_path_filtering():
    """
    Test 4: Path filtering inheritance - child inherits path whitelist

    Scenario:
    1. Parent enables monitoring with openat restricted to /etc/ only
    2. Parent forks child
    3. Child tries to read /etc/hostname -> should succeed (in path whitelist)
    4. Child tries to read /tmp/test.txt -> should fail (path not in whitelist)
    5. Child tries to read /var/log/syslog -> should fail (path not in whitelist)
    """
    print_test("TEST 4: Path Filtering Inheritance")

    # Whitelist with path restriction: openat only allows /etc/
    # Keep under MAX_RULES (32) limit
    rules = {
        # Core file operations
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': ['/etc/'],  # ONLY /etc/ is allowed, /tmp/ and /var/ are blocked
        'lseek': [],
        'ioctl': [],
        'pipe': [],
        'pipe2': [],
        # Process operations
        'fork': [],
        'clone': [],
        'wait4': [],
        'exit_group': [],
        # Memory management
        'brk': [],
        'mmap': [],
        'munmap': [],
        'mprotect': [],
        # Essential runtime
        'arch_prctl': [],
        'futex': [],
        'rt_sigaction': [],
        'rt_sigprocmask': [],
        'getpid': [],
    }

    print("Enabling filter with openat restricted to /etc/ only...")
    try:
        result = syscall_filter_begin(rules)
        if not result:
            print("  syscall_filter_begin() returned False")
            return False
        print("  Filter enabled")
    except Exception as e:
        print(f"  Filter enable failed: {e}")
        return False

    # Create a test file in /tmp for child to try accessing
    test_file = '/tmp/cascading_path_test.txt'
    try:
        with open(test_file, 'w') as f:
            f.write('test content')
    except:
        pass  # May fail if filter already active, that's ok

    read_fd, write_fd = os.pipe()

    print("\nForking child process...")
    pid = os.fork()

    if pid == 0:
        # ========== CHILD PROCESS ==========
        os.close(read_fd)

        results = []

        # Test 1: Allowed path - /etc/hostname (should succeed)
        success, content = try_read_file('/etc/hostname')
        if success:
            results.append(('read_etc', 'PASS', f'content={content.strip()[:20]}'))
        else:
            results.append(('read_etc', 'FAIL', content))

        # Test 2: Blocked path - /tmp/ (should fail with EPERM)
        try:
            with open(test_file, 'r') as f:
                _ = f.read()
            results.append(('read_tmp', 'FAIL', 'read succeeded (should be blocked)'))
        except PermissionError as e:
            if e.errno == 1:  # EPERM
                results.append(('read_tmp', 'PASS', 'EPERM'))
            else:
                results.append(('read_tmp', 'FAIL', f'wrong errno: {e.errno}'))
        except OSError as e:
            if e.errno == 1:  # EPERM
                results.append(('read_tmp', 'PASS', 'EPERM'))
            else:
                results.append(('read_tmp', 'FAIL', f'OSError: {e.errno}'))
        except FileNotFoundError:
            results.append(('read_tmp', 'SKIP', 'file not found'))
        except Exception as e:
            results.append(('read_tmp', 'FAIL', str(e)))

        # Test 3: Blocked path - /var/log/ (should fail with EPERM)
        try:
            with open('/var/log/syslog', 'r') as f:
                _ = f.read(10)
            results.append(('read_var', 'FAIL', 'read succeeded (should be blocked)'))
        except PermissionError as e:
            if e.errno == 1:  # EPERM
                results.append(('read_var', 'PASS', 'EPERM'))
            else:
                results.append(('read_var', 'FAIL', f'wrong errno: {e.errno}'))
        except OSError as e:
            if e.errno == 1:  # EPERM
                results.append(('read_var', 'PASS', 'EPERM'))
            else:
                results.append(('read_var', 'FAIL', f'OSError: {e.errno}'))
        except FileNotFoundError:
            results.append(('read_var', 'SKIP', 'file not found'))
        except Exception as e:
            results.append(('read_var', 'FAIL', str(e)))

        # Send results to parent
        result_str = ';'.join([f"{r[0]}:{r[1]}:{r[2]}" for r in results])
        os.write(write_fd, result_str.encode())
        os.close(write_fd)
        os._exit(0)

    else:
        # ========== PARENT PROCESS ==========
        os.close(write_fd)

        os.waitpid(pid, 0)
        results_data = os.read(read_fd, 4096).decode()
        os.close(read_fd)

        print(f"\nChild results: {results_data}")

        # Parse and display results
        passed = True
        for item in results_data.split(';'):
            if item:
                parts = item.split(':')
                if len(parts) >= 3:
                    test_name, status, detail = parts[0], parts[1], ':'.join(parts[2:])
                    if status == 'PASS':
                        print(f"  [PASS] {test_name}: {detail}")
                    elif status == 'SKIP':
                        print(f"  [SKIP] {test_name}: {detail}")
                    else:
                        print(f"  [FAIL] {test_name}: {detail}")
                        passed = False

        # Cleanup
        print("\nDisabling filter...")
        syscall_filter_end(rules)
        print("  Filter disabled")

        # Remove test file
        try:
            os.unlink(test_file)
        except:
            pass

        return passed

def test_cascading_no_filter():
    """
    Test 5: Sanity check - operations work without filter
    """
    print_test("TEST 5: Sanity Check - Operations Work Without Filter")

    print("Testing socket without filter...")
    success, errno = try_socket_operation()
    if success:
        print("  [PASS] Socket created successfully")
    else:
        print(f"  [FAIL] Socket failed: errno={errno}")
        return False

    print("\nTesting fork without filter...")
    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        else:
            os.waitpid(pid, 0)
            print("  [PASS] Fork succeeded")
    except Exception as e:
        print(f"  [FAIL] Fork failed: {e}")
        return False

    return True

# ============================================================================
# Main test runner
# ============================================================================

def main():
    print("\n" + "="*70)
    print(" Python Syscall Filter - Cascading Monitoring Tests")
    print("="*70)

    results = {}

    # Run sanity check first
    results['sanity_check'] = test_cascading_no_filter()

    if not results['sanity_check']:
        print("\n[ERROR] Sanity check failed - system may not support required operations")
        return 1

    # Run cascading tests
    results['basic_cascading'] = test_cascading_basic()
    results['double_fork'] = test_cascading_double_fork()
    results['bypass_attempt'] = test_cascading_bypass_attempt()
    results['path_filtering'] = test_cascading_path_filtering()

    # Summary
    print_test("TEST SUMMARY")
    passed = sum(results.values())
    total = len(results)

    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"[{status}] {test_name}")

    print(f"\n{passed}/{total} tests passed")

    if passed == total:
        print("\nAll cascading monitoring tests passed!")
        return 0
    else:
        print(f"\n{total - passed} tests failed")
        print("\nNote: If eBPF loader is not running, tests will fail.")
        print("Start eBPF loader on host: sudo python3 syscall_filter/ebpf_load.py &")
        return 1

if __name__ == '__main__':
    sys.exit(main())
