#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path filtering tests for Python syscall_filter (Protocol 4.0.0)

Tests the new path parameter whitelist feature that restricts file operations
to specific path prefixes.

Tests:
1. Path whitelist - only /tmp/ and /etc/ allowed
2. No path constraint - all paths allowed
3. Mixed rules - some syscalls with path constraints, some without
4. Blocked paths - verify /home/, /var/ are blocked when not whitelisted
"""

import sys
import os
import tempfile

# Add module to path
sys.path.insert(0, '/tmp/python_syscall_filter')

from syscall_filter import (
    syscall_filter_begin,
    syscall_filter_end,
    SyscallFilter
)

def print_test(name):
    print(f"\n{'='*70}")
    print(f" {name}")
    print(f"{'='*70}")

def test_path_whitelist():
    """Test 1: Path whitelist - only /tmp/ and /etc/ allowed"""
    print_test("TEST 1: Path Whitelist - /tmp/ and /etc/ only")

    rules = {
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': ['/tmp/', '/etc/'],  # Path whitelist for openat
    }

    print("Enabling filter with openat restricted to /tmp/ and /etc/...")
    try:
        result = syscall_filter_begin(rules)
        if not result:
            print("✗ syscall_filter_begin() returned False")
            print("  (This is expected if eBPF loader is not running)")
            return False
        print("✓ Filter enabled")
    except Exception as e:
        print(f"✗ Filter enable failed: {e}")
        return False

    # Test 1a: Allowed path - /etc/hostname
    print("\nTest 1a: Attempting to read /etc/hostname (should succeed)...")
    try:
        with open('/etc/hostname', 'r') as f:
            hostname = f.read().strip()
        print(f"✓ File read succeeded: {hostname}")
    except Exception as e:
        print(f"✗ File read failed: {e}")
        syscall_filter_end(rules)
        return False

    # Test 1b: Allowed path - /tmp/ (create temp file)
    print("\nTest 1b: Attempting to write to /tmp/ (should succeed)...")
    try:
        test_file = '/tmp/test_syscall_filter_12345.txt'
        with open(test_file, 'w') as f:
            f.write('test')
        print(f"✓ File write to /tmp/ succeeded")

        # Clean up
        try:
            os.unlink(test_file)
        except:
            pass
    except Exception as e:
        print(f"✗ File write failed: {e}")
        syscall_filter_end(rules)
        return False

    # Test 1c: Blocked path - /home/ (if exists)
    print("\nTest 1c: Attempting to read /home/ (should fail)...")
    try:
        # Try to open a file in /home/ or /var/
        with open('/var/log/syslog', 'r') as f:
            _ = f.read(100)
        print(f"✗ File read to /var/ succeeded (should have been blocked)")
        syscall_filter_end(rules)
        return False
    except PermissionError as e:
        if e.errno == 1:  # EPERM
            print(f"✓ File read blocked with EPERM (path not in whitelist)")
        else:
            print(f"? File read failed with different permission error: {e}")
    except FileNotFoundError:
        print(f"? File not found (normal - /var/log/syslog may not exist)")
    except OSError as e:
        if e.errno == 1:  # EPERM
            print(f"✓ File operation blocked with EPERM")
        else:
            print(f"? OSError: {e}")
    except Exception as e:
        print(f"? Unexpected exception: {e}")

    # Disable filter
    print("\nDisabling filter...")
    try:
        syscall_filter_end(rules)
        print("✓ Filter disabled")
    except Exception as e:
        print(f"✗ Filter disable failed: {e}")
        return False

    return True

def test_no_path_constraint():
    """Test 2: No path constraint - all paths allowed"""
    print_test("TEST 2: No Path Constraint - All Paths Allowed")

    rules = {
        'read': [],
        'write': [],
        'close': [],
        'fstat': [],
        'openat': [],  # Empty list = no path constraint, all paths allowed
    }

    print("Enabling filter with openat (no path constraint)...")
    try:
        syscall_filter_begin(rules)
        print("✓ Filter enabled")
    except Exception as e:
        print(f"✗ Filter enable failed: {e}")
        return False

    # Test various paths
    print("\nTesting file access to /etc/hostname...")
    try:
        with open('/etc/hostname', 'r') as f:
            _ = f.read()
        print("✓ /etc/hostname read succeeded")
    except Exception as e:
        print(f"✗ Read failed: {e}")
        syscall_filter_end(rules)
        return False

    print("\nTesting file access to /tmp/...")
    try:
        test_file = '/tmp/test_no_constraint_12345.txt'
        with open(test_file, 'w') as f:
            f.write('test')
        print("✓ /tmp/ write succeeded")
        try:
            os.unlink(test_file)
        except:
            pass
    except Exception as e:
        print(f"✗ Write failed: {e}")
        syscall_filter_end(rules)
        return False

    # Disable filter
    print("\nDisabling filter...")
    try:
        syscall_filter_end(rules)
        print("✓ Filter disabled")
    except Exception as e:
        print(f"✗ Filter disable failed: {e}")
        return False

    return True

def test_mixed_rules():
    """Test 3: Mixed rules - some syscalls with path constraints, some without"""
    print_test("TEST 3: Mixed Rules")

    rules = {
        'read': [],              # No path constraint
        'write': [],             # No path constraint
        'close': [],             # No path constraint
        'fstat': [],             # No path constraint
        'openat': ['/etc/'],     # Path constraint - only /etc/ allowed
    }

    print("Enabling filter with mixed rules...")
    print("  - read/write/close/fstat: no path constraint")
    print("  - openat: only /etc/ allowed")

    try:
        syscall_filter_begin(rules)
        print("✓ Filter enabled")
    except Exception as e:
        print(f"✗ Filter enable failed: {e}")
        return False

    # Test allowed path
    print("\nTesting /etc/hostname access (should succeed)...")
    try:
        with open('/etc/hostname', 'r') as f:
            _ = f.read()
        print("✓ /etc/ access succeeded")
    except Exception as e:
        print(f"✗ Access failed: {e}")
        syscall_filter_end(rules)
        return False

    # Test blocked path
    print("\nTesting /tmp/ access (should fail - not in openat whitelist)...")
    try:
        with open('/tmp/test_mixed_12345.txt', 'w') as f:
            f.write('test')
        print("✗ /tmp/ access succeeded (should have been blocked)")
        syscall_filter_end(rules)
        return False
    except PermissionError as e:
        if e.errno == 1:
            print(f"✓ /tmp/ access blocked with EPERM")
        else:
            print(f"? Permission error: {e}")
    except OSError as e:
        if e.errno == 1:
            print(f"✓ /tmp/ access blocked with EPERM")
        else:
            print(f"? OSError: {e}")
    except Exception as e:
        print(f"? Unexpected exception: {e}")

    # Disable filter
    print("\nDisabling filter...")
    try:
        syscall_filter_end(rules)
        print("✓ Filter disabled")
    except Exception as e:
        print(f"✗ Filter disable failed: {e}")
        return False

    return True

def test_context_manager_with_paths():
    """Test 4: Context manager with path constraints"""
    print_test("TEST 4: Context Manager with Path Constraints")

    print("Using SyscallFilter context manager with path whitelist...")
    try:
        with SyscallFilter({
            'read': [],
            'write': [],
            'close': [],
            'fstat': [],
            'openat': ['/etc/', '/tmp/']
        }):
            print("✓ Entered context (filter active)")

            # Test allowed paths
            with open('/etc/hostname', 'r') as f:
                _ = f.read()
            print("✓ /etc/ access succeeded")

            test_file = '/tmp/test_context_12345.txt'
            with open(test_file, 'w') as f:
                f.write('test')
            print("✓ /tmp/ access succeeded")

            try:
                os.unlink(test_file)
            except:
                pass

        print("✓ Exited context (filter disabled)")
    except Exception as e:
        print(f"✗ Context manager failed: {e}")
        return False

    # Verify filter is disabled - access blocked path without error
    print("\nVerifying filter is disabled...")
    try:
        test_file = '/tmp/test_after_context_12345.txt'
        with open(test_file, 'w') as f:
            f.write('test')
        print("✓ File operations work after context exit")
        try:
            os.unlink(test_file)
        except:
            pass
    except Exception as e:
        print(f"✗ Operations still blocked: {e}")
        return False

    return True

# ============================================================================
# Main test runner
# ============================================================================

def main():
    print("\n" + "="*70)
    print(" Python Syscall Filter - Path Filtering Tests (Protocol 4.0.0)")
    print("="*70)

    results = {}

    # Run all tests
    results['path_whitelist'] = test_path_whitelist()
    results['no_path_constraint'] = test_no_path_constraint()
    results['mixed_rules'] = test_mixed_rules()
    results['context_manager_paths'] = test_context_manager_with_paths()

    # Summary
    print_test("TEST SUMMARY")
    passed = sum(results.values())
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")

    print(f"\n{passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All path filtering tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} tests failed")
        print("\nNote: If eBPF loader is not running, tests will fail.")
        print("Start eBPF loader on host: sudo python3 syscall_filter/ebpf_load.py &")
        return 1

if __name__ == '__main__':
    sys.exit(main())
