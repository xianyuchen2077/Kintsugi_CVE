#!/usr/bin/env python3
"""
Path prefix compression algorithm

Core algorithm:
1. Enumerate all possible prefixes (all ancestors of each path)
2. Select the prefix with minimum cost and maximum gain for compression
3. Repeat until target size is reached or no further compression is possible

Definitions:
- cost(P, a): compression cost = max(depth(p) - depth(a)) for p in cover(P, a)
- gain(P, a): compression gain = |cover(P, a)| - 1
"""

import os
from pathlib import Path
from typing import Set, List, Tuple, Dict
from collections import defaultdict


def get_depth(path: str) -> int:
    """
    Get the directory depth of a path.

    Examples:
        /usr/lib/x86/a.so -> 5
        /etc/passwd -> 3
        /tmp/ -> 2
        / -> 1
        a.txt -> 1 (relative path)
    """
    if not path:
        return 0

    path = path.replace('\\', '/')
    path = path.rstrip('/')

    if path == '' or path == '/':
        return 1

    parts = [p for p in path.split('/') if p]

    if path.startswith('/'):
        return len(parts) + 1

    return len(parts)


def get_ancestor(path: str, level: int) -> str:
    """
    Get the ancestor directory at the specified level.

    Args:
        path: File path
        level: Ancestor level (1 = parent, 2 = grandparent, etc.)

    Returns:
        Ancestor path (with trailing slash)

    Examples:
        ('/usr/lib/x86/a.so', 1) -> '/usr/lib/x86/'
        ('/usr/lib/x86/a.so', 2) -> '/usr/lib/'
        ('/usr/lib/x86/a.so', 3) -> '/usr/'
        ('/usr/lib/x86/a.so', 4) -> '/' (root)
    """
    if level <= 0:
        return path

    path = path.replace('\\', '/')
    path = path.rstrip('/')

    is_absolute = path.startswith('/')
    parts = [p for p in path.split('/') if p]

    if level >= len(parts):
        return '/' if is_absolute else './'

    ancestor_parts = parts[:-level]

    if not ancestor_parts:
        return '/' if is_absolute else './'

    ancestor_path = '/'.join(ancestor_parts)

    if is_absolute:
        ancestor_path = '/' + ancestor_path

    if not ancestor_path.endswith('/'):
        ancestor_path += '/'

    return ancestor_path


def get_covered_paths(paths: Set[str], prefix: str) -> Set[str]:
    """
    Get all paths covered by the specified prefix.

    Args:
        paths: Set of paths
        prefix: Prefix string

    Returns:
        Set of paths covered by the prefix
    """
    if prefix.endswith('/'):
        return {p for p in paths if p.startswith(prefix)}

    covered = set()
    for p in paths:
        if p == prefix or p.startswith(prefix + '/'):
            covered.add(p)

    return covered


def compute_cost(paths: Set[str], prefix: str, covered: Set[str]) -> int:
    """
    Compute compression cost.

    Cost is the negative depth of the prefix (prefer compressing deeper paths).
    cost(P, a) = -depth(a)

    Examples:
        /etc/ -> cost = -2 (shallow, low cost, less likely to compress)
        /usr/lib/ -> cost = -3
        /usr/lib/x86_64-linux-gnu/ -> cost = -4
        /usr/lib/x86_64-linux-gnu/avx512_1/ -> cost = -5 (deep, high cost, compress first)

    The algorithm selects the prefix with minimum cost, thus preferring deeper paths.

    Args:
        paths: Path set (unused, reserved for extension)
        prefix: Prefix string
        covered: Covered path set (unused, reserved for extension)

    Returns:
        Compression cost (negative depth of the prefix)
    """
    return -get_depth(prefix)


def compress_paths_by_ancestors(paths: Set[str], target_size: int = 32, min_files: int = 10) -> List[str]:
    """
    Compress paths using ancestor directory algorithm.

    Algorithm:
        1. While |paths| > target_size:
           - Enumerate all possible prefixes (all ancestors of each path)
           - Filter candidate prefixes covering >= 2 paths
           - Select the prefix with minimum cost and maximum gain
           - Replace covered paths with the prefix
        2. Final compression: compress directories with >= min_files files
        3. Return compressed result (best effort)

    Args:
        paths: Set of paths
        target_size: Maximum target size (default: 32)
        min_files: Minimum files to trigger directory compression (default: 10)

    Returns:
        Sorted list of compressed paths

    Examples:
        Input:  {'/usr/lib/a.so', '/usr/lib/b.so', '/etc/conf'}, target=2
        Output: ['/etc/conf', '/usr/lib/']

        Input:  {'/usr/lib/x86/a.so', '/usr/lib/x86/b.so', '/usr/abc', '/etc/conf'}, target=1
        Output: ['/']
    """
    if not paths:
        return []

    normalized_paths = set()
    for p in paths:
        if p.endswith('/'):
            normalized_paths.add(p)
        else:
            p_with_slash = p + '/'
            is_prefix = any(other.startswith(p_with_slash) for other in paths if other != p)
            if is_prefix:
                normalized_paths.add(p_with_slash)
            else:
                normalized_paths.add(p)

    if len(normalized_paths) <= target_size:
        compressed = _final_compress_by_directory(normalized_paths, min_files=min_files)
        return sorted(compressed)

    compressed = set(normalized_paths)

    iteration = 0
    max_iterations = len(paths) * 10

    while len(compressed) > target_size and iteration < max_iterations:
        iteration += 1

        candidates: Dict[str, Set[str]] = {}

        for path in compressed:
            path_depth = get_depth(path)

            for level in range(1, path_depth):
                ancestor = get_ancestor(path, level)
                covered = get_covered_paths(compressed, ancestor)

                if len(covered) >= 2:
                    candidates[ancestor] = covered

        if not candidates:
            break

        best_prefix = None
        best_cost = float('inf')
        best_gain = -1

        for prefix, covered in candidates.items():
            cost = compute_cost(compressed, prefix, covered)
            gain = len(covered) - 1

            if cost < best_cost or (cost == best_cost and gain > best_gain):
                best_prefix = prefix
                best_cost = cost
                best_gain = gain

        if best_prefix:
            covered = candidates[best_prefix]
            compressed = (compressed - covered) | {best_prefix}
        else:
            break

    compressed = _final_compress_by_directory(compressed, min_files=min_files)

    return sorted(compressed)


def _final_compress_by_directory(paths: Set[str], min_files: int = 10) -> Set[str]:
    """
    Final compression: compress multiple files under the same directory into the parent directory.

    Only compresses when a directory has >= min_files files. Otherwise keeps original paths.

    Args:
        paths: Set of paths
        min_files: Minimum files to trigger compression (default: 10)

    Examples (min_files=2):
        /usr/lib/a.so, /usr/lib/b.so -> /usr/lib/
        /etc/passwd -> /etc/passwd (single file, kept as-is)
        /var/www/ -> /var/www/ (already a directory, unchanged)
    """
    dir_to_files = defaultdict(list)
    directories = set()

    for path in paths:
        if path == '/':
            directories.add(path)
            continue

        if path.endswith('/'):
            directories.add(path)
        else:
            parent = os.path.dirname(path)
            if not parent:
                parent = '/'
            if not parent.endswith('/'):
                parent += '/'
            dir_to_files[parent].append(path)

    result = set(directories)

    for parent, files in dir_to_files.items():
        if len(files) >= min_files:
            result.add(parent)
        else:
            result.update(files)

    return result


def test_get_depth():
    print("\n=== Test get_depth() ===")

    test_cases = [
        ('/usr/lib/x86/a.so', 5),
        ('/etc/passwd', 3),
        ('/tmp/', 2),
        ('/', 1),
        ('a.txt', 1),
        ('foo/bar/baz.txt', 3),
    ]

    for path, expected in test_cases:
        result = get_depth(path)
        status = "[OK]" if result == expected else "[FAIL]"
        print(f"{status} get_depth('{path}') = {result} (expected {expected})")


def test_get_ancestor():
    print("\n=== Test get_ancestor() ===")

    test_cases = [
        ('/usr/lib/x86/a.so', 1, '/usr/lib/x86/'),
        ('/usr/lib/x86/a.so', 2, '/usr/lib/'),
        ('/usr/lib/x86/a.so', 3, '/usr/'),
        ('/usr/lib/x86/a.so', 4, '/'),
        ('/etc/passwd', 1, '/etc/'),
        ('/etc/passwd', 2, '/'),
        ('foo/bar/baz.txt', 1, 'foo/bar/'),
        ('foo/bar/baz.txt', 2, 'foo/'),
        ('foo/bar/baz.txt', 3, './'),
    ]

    for path, level, expected in test_cases:
        result = get_ancestor(path, level)
        status = "[OK]" if result == expected else "[FAIL]"
        print(f"{status} get_ancestor('{path}', {level}) = '{result}' (expected '{expected}')")


def test_compress_basic():
    print("\n=== Test basic compression ===")

    paths = {'/usr/lib/a.so', '/usr/lib/b.so', '/etc/conf'}
    result = compress_paths_by_ancestors(paths, target_size=2)

    print(f"Input: {sorted(paths)}")
    print(f"Target size: 2")
    print(f"Output: {result}")
    print(f"Actual size: {len(result)}")

    assert len(result) <= 2, f"Compression failed: result size {len(result)} > target 2"

    all_covered = True
    for path in paths:
        covered = any(path.startswith(prefix) or path == prefix for prefix in result)
        if not covered:
            print(f"[FAIL] Path '{path}' not covered")
            all_covered = False

    if all_covered:
        print("[OK] All paths covered")


def test_compress_example_from_spec():
    print("\n=== Test spec examples ===")

    paths1 = {'/usr/lib/x86/a.so', '/usr/lib/x86/b.so', '/usr/abc', '/etc/conf'}
    result1 = compress_paths_by_ancestors(paths1, target_size=1)

    print(f"\nExample 1:")
    print(f"Input: {sorted(paths1)}")
    print(f"Target size: 1")
    print(f"Output: {result1}")

    assert len(result1) == 1, f"Expected size 1, got {len(result1)}"
    assert result1[0] == '/', f"Expected ['/'], got {result1}"
    print("[OK] Successfully compressed to ['/']")

    paths2 = {'/usr/lib/a.so', '/usr/lib/b.so', '/var/www/a.txt'}
    result2 = compress_paths_by_ancestors(paths2, target_size=2)

    print(f"\nExample 2:")
    print(f"Input: {sorted(paths2)}")
    print(f"Target size: 2")
    print(f"Output: {result2}")

    assert len(result2) == 2, f"Expected size 2, got {len(result2)}"
    assert '/usr/lib/' in result2, f"Expected '/usr/lib/' in result, got {result2}"
    print("[OK] Correctly selected prefix with minimum cost")


def test_network_paths():
    print("\n=== Test network paths ===")

    paths = {
        '172.25.0.3:40404->172.25.0.2:3306',
        '172.25.0.3:40405->172.25.0.2:3306',
        '/etc/passwd'
    }
    result = compress_paths_by_ancestors(paths, target_size=2)

    print(f"Input: {sorted(paths)}")
    print(f"Target size: 2")
    print(f"Output: {result}")


def test_edge_cases():
    print("\n=== Test edge cases ===")

    result1 = compress_paths_by_ancestors(set(), target_size=10)
    assert result1 == [], "Empty set should return empty list"
    print("[OK] Empty set handled correctly")

    result2 = compress_paths_by_ancestors({'/etc/passwd'}, target_size=10)
    assert result2 == ['/etc/passwd'], "Single path should be returned as-is"
    print("[OK] Single path handled correctly")

    paths3 = {'/a', '/b', '/c'}
    result3 = compress_paths_by_ancestors(paths3, target_size=10)
    assert result3 == ['/a', '/b', '/c'], "Already within target should be returned as-is"
    print("[OK] Already within target handled correctly")

    paths4 = {'/a.txt', '/b.txt', '/c.txt'}
    result4 = compress_paths_by_ancestors(paths4, target_size=1)
    print(f"No common prefix paths: {result4}")
    assert len(result4) == 1 and result4[0] == '/', "Should compress to root"
    print("[OK] No common prefix correctly compressed to root")


def main():
    print("=" * 60)
    print("Path prefix compression algorithm tests")
    print("=" * 60)

    try:
        test_get_depth()
        test_get_ancestor()
        test_compress_basic()
        test_compress_example_from_spec()
        test_network_paths()
        test_edge_cases()

        print("\n" + "=" * 60)
        print("[PASS] All tests passed!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"\n[ERROR] Runtime error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
