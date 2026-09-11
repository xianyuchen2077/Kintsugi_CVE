"""
Whitelist computation and formatting
"""

import re
import logging
from pathlib import Path
from collections import defaultdict

from utils.path_compression import compress_paths_by_ancestors

logger = logging.getLogger(__name__)

PATH_SUPPORTED_SYSCALLS = {
    'open', 'openat', 'execve', 'execveat', 'unlink', 'unlinkat',
    'mkdir', 'mkdirat', 'rename', 'renameat', 'renameat2'
}

LANGUAGE_DEFAULT_PATHS = {
    'python': {
        'open': ['/usr/lib/python', '/usr/local/lib/python'],
        'openat': ['/usr/lib/python', '/usr/local/lib/python'],
    },
    'php': {
    }
}


def parse_filter_range(code: str, func_start: int, original_code: str) -> tuple[int | None, int | None]:
    """
    Parse the line number range of syscall_filter_begin/end in repair code.

    Matches the code between begin/end against the original code to compute
    line number ranges in the original source.

    Args:
        code: Repaired function code
        func_start: Function definition start line number (1-based)
        original_code: Original function code (required for precise line matching)

    Returns:
        (start_line, end_line): Line number range covered by the filter (in original code)
    """
    lines = code.split('\n')

    begin_offset = None
    end_offset = None

    for i, line in enumerate(lines):
        if 'syscall_filter_begin' in line or 'SyscallFilter' in line:
            begin_offset = i
        elif 'syscall_filter_end' in line:
            end_offset = i

    if begin_offset is None or end_offset is None:
        return None, None

    protected_lines = lines[begin_offset + 1:end_offset]
    protected_lines_normalized = [line.strip() for line in protected_lines if line.strip()]

    if not protected_lines_normalized:
        return None, None

    original_lines = original_code.split('\n')

    original_line_indices = {}
    for i, orig_line in enumerate(original_lines):
        orig_stripped = orig_line.strip()
        if orig_stripped:
            if orig_stripped not in original_line_indices:
                original_line_indices[orig_stripped] = []
            original_line_indices[orig_stripped].append(i)

    anchor_idx = None
    anchor_orig_idx = None

    for i, protected_line in enumerate(protected_lines_normalized):
        if protected_line in original_line_indices:
            matches = original_line_indices[protected_line]
            if len(matches) == 1:
                anchor_idx = i
                anchor_orig_idx = matches[0]
                logger.debug(f"parse_filter_range: anchor '{protected_line[:40]}' -> line {anchor_orig_idx}")
                break

    if anchor_idx is None:
        first_line = protected_lines_normalized[0]
        if first_line in original_line_indices:
            anchor_idx = 0
            anchor_orig_idx = original_line_indices[first_line][0]
            logger.debug(f"parse_filter_range: fallback to first line '{first_line[:40]}' -> line {anchor_orig_idx}")
        else:
            logger.debug("parse_filter_range: no matches found")
            return None, None

    first_match = anchor_orig_idx - anchor_idx
    last_match = anchor_orig_idx + (len(protected_lines_normalized) - anchor_idx - 1)

    start_line = func_start + first_match
    end_line = func_start + last_match
    logger.debug(f"parse_filter_range: range {start_line}-{end_line}")

    return start_line, end_line


def extract_syscalls_in_range(syscalls: list, start_line: int, end_line: int, target_path: str = None) -> list:
    """
    Extract syscalls within a line number range.

    Uses __FCALL__ markers to determine temporal boundaries.

    Args:
        syscalls: full_syscalls list (containing __FCALL__ markers)
        start_line: Start line number (1-based)
        end_line: End line number (1-based)
        target_path: Target file path, only match __FCALL__ entries in this file

    Returns:
        List of syscalls within the range
    """
    result = []
    prev_syscall = []
    in_range = False
    is_prev = True

    for item in syscalls:
        if item.get('type') == '__FCALL__':
            line = item.get('line', 0)
            if line < 0:
                continue
            if target_path and item.get('path') != target_path:
                continue
            if not in_range:
                if line < start_line:
                    prev_syscall = []
                elif start_line <= line <= end_line:
                    in_range = True
                    is_prev = False
            elif in_range and (line < start_line or line > end_line):
                in_range = False
        elif in_range:
            result.append(item)
        elif is_prev:
            prev_syscall.append(item)

    result = prev_syscall + result

    return result


def compute_whitelist(syscalls: list, language: str = None, min_files: int = 10) -> dict:
    """
    Compute whitelist from syscalls.

    Args:
        syscalls: List of syscalls
        language: Language type (python/php), for adding language-specific default paths
        min_files: Minimum files to trigger directory compression (default: 10)

    Returns:
        {syscall_type: [paths]} - empty list means allow any path
    """
    whitelist = defaultdict(set)
    path_collections = defaultdict(set)

    for sc in syscalls:
        sc_type = sc.get('type')
        if sc_type == 'write' and sc.get('fd.name') == '/dev/null':
            continue
        if not sc_type or sc_type == '__FCALL__':
            continue

        whitelist[sc_type] = set()

        if sc_type in PATH_SUPPORTED_SYSCALLS:
            for field in ['fd.name', 'evt.arg.path', 'evt.arg.filename']:
                if field in sc and sc[field]:
                    path_collections[sc_type].add(sc[field])

    result = {}
    for sc_type in whitelist:
        if sc_type in path_collections:
            paths = list(path_collections[sc_type])
            result[sc_type] = compress_paths(paths, min_files=min_files)
        else:
            result[sc_type] = []

    if language and language in LANGUAGE_DEFAULT_PATHS:
        for sc_type, default_paths in LANGUAGE_DEFAULT_PATHS[language].items():
            if sc_type in result:
                existing = set(result[sc_type])
                existing.update(default_paths)
                result[sc_type] = compress_paths(list(existing), min_files=min_files)
            else:
                result[sc_type] = list(default_paths)

    return result


def compress_paths(paths: list, max_rules: int = 32, min_files: int = 10) -> list:
    """
    Compress a list of paths using ancestor directory algorithm.

    Args:
        paths: List of paths
        max_rules: Maximum number of rules (default: 32)
        min_files: Minimum files to trigger directory compression (default: 10)
    """
    if not paths:
        return []

    if len(paths) == 1:
        return list(paths)

    return compress_paths_by_ancestors(set(paths), target_size=max_rules, min_files=min_files)


def get_placeholder_indent(code: str, placeholder: str = '$WHITELIST$') -> str:
    """
    Get the indentation of the line containing the placeholder.

    Args:
        code: Code containing the placeholder
        placeholder: Placeholder string

    Returns:
        Indentation string (leading whitespace)
    """
    for line in code.split('\n'):
        if placeholder in line:
            return line[:len(line) - len(line.lstrip())]
    return ""


def format_whitelist(whitelist: dict, language: str = "php", php53_syntax: bool = False, indent: str = "") -> str:
    """
    Format whitelist as code.

    Args:
        whitelist: {syscall_type: [paths]}
        language: "php" or "python"
        php53_syntax: Whether to use PHP 5.3 compatible syntax
        indent: Indentation string, applied to line 2 onwards

    Returns:
        Formatted code string
    """
    if language == "python":
        code = _format_whitelist_python(whitelist)
    else:
        code = _format_whitelist_php(whitelist, php53_syntax)

    if indent:
        lines = code.split('\n')
        lines = [lines[0]] + [indent + line for line in lines[1:]]
        code = '\n'.join(lines)

    return code


def _format_whitelist_php(whitelist: dict, php53_syntax: bool = False) -> str:
    if not whitelist:
        return "[]" if not php53_syntax else "array()"

    lines = []
    open_bracket = "array(" if php53_syntax else "["
    close_bracket = ")" if php53_syntax else "]"

    lines.append(open_bracket)

    for sc_type, paths in sorted(whitelist.items()):
        if paths:
            paths_str = ", ".join(f"'{p}'" for p in paths)
            if php53_syntax:
                lines.append(f"    '{sc_type}' => array({paths_str}),")
            else:
                lines.append(f"    '{sc_type}' => [{paths_str}],")
        else:
            if php53_syntax:
                lines.append(f"    '{sc_type}' => array(),")
            else:
                lines.append(f"    '{sc_type}' => [],")

    lines.append(close_bracket)

    return "\n".join(lines)


def _format_whitelist_python(whitelist: dict) -> str:
    if not whitelist:
        return "{}"

    lines = ["{"]

    for sc_type, paths in sorted(whitelist.items()):
        if paths:
            paths_str = ", ".join(f"'{p}'" for p in paths)
            lines.append(f"    '{sc_type}': [{paths_str}],")
        else:
            lines.append(f"    '{sc_type}': [],")

    lines.append("}")

    return "\n".join(lines)


def compute_syscall_diff(abnormal_syscalls: list, normal_samples: list) -> dict:
    """
    Compute syscall diff between abnormal and normal requests.

    Args:
        abnormal_syscalls: Syscalls from abnormal request
        normal_samples: List of normal samples

    Returns:
        {
            'type_diff': set,       # Syscall types present in abnormal but not normal
            'path_diff': dict       # Path diffs categorized by type
        }
    """
    abnormal_types = set()
    abnormal_paths = defaultdict(set)
    path_fields = ['fd.name', 'evt.arg.path', 'evt.arg.filename', 'proc.cmdline']

    for sc in abnormal_syscalls:
        sc_type = sc.get('type')
        if sc_type and sc_type != '__FCALL__':
            abnormal_types.add(sc_type)
            for field in path_fields:
                if field in sc and sc[field]:
                    abnormal_paths[sc_type].add(sc[field])

    normal_types = set()
    normal_paths = defaultdict(set)

    for sample in normal_samples:
        sample_func = sample.get('function', {})
        syscalls = sample_func.get('full_syscalls', sample_func.get('syscalls', []))
        for sc in syscalls:
            sc_type = sc.get('type')
            if sc_type and sc_type != '__FCALL__':
                normal_types.add(sc_type)
                for field in path_fields:
                    if field in sc and sc[field]:
                        normal_paths[sc_type].add(sc[field])

    type_diff = abnormal_types - normal_types

    path_diff = {}
    for sc_type in abnormal_types:
        diff = abnormal_paths[sc_type] - normal_paths.get(sc_type, set())
        if diff:
            path_diff[sc_type] = diff

    return {
        'type_diff': type_diff,
        'path_diff': path_diff
    }


def format_syscall_diff(diff: dict) -> str:
    result = ""

    result += "[Anomalous: extra syscall types]\n"
    if diff['type_diff']:
        result += f"{', '.join(sorted(diff['type_diff']))}\n"
    else:
        result += "(none)\n"

    result += "\n[Anomalous: extra path accesses]\n"
    if diff['path_diff']:
        for sc_type, paths in sorted(diff['path_diff'].items()):
            compressed = compress_paths(list(paths))
            result += f"- {sc_type}: {', '.join(compressed)}\n"
    else:
        result += "(none)\n"

    return result
