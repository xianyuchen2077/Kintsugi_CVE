#!/usr/bin/env python3
"""
Call Stack Reconstruction Script

This script processes CSV files containing syscall traces and reconstructs
Function call stacks along with associated system calls.
"""

import csv
import copy
import json
import logging
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import atexit

logger = logging.getLogger(__name__)

# Global write thread pool
_write_executor: Optional[ThreadPoolExecutor] = None
_pending_futures = []


def _get_write_executor() -> ThreadPoolExecutor:
    """Get or create write thread pool"""
    global _write_executor
    if _write_executor is None:
        _write_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="callstack_writer")
        atexit.register(_shutdown_write_executor)
    return _write_executor


def _shutdown_write_executor():
    """Shutdown write thread pool"""
    global _write_executor, _pending_futures
    if _write_executor is not None:
        for future in _pending_futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Write task failed: {e}", exc_info=True)
        _pending_futures.clear()
        _write_executor.shutdown(wait=True)
        _write_executor = None


def wait_for_pending_writes():
    """Wait for all pending write tasks to complete"""
    global _pending_futures
    for future in _pending_futures:
        try:
            future.result()
        except Exception as e:
            logger.error(f"Write task failed: {e}", exc_info=True)
    _pending_futures.clear()


# Syscall parameter mapping
SYSCALL_PARAMS = {
    # File operations
    "open": ["fd.name"],
    "openat": ["fd.name"],
    "read": ["fd.name",],
    "write": ["fd.name"],
    "writev": ["fd.name", "evt.buffer"],
    "close": ["fd.name"],
    "lseek": ["fd.name", "evt.arg.whence"],
    "fcntl": ["evt.arg.cmd"],

    # Directory operations
    "chdir": ["evt.arg.path"],
    "getcwd": ["evt.arg.path"],
    "getdents": ["fd.name"],

    # Network operations
    "connect": ["fd.name"],
    "sendto": ["fd.name"],
    "sendmmsg": ["fd.name"],
    "recvfrom": ["fd.name"],
    "getsockopt": ["evt.arg.level", "evt.arg.optname"],
    "setsockopt": ["evt.arg.level", "evt.arg.optname"],

    # Process execution
    "execve": ["evt.arg.filename", "proc.cmdline"],
    "execveat": ["evt.arg.filename", "proc.cmdline"],
}


@dataclass
class FunctionCall:
    """Represents a function call with its context"""
    name: str
    path: str
    line: int
    is_builtin: bool
    call_type: str
    args: Optional[str] = None

    def_path: Optional[str] = None
    def_start: Optional[int] = None
    def_end: Optional[int] = None

    syscalls: List[Any] = field(default_factory=list)
    full_syscalls: List[Any] = field(default_factory=list)

    def __hash__(self):
        return hash((self.name, self.path, self.line))

    def __eq__(self, other):
        if not isinstance(other, FunctionCall):
            return False
        return self.name == other.name and self.path == other.path and self.line == other.line

    def to_dict(self, include_syscalls=True) -> Dict:
        """Convert to dictionary with definition info"""
        result = {
            "name": self.name,
            "path": self.path,
            "line": self.line,
            "is_builtin": self.is_builtin,
            "call_type": self.call_type,
            "args": self.args,
            "def_path": self.def_path,
            "def_start": self.def_start,
            "def_end": self.def_end,
        }
        if include_syscalls:
            result["syscalls"] = self.syscalls
            result["full_syscalls"] = self.full_syscalls
        return result


@dataclass
class StackFrame:
    """Stack frame: extracted at runtime"""
    function: FunctionCall
    called_functions: List[FunctionCall] = field(default_factory=list)


@dataclass
class CallStackEntry:
    """Final output function call record"""
    function: FunctionCall
    call_stack: List[FunctionCall]
    called_functions: List[FunctionCall] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "function": self.function.to_dict(include_syscalls=True),
            "call_stack": [f.to_dict(include_syscalls=False) for f in self.call_stack],
            "called_functions": [f.to_dict(include_syscalls=False) for f in self.called_functions],
        }


class CallStackReconstructor:
    """Reconstructs PHP function call stacks from syscall traces"""

    # Regex for instrumentation data with function call arguments
    # FCALL format: [FCALL][path:line][U]FuncName[DEF:path:start-end](args)
    # RETURN format: [RETURN][path:line][U]FuncName[DEF:path:start-end]
    INSTRUMENTATION_PATTERN = re.compile(
        r'\[(FCALL|UCALL|ICALL|FCALL_BY_NAME|RETURN|RETURN_BY_REF)\]'
        r'\[([^:]+):(\d+)\]'
        r'(?:\[([IU])\])?'
        r'([^[\](]+?)'                              # Function name (no [ ] ( ))
        r'(?:\[DEF:([^:]+):(\d+)-(\d+)\])?'         # DEF info (optional, before args)
        r'(\(.*\))?'                                 # Arguments (optional)
        r'\.?$'
    )

    def __init__(self, whitelist_file: Optional[str] = None):
        self.stack: List[StackFrame] = []
        self.results: List[CallStackEntry] = []
        self.mismatched: List[FunctionCall] = []

        self.whitelist_paths: set = set()
        if whitelist_file:
            logger.info(f"Use a whitelist: {whitelist_file}")
            self.load_whitelist(whitelist_file)

    def load_whitelist(self, whitelist_file: str):
        """
        Load whitelist path prefixes from file

        Args:
            whitelist_file: Path to whitelist file (one path prefix per line)
        """
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    path = line.strip()
                    if path and not path.startswith('#'):
                        normalized = path.replace('\\', '/')
                        self.whitelist_paths.add(normalized)
        except Exception as e:
            logger.warning(f"Failed to load whitelist file {whitelist_file}: {e}")

    def is_in_whitelist(self, definition_path: Optional[str]) -> bool:
        """
        Check if a function definition path is in the whitelist

        Args:
            definition_path: Function definition path

        Returns:
            bool: True if no whitelist is set; otherwise checks for a match
        """
        if not self.whitelist_paths:
            return True
        if not definition_path:
            return True
        norm_path = definition_path.replace('\\', '/')
        for whitelist_path in self.whitelist_paths:
            if norm_path.startswith(whitelist_path):
                return True

        return False

    def _filter_called_functions(self, called_functions: List[FunctionCall]) -> List[FunctionCall]:
        if not self.whitelist_paths:
            return called_functions

        return [
            func for func in called_functions
            if func.is_builtin or self.is_in_whitelist(func.def_path)
        ]

    def _finalize_function(self, stack_index: int) -> None:
        """
        Finalize a stack frame (whether normal return or mismatched).
        Performs whitelist check, creates Entry or collapses syscalls,
        and merges full_syscalls to parent function.
        """
        frame = self.stack[stack_index]
        func = frame.function

        if self.is_in_whitelist(func.def_path):
            entry = CallStackEntry(
                function=func,
                call_stack=[f.function for f in self.stack[:stack_index + 1]],
                called_functions=self._filter_called_functions(frame.called_functions),
            )
            self.results.append(entry)
        else:
            # Collapse syscalls to parent function
            if stack_index > 0:
                self.stack[stack_index - 1].function.syscalls.extend(func.syscalls)

        # Merge full_syscalls to parent function
        if stack_index > 0:
            self.stack[stack_index - 1].function.full_syscalls.extend(func.full_syscalls)

    def parse_instrumentation(self, buffer: str) -> Optional[FunctionCall]:
        """Parse instrumentation data and return a FunctionCall instance"""
        match = self.INSTRUMENTATION_PATTERN.match(buffer)
        if not match:
            return None

        call_type = match.group(1)
        code_path = match.group(2)
        line_number = int(match.group(3))
        func_type_group = match.group(4)
        function_name = match.group(5).strip()
        def_path = match.group(6)
        def_start = int(match.group(7)) if match.group(7) else None
        def_end = int(match.group(8)) if match.group(8) else None
        arguments = match.group(9)

        arg_content = None
        if arguments:
            arg_content = arguments[1:-1] if arguments.startswith('(') and arguments.endswith(')') else arguments

        is_builtin = func_type_group == 'I' if func_type_group else False

        return FunctionCall(
            name=function_name,
            path=code_path,
            line=line_number,
            is_builtin=is_builtin,
            call_type=call_type,
            args=arg_content,
            def_path=def_path,
            def_start=def_start,
            def_end=def_end
        )

    def extract_syscall_params(self, syscall_type: str, row: Dict[str, str]) -> Dict:
        """Extract relevant parameters for a syscall"""
        syscall_data = {"type": syscall_type}

        params_to_extract = SYSCALL_PARAMS.get(syscall_type, [])

        for param in params_to_extract:
            value = row.get(param, "")
            if value:
                syscall_data[param] = value

        proc_name = row.get("proc.name", "")
        if proc_name:
            syscall_data["proc.name"] = proc_name

        return syscall_data

    def handle_function_call(self, func: FunctionCall):
        # Record in parent function
        if self.stack:
            self.stack[-1].function.full_syscalls.append({
                "type": "__FCALL__",
                "name": func.name,
                "path": func.path,
                "line": func.line,
                "is_builtin": func.is_builtin,
                "def_path": func.def_path,
                "def_start": func.def_start,
                "def_end": func.def_end
            })
            self.stack[-1].called_functions.append(func)

        # User functions need to be pushed onto the stack
        if not func.is_builtin:
            self.stack.append(StackFrame(function=func))

    def handle_function_return(self, returning_func: FunctionCall):
        """Handle function return event (RETURN) with definition info"""
        if returning_func.is_builtin:
            return

        # Find matching function in call stack
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].function.name == returning_func.name:
                stack_func = self.stack[i].function

                # Update function definition info
                if returning_func.def_path:
                    stack_func.def_path = returning_func.def_path
                    stack_func.def_start = returning_func.def_start
                    stack_func.def_end = returning_func.def_end

                # Finalize nested mismatched functions (innermost to outermost)
                for j in range(len(self.stack) - 1, i, -1):
                    self._finalize_function(j)
                    self.mismatched.append(self.stack[j].function)

                self._finalize_function(i)

                # Remove this function and everything above it from the stack
                self.stack = self.stack[:i]
                break

    def process_event(self, row: Dict[str, str]):
        """Process a single event from CSV"""
        evt_type = row.get("evt.type", "")
        fd_name = row.get("fd.name", "")
        evt_buffer = row.get("evt.buffer", "")

        # Check if this is an instrumentation event
        if evt_type == "write" and fd_name == "/dev/null" and evt_buffer:
            func_call = self.parse_instrumentation(evt_buffer)
            if not func_call:
                return

            if func_call.call_type in ["FCALL", "UCALL", "ICALL", "FCALL_BY_NAME"]:
                self.handle_function_call(func_call)
            elif func_call.call_type in ["RETURN", "RETURN_BY_REF"]:
                self.handle_function_return(func_call)

        # Regular syscall - append to current top-of-stack function
        elif evt_type and self.stack:
            syscall_data = self.extract_syscall_params(evt_type, row)
            self.stack[-1].function.syscalls.append(syscall_data)
            self.stack[-1].function.full_syscalls.append(syscall_data)

    def process_csv_file(self, filepath: Path) -> tuple[List[CallStackEntry], List[FunctionCall]]:
        """Process a single CSV file, return matched and mismatched results"""
        self.stack = []
        self.results = []
        self.mismatched = []

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    self.process_event(row)
                except Exception as e:
                    logger.error(f"Error processing row in {filepath}: {e}")
                    continue

        # Collect remaining functions on the stack (mismatched at end of file)
        for j in range(len(self.stack) - 1, -1, -1):
            self._finalize_function(j)
            self.mismatched.append(self.stack[j].function)

        return self.results, self.mismatched


def extract_http_payload(csv_filepath):
    """Extract HTTP request payload from CSV file"""
    try:
        with open(csv_filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                evt_arg_data = row.get('evt.arg.data', '')
                if evt_arg_data:
                    if evt_arg_data.startswith('GET ') or evt_arg_data.startswith('POST '):
                        return evt_arg_data
    except Exception as e:
        logger.error(f"Error extracting payload from {csv_filepath}: {e}")
    return None


def _write_jsonl_file(output_file: Path, results_data: list):
    """Write JSONL file in background"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for result_dict in results_data:
                f.write(json.dumps(result_dict, ensure_ascii=False) + '\n')
    except Exception as e:
        logger.error(f"Failed to write {output_file}: {e}")


def _write_function_files(function_groups: dict, functions_dir: Path, source_name: str):
    """Write per-function grouped files in background"""
    try:
        functions_dir.mkdir(exist_ok=True)
        for func_name, func_results in function_groups.items():
            safe_func_name = func_name.replace('\\', '_')
            safe_func_name = re.sub(r'[^\w\-_.]', '_', func_name)
            func_file = functions_dir / f"{source_name}_{safe_func_name}.json"
            with open(func_file, 'w', encoding='utf-8') as f:
                json.dump(func_results, f, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to write function files: {e}")


def save_results_by_function(results: List[CallStackEntry], output_dir: Path, source_file: str):
    """Save results grouped by function name to functions subdirectory"""
    functions_dir = output_dir / "functions"
    functions_dir.mkdir(exist_ok=True)

    source_name = Path(source_file).stem

    function_groups = defaultdict(list)
    for result in results:
        func_name = result.function.name
        function_groups[func_name].append(result.to_dict())

    for func_name, func_results in function_groups.items():
        safe_func_name = func_name.replace('\\', '_')
        safe_func_name = re.sub(r'[^\w\-_.]', '_', func_name)
        func_file = functions_dir / f"{source_name}_{safe_func_name}.json"

        with open(func_file, 'w', encoding='utf-8') as f:
            json.dump(func_results, f, ensure_ascii=False)


def process_callstack(cve, whitelist_file=None):
    """
    Process call stack reconstruction for a specific CVE

    Args:
        cve: CVEConfig object
        whitelist_file (str, optional): Whitelist file path

    Returns:
        bool: True if successful, False otherwise
    """
    input_dir = cve.data_dir / "unit"
    output_dir = cve.data_dir / "callstack"

    output_dir.mkdir(parents=True, exist_ok=True)

    reconstructor = CallStackReconstructor(whitelist_file=whitelist_file)

    csv_files = sorted(input_dir.glob("*.csv"))
    logger.info(f"Found {len(csv_files)} CSV files to process")

    if not csv_files:
        logger.error(f"No CSV files found in {input_dir}")
        return False

    for i, csv_file in enumerate(csv_files, 1):
        logger.info(f"[{i}/{len(csv_files)}] Processing {csv_file.name}...")

        http_payload = extract_http_payload(csv_file)

        parse_start = time.time()
        results, mismatched = reconstructor.process_csv_file(csv_file)
        parse_time = time.time() - parse_start

        if not results:
            logger.info(f"No matched function calls found (parse: {parse_time:.2f}s)")
            continue

        base_name = csv_file.stem
        output_file = output_dir / f"{base_name}.jsonl"

        # Serialize in main thread to avoid race conditions
        results_data = []
        function_groups = defaultdict(list)
        for result in results:
            result_dict = result.to_dict()
            result_dict["source_file"] = csv_file.name
            result_dict["payload"] = http_payload
            results_data.append(result_dict)
            function_groups[result.function.name].append(result_dict)

        # Async write JSONL file
        executor = _get_write_executor()
        future1 = executor.submit(_write_jsonl_file, output_file, results_data)
        _pending_futures.append(future1)

        # Async write per-function grouped files
        functions_dir = output_dir / "functions"
        source_name = csv_file.stem
        future2 = executor.submit(_write_function_files, dict(function_groups), functions_dir, source_name)
        _pending_futures.append(future2)

        logger.info(f"Found {len(results)} calls (parse: {parse_time:.2f}s, write: async)")

    logger.info("Waiting for background writes to complete...")
    wait_for_pending_writes()
    logger.info("All writes completed")

    return True
