# -*- coding: utf-8 -*-
"""
Python Function-Level Stack Tracer

Inspired by the PHP linetracer design, this uses sys.setprofile() to trace 
Python function calls and writes results to /dev/null via system calls 
to be captured by tools like sysdig.
"""

import sys
import os
import inspect
import threading
import time
import ctypes
from datetime import datetime

# ============================================================================
# System Call Wrappers (Mimicking PHP syscall implementation)
# ============================================================================

# Load libc
libc = ctypes.CDLL(None)
SYS_write = 1  # write syscall number for x86_64 Linux

def raw_syscall_write(fd, data_bytes):
    """Directly invoke the write syscall, bypassing Python's abstractions"""
    return libc.syscall(SYS_write, fd, data_bytes, len(data_bytes))

# ============================================================================
# Global Configuration
# ============================================================================

class TracerConfig:
    def __init__(self):
        self.enabled = False
        self.capture_args = False
        self.target_paths = []
        self.devnull_fd = -1
        self.original_trace_function = None
        self.path_cache = {}  # filepath → bool (is within target path)
        self.end_line_cache = {}  # (filepath, start_line) → end_line

# Global configuration instance
CONFIG = TracerConfig()

# ============================================================================
# Core Tracing Logic
# ============================================================================

def _is_in_target_path(filepath):
    """Check if file is within target paths (with caching)"""
    if filepath in CONFIG.path_cache:
        return CONFIG.path_cache[filepath]
    result = any(filepath.startswith(path) for path in CONFIG.target_paths)
    CONFIG.path_cache[filepath] = result
    return result


def _profiler(frame, event, arg):
    """Core tracing function registered via sys.setprofile()"""
    if not CONFIG.enabled:
        return

    # --- 1. Event Filtering ---
    # setprofile events: call, return, c_call, c_return, c_exception
    # Only process Python function calls
    if event not in ('call', 'return'):
        return

    # --- 2. Filter <module> and tracer internal functions ---
    func_name = frame.f_code.co_name
    if '<module>' in func_name:
        return
    if func_name in ('patched_threading_init', 'run_with_trace', 'reinit_in_child'):
        return
    # Filter class definition events (calls triggered by 'class Foo:' statements)
    if func_name in frame.f_globals and isinstance(frame.f_globals.get(func_name), type):
        return

    # --- 3. File Path Filtering (using cache) ---
    # Use caller's file path to determine tracing (consistent with PHP tracer behavior)
    # This ensures calls are recorded if the call site is in target, even if callee is in stdlib
    try:
        if frame.f_back:
            caller_filepath = frame.f_back.f_code.co_filename
        else:
            caller_filepath = frame.f_code.co_filename

        callee_filepath = frame.f_code.co_filename
        caller_in_target = _is_in_target_path(caller_filepath)
        callee_in_target = _is_in_target_path(callee_filepath)

        if not caller_in_target and not callee_in_target:
            return

        if not caller_filepath.endswith('.py'):
            return
    except: # pragma: no cover
        return

    # --- 4. Information Extraction ---
    # Use caller's frame info (call site), set to -1 if no caller
    if frame.f_back:
        caller_lineno = frame.f_back.f_lineno
        caller_filepath = frame.f_back.f_code.co_filename
    else:
        caller_lineno = -1
        caller_filepath = ""
    function_name = frame.f_code.co_name
    module_name = frame.f_globals.get('__name__', '?')

    # Try to get class name (use type() to avoid triggering __getattribute__)
    class_name = None
    try:
        if 'self' in frame.f_locals:
            obj = frame.f_locals['self']
            class_name = type(obj).__name__
        elif 'cls' in frame.f_locals:
            obj = frame.f_locals['cls']
            # cls might be a class object or a string (e.g., in enum.py)
            if isinstance(obj, type):
                class_name = obj.__name__
    except:
        pass  # Ignore any errors during class name retrieval

    # Concatenate full function name
    full_name = "{}.{}".format(module_name, function_name)
    if class_name:
        full_name = "{}.{}.{}".format(module_name, class_name, function_name)

    # --- 5. Get Function Definition Info (using inspect.getsourcelines for end line, with cache) ---
    def_info = ""
    try:
        filepath = frame.f_code.co_filename
        start_line = frame.f_code.co_firstlineno
        cache_key = (filepath, start_line)

        if cache_key in CONFIG.end_line_cache:
            end_line = CONFIG.end_line_cache[cache_key]
        else:
            try:
                func_obj = None
                # Case 1: Instance method self.method()
                if class_name and 'self' in frame.f_locals:
                    func_obj = getattr(frame.f_locals['self'], function_name, None)
                # Case 2: Class method cls.method()
                elif class_name and 'cls' in frame.f_locals:
                    func_obj = getattr(frame.f_locals['cls'], function_name, None)
                # Case 3: Global function in current module
                elif function_name in frame.f_globals:
                    func_obj = frame.f_globals.get(function_name)
                # Case 4: Module-level function (e.g., subprocess.getoutput)
                else:
                    module_obj = sys.modules.get(module_name)
                    if module_obj:
                        func_obj = getattr(module_obj, function_name, None)
            
                if func_obj and hasattr(func_obj, '__code__'):
                    source_lines, _ = inspect.getsourcelines(func_obj)
                    while source_lines and source_lines[-1].strip() == '':
                        source_lines.pop()
                    end_line = start_line + len(source_lines) - 1
                    CONFIG.end_line_cache[cache_key] = end_line
                else:
                    end_line = start_line
                
            except:
                end_line = start_line

        def_info = "[DEF:{}:{}-{}]".format(filepath, start_line, end_line)
    except:
        pass  # def_info remains empty if retrieval fails

    # --- 6. Format Output ---
    output = ""
    if event == 'call':
        args_str = "()"
        if CONFIG.capture_args:
            try:
                args_info = inspect.getargvalues(frame)
                args_list = ["{}={}".format(k, _format_arg(v)) for k, v in args_info.locals.items()]
                args_str = "({})".format(', '.join(args_list))
            except Exception as e:
                print(e)
                args_str = "()"
        # Format: [FCALL][caller_file:line][U]func_name[DEF:...](args)
        output = "[FCALL][{}:{}][U]{}{}{}\n".format(caller_filepath, caller_lineno, full_name, def_info, args_str)

    elif event == 'return':
        output = "[RETURN][{}:{}][U]{}{}\n".format(caller_filepath, caller_lineno, full_name, def_info)

    # --- 7. Write to /dev/null (using syscall, mimicking PHP implementation) ---
    if output and CONFIG.devnull_fd != -1:
        try:
            data_bytes = output.encode('utf-8', 'ignore')
            raw_syscall_write(CONFIG.devnull_fd, data_bytes)
        except:
            pass  # Ignore write errors

def _format_arg(value, max_len=128):
    """Safely format argument values"""
    try:
        s = repr(value)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s
    except:
        return "<unrepresentable>"

# ============================================================================
# Public API
# ============================================================================

def enable_tracer(target_paths, output_file=None):
    """Enable function tracing

    Args:
        target_paths: List of paths to trace
        output_file: Output file path (uses /dev/null if None)
    """
    if CONFIG.enabled:
        return

    print("[Tracer] Enabling tracer for paths: {}".format(target_paths))

    # Use provided paths directly (supports absolute and relative)
    CONFIG.target_paths = list(target_paths)
    print("[Tracer] Configured target paths: {}".format(CONFIG.target_paths), file=sys.stderr)

    try:
        # Use specified file if provided; otherwise use /dev/null
        if output_file:
            CONFIG.devnull_fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            print("[Tracer] Writing to file: {}".format(output_file), file=sys.stderr)
        else:
            CONFIG.devnull_fd = os.open('/dev/null', os.O_WRONLY)
            print("[Tracer] Writing to /dev/null", file=sys.stderr)
    except OSError as e:
        print("[Tracer] Warning: Could not open output file: {}. Using stderr as fallback.".format(e), file=sys.stderr)
        CONFIG.devnull_fd = sys.stderr.fileno()

    CONFIG.original_trace_function = sys.getprofile()
    CONFIG.enabled = True
    sys.setprofile(_profiler)

    # Automatically enable tracer for all new threads
    original_threading_init = threading.Thread.__init__

    def patched_threading_init(self, *args, **kwargs):
        original_threading_init(self, *args, **kwargs)
        original_run = self.run

        def run_with_trace(*args, **kwargs):
            # Enable tracer in the new thread
            # Accept arbitrary args for compatibility with other library patches (e.g., sentry_sdk)
            sys.setprofile(_profiler)
            try:
                original_run()
            finally:
                sys.setprofile(None)

        self.run = run_with_trace

    threading.Thread.__init__ = patched_threading_init
    print("[Tracer] Multi-threading support enabled", file=sys.stderr)

    # Enable tracing for forked child processes
    try:
        def reinit_in_child():
            """Re-initialize tracer in forked child process"""
            if CONFIG.enabled:
                try:
                    # Re-open output file descriptor
                    if output_file:
                        CONFIG.devnull_fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
                    else:
                        CONFIG.devnull_fd = os.open('/dev/null', os.O_WRONLY)
                except:
                    CONFIG.devnull_fd = sys.stderr.fileno()
                sys.setprofile(_profiler)
                print("[Tracer] Reinit in child process (pid={})".format(os.getpid()), file=sys.stderr)

        if hasattr(os, 'register_at_fork'):
            os.register_at_fork(after_in_child=reinit_in_child)
            print("[Tracer] Fork support enabled", file=sys.stderr)
    except Exception as e:
        print("[Tracer] Warning: Fork support failed: {}".format(e), file=sys.stderr)

def disable_tracer():
    """Disable function tracing"""
    if not CONFIG.enabled:
        return

    print("[Tracer] Disabling tracer.")

    CONFIG.enabled = False
    sys.setprofile(CONFIG.original_trace_function)

    if CONFIG.devnull_fd != -1 and CONFIG.devnull_fd != sys.stderr.fileno():
        os.close(CONFIG.devnull_fd)

    CONFIG.devnull_fd = -1
    CONFIG.target_paths = []
    CONFIG.path_cache.clear()  # Clear path cache

# ============================================================================
# Auto-enable (via config file)
# ============================================================================

def auto_enable_from_ini(config_path='/etc/tracer.ini'):
    """Read configuration from file and auto-enable tracing

    Args:
        config_path: Path to config file, defaults to /etc/tracer.ini

    Config file format:
        [tracer]
        enabled = 1
        target_paths = /app,/opt/myapp
    """
    import configparser

    if not os.path.exists(config_path):
        return

    try:
        config = configparser.ConfigParser()
        config.read(config_path)

        # Check enabled option (defaults to 1)
        enabled = config.get('tracer', 'enabled', fallback='1')
        if enabled.lower() in ('0', 'false', 'no', 'off'):
            return

        target_paths = config.get('tracer', 'target_paths', fallback='').split(',')
        target_paths = [p.strip() for p in target_paths if p.strip()]

        if not target_paths:
            return

        enable_tracer(target_paths)
    except Exception as e:
        print("[Tracer] Error reading config: {}".format(e), file=sys.stderr)

# Automatically check config file on module load
auto_enable_from_ini()
