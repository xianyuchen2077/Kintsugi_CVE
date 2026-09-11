# -*- coding: utf-8 -*-
"""
Python Stack Tracer Package

Function-level tracing plugin for Python application call stack analysis.
Automatically loaded via the sitecustomize mechanism, with configuration at /etc/tracer.ini
"""

from .tracer import enable_tracer, disable_tracer, auto_enable_from_ini

__version__ = "1.1.0"
__all__ = [
    'enable_tracer',
    'disable_tracer',
    'auto_enable_from_ini',
]
