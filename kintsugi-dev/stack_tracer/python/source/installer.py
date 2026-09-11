#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sitecustomize installer

Auto-configure Python environment to enable tracer:
1. Detect current Python interpreter's site-packages path
2. Copy tracer.py to site-packages
3. Create/modify sitecustomize.py to auto-import tracer

Compatible with Python 3.5+
"""

import sys
import os
import site
import shutil


def get_site_packages_dir():
    """Get current Python's site-packages directory"""
    # Prefer site.getsitepackages() (System Python)
    if hasattr(site, 'getsitepackages'):
        dirs = site.getsitepackages()
        for d in dirs:
            if os.path.isdir(d):
                return d

    # virtualenv doesn't have getsitepackages, use sysconfig
    import sysconfig
    return sysconfig.get_paths()['purelib']


def get_sitecustomize_path():
    """Get the path of sitecustomize.py that Python actually loads

    Python searches sitecustomize.py in sys.path order.
    If one already exists, we need to modify that file instead of creating a new one.
    """
    # 1. Check if sitecustomize is already loaded
    try:
        import sitecustomize
        if hasattr(sitecustomize, '__file__') and sitecustomize.__file__:
            existing_path = sitecustomize.__file__
            # Handle .pyc files
            if existing_path.endswith('.pyc'):
                existing_path = existing_path[:-1]
            if os.path.exists(existing_path):
                return existing_path
    except ImportError:
        pass

    # 2. No existing sitecustomize, create in site-packages
    return os.path.join(get_site_packages_dir(), 'sitecustomize.py')


def main():
    # Get site-packages directory
    site_dir = get_site_packages_dir()
    print("[Installer] Using site-packages: {}".format(site_dir))

    # tracer.py is in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tracer_source = os.path.join(script_dir, 'tracer.py')

    if not os.path.exists(tracer_source):
        sys.stderr.write("[Installer] Error: tracer.py not found: {}\n".format(tracer_source))
        return 1

    # 1. Copy tracer.py to site-packages
    dest = os.path.join(site_dir, 'tracer.py')
    shutil.copy2(tracer_source, dest)
    print("[Installer] Installed tracer to: {}".format(dest))

    # 2. Setup sitecustomize.py
    sitecustomize_path = get_sitecustomize_path()
    print("[Installer] Using sitecustomize: {}".format(sitecustomize_path))

    import_code = '''
# Python Tracer auto-load
try:
    import tracer
except ImportError:
    pass
'''

    if os.path.exists(sitecustomize_path):
        with open(sitecustomize_path, 'r') as f:
            content = f.read()
        if 'import tracer' not in content:
            with open(sitecustomize_path, 'a') as f:
                f.write(import_code)
            print("[Installer] Appended to: {}".format(sitecustomize_path))
        else:
            print("[Installer] Already configured: {}".format(sitecustomize_path))
    else:
        with open(sitecustomize_path, 'w') as f:
            f.write(import_code)
        print("[Installer] Created: {}".format(sitecustomize_path))

    print("[Installer] Complete!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
