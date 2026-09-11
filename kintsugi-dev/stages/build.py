"""
Stage 1: Build and install plugins

- PHP: Build .so extensions (stack_tracer, syscall_filter)
- Python: Deploy and inject modules
- General: Install net_filter network filtering plugin
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def run_sudo(args, cwd=None):
    """Run sudo in both terminal and non-interactive Bridge contexts."""
    password = os.getenv("KINTSUGI_SUDO_PASSWORD")
    if password:
        return subprocess.run(
            ["sudo", "-S", "-p", "", *args],
            cwd=cwd,
            check=True,
            input=f"{password}\n",
            text=True,
        )
    if sys.stdin.isatty():
        return subprocess.run(["sudo", *args], cwd=cwd, check=True)
    logger.error("sudo requires a password, but no TTY is available. Provide it from the Local Bridge UI.")
    return subprocess.run(["sudo", "-n", *args], cwd=cwd, check=True)


def build_plugins(cve):
    """Build and install plugins"""
    project_root = Path(__file__).parent.parent
    env_dir = cve.env_dir

    if cve.language == "php":
        logger.info("PHP project: building .so extensions")

        # Stop container (need to re-establish mount mappings)
        subprocess.run(["docker", "compose", "down", "-v"], cwd=env_dir, check=True)

        # Clean old .so files and create empty ones (required for Docker mounts)
        for so_file in ["tracer.so", "syscall_filter.so"]:
            so_path = env_dir / so_file
            if so_path.exists():
                if so_path.is_dir():
                    shutil.rmtree(so_path)
                else:
                    so_path.unlink()
            so_path.touch()

        logger.info("Building stack_tracer...")
        run_sudo(
            ["bash", f"stack_tracer/php{cve.version}/source/build.sh", str(env_dir), cve.container],
            cwd=project_root,
        )

        logger.info("Building syscall_filter...")
        run_sudo(
            ["bash", f"syscall_filter/php{cve.version}/source/build.sh", str(env_dir), cve.container],
            cwd=project_root,
        )

        for so_file in ["tracer.so", "syscall_filter.so"]:
            so_path = env_dir / so_file
            logger.info(f"  {so_file}: {so_path.stat().st_size} bytes")

        subprocess.run(["docker", "compose", "up", "-d"], cwd=env_dir, check=True)

        logger.info("Installing net_filter...")
        run_sudo(["bash", "net_filter/setup.sh", cve.container], cwd=project_root)
        subprocess.run(
            ["bash", "net_filter/php/build.sh", cve.container],
            cwd=project_root, check=True,
        )

    elif cve.language == "python":
        logger.info("Python project: deploying modules (sitecustomize auto-load)")

        subprocess.run(["docker", "compose", "up", "-d"], cwd=env_dir, check=True)

        # Deploy stack_tracer (auto-enabled via sitecustomize, config mapped via docker-compose volumes)
        logger.info("Deploying stack_tracer...")
        cmd = ["bash", "stack_tracer/python/source/build.sh", cve.container]
        if cve.python_path:
            cmd.append(cve.python_path)
        subprocess.run(cmd, cwd=project_root, check=True)

        logger.info("Deploying syscall_filter...")
        subprocess.run(
            ["bash", "syscall_filter/python/source/build.sh", cve.container],
            cwd=project_root, check=True,
        )

        # Restart container for sitecustomize to take effect (restart preserves installed files)
        logger.info("Restarting container...")
        subprocess.run(["docker", "restart", cve.container], check=True)

        logger.info("Installing net_filter...")
        run_sudo(["bash", "net_filter/setup.sh", cve.container], cwd=project_root)
        subprocess.run(
            ["bash", "net_filter/python/build.sh", cve.container],
            cwd=project_root, check=True,
        )

    else:
        raise ValueError(f"Unsupported language: {cve.language}")

    logger.info("Plugin installation complete")

    if cve.manual_install:
        logger.warning(f"{cve.cve_id} requires manual installation, please complete before continuing")
        logger.warning("Press Enter to continue...")
        input()
