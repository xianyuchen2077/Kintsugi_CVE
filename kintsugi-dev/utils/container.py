"""
Docker container operations
"""

import os
import time
import logging
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class ContainerOperator:

    def __init__(self, container: str, cve_id: str, language: str = "php"):
        self.container = container
        self.cve_id = cve_id
        self.language = language
        self.env_dir = Path(f"cves/{language}/{cve_id}/env")

    def file_exists(self, path: str) -> bool:
        result = subprocess.run(
            ['docker', 'exec', self.container, 'test', '-f', path],
            capture_output=True
        )
        return result.returncode == 0

    def read_file(self, path: str) -> str:
        result = subprocess.run(
            ['docker', 'exec', self.container, 'cat', path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise FileNotFoundError(f"Cannot read container file: {path}")
        return result.stdout

    def write_file(self, path: str, content: str):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            container_temp = f"/tmp/repair_{os.path.basename(path)}"
            subprocess.run(
                ['docker', 'cp', temp_path, f"{self.container}:{container_temp}"],
                check=True
            )
            subprocess.run(
                ['docker', 'exec', '-u', '0', self.container, 'chmod', '644', container_temp],
                check=True
            )
            subprocess.run(
                ['docker', 'exec', self.container, 'cp', container_temp, path],
                check=True
            )
            subprocess.run(
                ['docker', 'exec', self.container, 'rm', container_temp],
                capture_output=True
            )
        finally:
            os.unlink(temp_path)

    def backup_file(self, path: str) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{path}.backup_{timestamp}"

        result = subprocess.run(
            ['docker', 'exec', self.container, 'cp', path, backup_path],
            capture_output=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to backup file: {path}")

        logger.debug(f"Backed up: {path} -> {backup_path}")
        return backup_path

    def restore_file(self, original: str, backup: str):
        result = subprocess.run(
            ['docker', 'exec', self.container, 'cp', backup, original],
            capture_output=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to restore file: {original}")

        logger.debug(f"Restored: {backup} -> {original}")

    def apply_code(self, path: str, start_line: int, end_line: int, new_code: str, indent_level: int = 0):
        """
        Replace a code segment in a file.

        Args:
            path: File path inside the container
            start_line: Start line number (1-based, inclusive)
            end_line: End line number (1-based, inclusive)
            new_code: New code
            indent_level: Indentation level (number of spaces)
        """
        content = self.read_file(path)
        lines = content.split('\n')

        if indent_level > 0:
            indented_lines = []
            for line in new_code.split('\n'):
                if line.strip():
                    indented_lines.append(' ' * indent_level + line)
                else:
                    indented_lines.append(line)
            new_code = '\n'.join(indented_lines)

        new_lines = lines[:start_line - 1] + new_code.split('\n') + lines[end_line:]

        full_content = '\n'.join(new_lines)
        logger.info(f"[DEBUG] Full file content:\n{full_content}")

        self.write_file(path, full_content)
        logger.info(f"Applied repair: {path} (lines {start_line}-{end_line})")

    def restart(self, wait_seconds: int = 60):
        tracer_ini = None
        if self.language == "php":
            tracer_ini = self.env_dir / '99-tracer-filter.ini'
            if tracer_ini.exists():
                content = tracer_ini.read_text()
                tracer_ini.write_text(content.replace('tracer.enabled=1', 'tracer.enabled=0'))
                logger.debug("Disabled PHP tracer")
        elif self.language == "python":
            tracer_ini = self.env_dir / 'tracer.ini'
            if tracer_ini.exists():
                content = tracer_ini.read_text()
                if 'enabled' not in content:
                    content = content.replace('[tracer]', '[tracer]\nenabled = 0')
                else:
                    content = content.replace('enabled = 1', 'enabled = 0')
                tracer_ini.write_text(content)
                logger.debug("Disabled Python tracer")

        logger.info(f"Restarting container {self.container}...")
        subprocess.run(['docker', 'restart', self.container], check=True, timeout=60)

        while True:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={self.container}', '--format', '{{.Status}}'],
                capture_output=True, text=True, timeout=10
            )
            status = result.stdout.strip()

            if status.startswith('Up'):
                logger.info(f"Container started: {status}")
                break

            time.sleep(1)

        logger.info(f"Waiting {wait_seconds}s for container to stabilize...")
        time.sleep(wait_seconds)
        logger.info("Container ready")

        if tracer_ini and tracer_ini.exists():
            content = tracer_ini.read_text()
            if self.language == "php":
                tracer_ini.write_text(content.replace('tracer.enabled=0', 'tracer.enabled=1'))
            elif self.language == "python":
                tracer_ini.write_text(content.replace('enabled = 0', 'enabled = 1'))
            logger.debug("Restored tracer config")
