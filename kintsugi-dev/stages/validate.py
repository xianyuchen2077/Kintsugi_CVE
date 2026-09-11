"""
Stage 10: Repair Validation

Apply repair code, restart the container, and verify the repair effectiveness.
"""

import time
import json
import logging
import importlib.util
import subprocess
import io
import os
import sys
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from config import CVEConfig
from utils.container import ContainerOperator

logger = logging.getLogger(__name__)

NET_FILTER_DIR = Path(__file__).parent.parent / "net_filter"
NET_FILTER_SETUP_SCRIPT = NET_FILTER_DIR / "setup.sh"


def sudo_command(args):
    password = os.getenv("KINTSUGI_SUDO_PASSWORD")
    if password:
        return ["sudo", "-S", "-p", "", *args], f"{password}\n"
    if sys.stdin.isatty():
        return ["sudo", *args], None
    return ["sudo", "-n", *args], None


class RepairValidator:
    """Repair validator"""

    def __init__(self, cve: CVEConfig):
        self.cve = cve

        self.input_dir = cve.data_dir / "repair_with_whitelist"
        self.output_dir = cve.data_dir / "repair_validated"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.container_ops = ContainerOperator(cve.container, cve.cve_id, cve.language)
        self.validate_module = self._load_validate_module()

    def _load_validate_module(self):
        """Load the CVE-specific validation module"""
        validate_path = Path(f"cves/{self.cve.language}/{self.cve.cve_id}/validate.py")

        if not validate_path.exists():
            raise FileNotFoundError(
                f"Validation script does not exist: {validate_path}\n"
                f"Please create validate.py containing validate_normal_request() and validate_malicious_request() functions"
            )

        spec = importlib.util.spec_from_file_location(f"{self.cve.cve_id}_validate", validate_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for func_name in ['validate_normal_request', 'validate_malicious_request']:
            if not hasattr(module, func_name):
                raise AttributeError(f"Missing required function: {func_name}")

        return module

    def run(self, skip_normal: bool = False, skip_malicious: bool = False, wait_time: int = 60, keep_repaired: bool = False):
        """
        Main workflow

        Args:
            skip_normal: Skip normal request validation
            skip_malicious: Skip malicious request validation
            wait_time: Wait time in seconds after container restart
            keep_repaired: Keep repaired state after validation, do not restore source files
        """
        self.wait_time = wait_time
        json_files = list(self.input_dir.glob("*_repairs.json"))

        if not json_files:
            logger.warning(f"No whitelisted repair files found: {self.input_dir}")
            return

        logger.info(f"Found {len(json_files)} repair file(s)")

        for json_file in json_files:
            logger.info(f"Processing: {json_file.name}")
            self._process_file(json_file, skip_normal, skip_malicious, keep_repaired)

    def _process_file(self, json_file: Path, skip_normal: bool, skip_malicious: bool, keep_repaired: bool = False):
        """Process a single repair file"""
        with open(json_file, 'r', encoding='utf-8') as f:
            repairs = json.load(f)

        valid_repairs = [r for r in repairs if r.get('success') and r.get('repair_code')]

        if not valid_repairs:
            logger.info(f"  No valid repairs")
            return

        logger.info(f"  Validating {len(valid_repairs)} repair(s)")

        backups = []
        try:
            for repair in valid_repairs:
                backup = self._backup_file(repair)
                if backup:
                    backups.append(backup)

            applied = []
            for repair in valid_repairs:
                if self._apply_repair(repair):
                    applied.append(repair)

            if not applied:
                logger.error(f"  All repairs failed to apply")
                return

            logger.info(f"  Applied {len(applied)} repair(s)")

            network_repairs = [r for r in applied if r.get('repair_method') == 'network']
            uses_network_filter = len(network_repairs) > 0

            network_whitelist_ips = set()
            for r in network_repairs:
                ips = r.get('network_whitelist', [])
                network_whitelist_ips.update(ips)

            logger.info(f"  Restarting container...")
            self.container_ops.restart(wait_seconds=self.wait_time)

            if uses_network_filter:
                whitelist_ips = sorted(network_whitelist_ips)
                if whitelist_ips:
                    logger.info(f"  Setting up net_filter (network repair method, whitelist: {', '.join(whitelist_ips)})...")
                else:
                    logger.info(f"  Setting up net_filter (network repair method, no whitelist)...")
                if not self._setup_net_filter(whitelist_ips=whitelist_ips):
                    logger.error(f"  net_filter setup failed")
                    result = {
                        'normal_ok': False,
                        'malicious_blocked': False,
                        'success': False,
                        'error': 'net_filter setup failed',
                    }
                    for repair in repairs:
                        repair['validation_result'] = result
                    return
                time.sleep(10)

            result = self._validate(skip_normal, skip_malicious)

            for repair in repairs:
                repair['validation_result'] = result

        finally:
            if keep_repaired:
                logger.info(f"  Keeping repaired state (not restoring source files)")
            else:
                for backup in backups:
                    self._restore_file(backup)

        output_file = self.output_dir / json_file.name
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'repairs': repairs,
                'validation_result': result,
            }, f, ensure_ascii=False, indent=2)

        if result['success']:
            logger.info(f"  ✓ Validation passed")
        else:
            logger.warning(f"  ✗ Validation failed")
            if not result.get('normal_ok'):
                logger.warning(f"    - Normal request did not pass")
            if not result.get('malicious_blocked'):
                logger.warning(f"    - Malicious request was not blocked")

        logger.info(f"  Saved to: {output_file}")

    def _backup_file(self, repair: dict) -> dict | None:
        """Back up a file"""
        file_path = repair.get('function_path')
        if not file_path:
            return None

        if not self.container_ops.file_exists(file_path):
            logger.warning(f"  File does not exist: {file_path}")
            return None

        try:
            backup_path = self.container_ops.backup_file(file_path)
            return {
                'original': file_path,
                'backup': backup_path,
            }
        except Exception as e:
            logger.error(f"  Backup failed {file_path}: {e}")
            return None

    def _restore_file(self, backup: dict):
        """Restore a file"""
        try:
            logger.info(f"Restoring file: {backup['original']}, {backup['backup']}")
            self.container_ops.restore_file(backup['original'], backup['backup'])
        except Exception as e:
            logger.error(f"  Restore failed {backup['original']}: {e}")

    def _apply_repair(self, repair: dict) -> bool:
        """Apply a repair"""
        file_path = repair.get('function_path')
        start_line = repair.get('start_line')
        end_line = repair.get('end_line')
        code = repair.get('repair_code')
        indent_level = repair.get('indent_level', 0)

        if not all([file_path, start_line, end_line, code]):
            logger.warning(f"  Incomplete repair data: {repair.get('function_name')}")
            return False

        try:
            self.container_ops.apply_code(file_path, start_line, end_line, code, indent_level)
            return True
        except Exception as e:
            logger.error(f"  Failed to apply repair {repair.get('function_name')}: {e}")
            return False

    def _setup_net_filter(self, whitelist_ips: list = None) -> bool:
        """
        Set up the net_filter environment

        1. Run setup.sh to configure host cgroup and container iptables
        2. Deploy the net_filter module to the container

        Args:
            whitelist_ips: Optional list of internal whitelist IPs that will not be blocked

        Returns:
            True if setup succeeded
        """
        container_name = self.cve.container

        if not NET_FILTER_SETUP_SCRIPT.exists():
            logger.error(f"  net_filter setup.sh does not exist: {NET_FILTER_SETUP_SCRIPT}")
            return False

        sudo_args = ['bash', str(NET_FILTER_SETUP_SCRIPT), container_name]
        if whitelist_ips:
            sudo_args.append(','.join(whitelist_ips))
        cmd, sudo_input = sudo_command(sudo_args)

        logger.info(f"    Running setup.sh {container_name}...")
        try:
            result = subprocess.run(
                cmd,
                input=sudo_input, capture_output=True, text=True, timeout=60
            )

            if result.returncode != 0:
                logger.error(f"    setup.sh failed: {result.stderr}")
                return False

            logger.info(f"    setup.sh completed")

        except subprocess.TimeoutExpired:
            logger.error(f"    setup.sh timed out")
            return False
        except Exception as e:
            logger.error(f"    setup.sh error: {e}")
            return False

        build_script = NET_FILTER_DIR / self.cve.language / "build.sh"
        if not build_script.exists():
            logger.error(f"  net_filter build.sh does not exist: {build_script}")
            return False

        logger.info(f"    Deploying net_filter module...")
        try:
            result = subprocess.run(
                ['bash', str(build_script), container_name],
                capture_output=True, text=True, timeout=120
            )

            if result.returncode != 0:
                logger.error(f"    build.sh failed: {result.stderr}")
                return False

            logger.info(f"    net_filter module deployed")

        except subprocess.TimeoutExpired:
            logger.error(f"    build.sh timed out")
            return False
        except Exception as e:
            logger.error(f"    build.sh error: {e}")
            return False

        return True

    def _validate(self, skip_normal: bool, skip_malicious: bool) -> dict:
        """Execute validation"""
        result = {
            'normal_ok': True,
            'malicious_blocked': True,
            'success': True,
        }

        if skip_normal:
            logger.info(f"  [Skip] Normal request validation")
        else:
            logger.info(f"  Validating normal request...")
            try:
                result['normal_ok'] = self._run_validate_func(
                    "normal", self.validate_module.validate_normal_request
                )
            except Exception as e:
                logger.error(f"  Normal request validation error: {e}")
                result['normal_ok'] = False

        if skip_malicious:
            logger.info(f"  [Skip] Malicious request validation")
        else:
            logger.info(f"  Validating malicious request...")
            try:
                result['malicious_blocked'] = self._run_validate_func(
                    "malicious", self.validate_module.validate_malicious_request
                )
            except Exception as e:
                logger.error(f"  Malicious request validation error: {e}")
                result['malicious_blocked'] = False

        result['success'] = result['normal_ok'] and result['malicious_blocked']

        logger.info(f"  Normal request: {'✓' if result['normal_ok'] else '✗'}")
        logger.info(f"  Malicious blocked: {'✓' if result['malicious_blocked'] else '✗'}")

        return result

    def _run_validate_func(self, label: str, func):
        """Run a CVE validation function and forward its prints to the logger."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            ok = func()

        for line in stdout.getvalue().splitlines():
            logger.info(f"  [{label} stdout] {line}")
        for line in stderr.getvalue().splitlines():
            logger.warning(f"  [{label} stderr] {line}")

        return ok
