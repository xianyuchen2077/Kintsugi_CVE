"""
Automated Traffic Collection Script
Complete version with sysdig functionality enabled
"""

import logging
import os
import sys
import time
import signal
import requests
import subprocess
import argparse
import importlib.util
from pathlib import Path

logger = logging.getLogger(__name__)


def sudo_command(*args):
    password = os.getenv("KINTSUGI_SUDO_PASSWORD")
    if password:
        return ["sudo", "-S", "-p", "", *args], f"{password}\n"
    return ["sudo", *args], None


class TrafficCollector:
    def __init__(self, cve, normal_time: int = 60, malicious_time: int = 20):
        self.cve = cve
        self.project_dir = Path(__file__).parent.parent
        self.data_dir = cve.data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.script_dir = cve.env_dir.parent
        self.port = cve.port

        # Run time settings (in seconds)
        self.normal_time = normal_time
        self.malicious_time = malicious_time

        # Process tracking
        self.sysdig_process = None
        self.locust_process = None
        self.current_capture_file = None
        self.traffic_env = {}
        
        # Setup signal handling
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)

    def wait_for_target(self, timeout: int = 120, interval: int = 3) -> bool:
        """Wait until the target web service is ready for traffic generation."""
        deadline = time.time() + timeout
        candidates = [
            f'http://localhost:{self.port}/vufind/Cover/Show?isbn=9780140328721',
            f'http://localhost:{self.port}/vufind/',
            f'http://localhost:{self.port}/',
        ]

        last_error = None
        while time.time() < deadline:
            for url in candidates:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code < 500 or "VuFind" in response.text:
                        logger.info(f"Target service is reachable: {url} status={response.status_code}")
                        return True
                    last_error = f"{url} status={response.status_code}"
                except Exception as e:
                    last_error = f"{url} {e}"

            logger.info(f"Target not ready yet ({last_error}); retrying in {interval}s")
            time.sleep(interval)

        logger.warning(f"Target service did not become ready within {timeout}s ({last_error})")
        return False

    def cleanup(self, signum=None, frame=None):
        """Clean up all running processes"""
        logger.info("Cleaning up processes...")

        if self.locust_process and self.locust_process.poll() is None:
            logger.info("Stopping locust process...")
            self.locust_process.terminate()
            try:
                self.locust_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.locust_process.kill()

        if self.sysdig_process and self.sysdig_process.poll() is None:
            logger.info("Stopping sysdig process...")
            self.sysdig_process.terminate()
            try:
                self.sysdig_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.sysdig_process.kill()

        logger.info("Cleanup completed")
        if signum:
            sys.exit(1)
    
    def start_capture(self, capture_file):
        """Start sysdig capture"""
        logger.info(f"Starting sysdig capture: {capture_file.name}")

        try:
            cmd, sudo_input = sudo_command('sysdig', '-s', '10000', '-w', str(capture_file))
            self.current_capture_file = capture_file
            self.sysdig_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if sudo_input else subprocess.DEVNULL,
                start_new_session=True,
            )
            if sudo_input and self.sysdig_process.stdin:
                self.sysdig_process.stdin.write(sudo_input.encode("utf-8"))
                self.sysdig_process.stdin.flush()
                self.sysdig_process.stdin.close()

            logger.info("Waiting 3 seconds for sysdig to initialize...")
            time.sleep(3)

            # Verify sysdig is still running
            if self.sysdig_process.poll() is not None:
                stderr = ""
                if self.sysdig_process.stderr:
                    stderr = self.sysdig_process.stderr.read().decode("utf-8", errors="replace").strip()
                logger.error(f"sysdig process exited early{': ' + stderr if stderr else ''}")
                return False

            logger.info("Sysdig capture started successfully")
            return True

        except Exception as e:
            logger.error(f"Error starting sysdig: {e}")
            return False
    
    def stop_capture(self):
        """Stop sysdig capture"""
        logger.info("Stopping sysdig capture")

        if self.sysdig_process and self.sysdig_process.poll() is None:
            pattern = None
            if self.current_capture_file:
                pattern = f"sysdig -s 10000 -w {self.current_capture_file}"
            try:
                self.sysdig_process.terminate()
                if pattern:
                    cmd, sudo_input = sudo_command('pkill', '-TERM', '-f', pattern)
                    subprocess.run(cmd, input=sudo_input, text=True, capture_output=True, timeout=5)
                self.sysdig_process.wait(timeout=5)
                logger.info("Sysdig stopped")

                return True

            except subprocess.TimeoutExpired:
                # Force kill with SIGKILL if still running
                logger.warning("Force killing sysdig with SIGKILL...")
                if pattern:
                    cmd, sudo_input = sudo_command('pkill', '-KILL', '-f', pattern)
                    subprocess.run(cmd, input=sudo_input, text=True, capture_output=True)
                self.sysdig_process.kill()
                try:
                    self.sysdig_process.wait(timeout=2)
                except:
                    pass
                logger.info("Sysdig force stopped")
                return True
        else:
            logger.info("Sysdig process not running")
        return True
    
    def prepare_traffic_script(self, traffic_script):
        """Run an optional traffic-script preparation hook before Locust starts."""
        try:
            source = traffic_script.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.error(f"Could not read traffic script: {traffic_script}: {exc}")
            return False
        if "def prepare_traffic" not in source:
            return True

        spec = importlib.util.spec_from_file_location(
            f"kintsugi_traffic_prepare_{traffic_script.stem}",
            traffic_script,
        )
        if not spec or not spec.loader:
            return True

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        prepare = getattr(module, "prepare_traffic", None)
        if prepare is None:
            return True

        logger.info(f"Running traffic preparation hook: {traffic_script.name}")
        result = prepare()
        if result is False:
            logger.error(f"Traffic preparation hook failed: {traffic_script.name}")
            return False
        if isinstance(result, dict):
            self.traffic_env.update({str(k): str(v) for k, v in result.items()})
        return True

    def execute_traffic(self, traffic_type):
        """Execute locust traffic generation"""
        logger.info(f"Executing {traffic_type} operation...")

        # Check if traffic script exists
        traffic_script = self.script_dir / f"{traffic_type}.py"
        if not traffic_script.exists():
            logger.error(f"Traffic script not found: {traffic_script}")
            return False

        if not self.prepare_traffic_script(traffic_script):
            return False

        # Set run time based on traffic type
        if traffic_type == 'normal':
            run_time = f'{self.normal_time}s'
        else:
            run_time = f'{self.malicious_time}s'

        # Prepare locust command
        cmd = [
            sys.executable,
            '-m', 'locust',
            '-f', str(traffic_script),
            '--headless',
            '--users', '1',
            '--spawn-rate', '1',
            '--run-time', run_time,
            '--host', f'http://localhost:{self.port}'
        ]

        try:
            logger.info("Starting locust...")
            env = os.environ.copy()
            env.update(self.traffic_env)
            self.locust_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                env=env
            )

            # Monitor output in real-time
            while True:
                output = self.locust_process.stdout.readline()
                if output == '' and self.locust_process.poll() is not None:
                    break
                if output:
                    logger.info(output.strip())

            # Wait for completion with timeout (run_time + buffer)
            if traffic_type == 'normal':
                timeout = self.normal_time + 140
            else:
                timeout = self.malicious_time + 30
            try:
                return_code = self.locust_process.wait(timeout=timeout)

                if return_code == 0:
                    logger.info(f"{traffic_type} operation completed successfully")
                    return True
                else:
                    logger.error(f"{traffic_type} operation failed with code {return_code}")
                    return False

            except subprocess.TimeoutExpired:
                logger.warning("Locust timeout, terminating...")
                self.locust_process.kill()
                return False
        except Exception as e:
            logger.error(f"Error running locust: {e}")
            return False
        finally:
            self.locust_process = None
    
    def collect_single(self, traffic_type):
        """Collect traffic for one type"""
        logger.info(f"=== Collecting {traffic_type} traffic ===")

        capture_file = self.data_dir / f"{traffic_type}.scap"

        # Remove existing capture file if it exists
        if capture_file.exists():
            logger.info(f"Removing existing capture file: {capture_file.name}")
            capture_file.unlink()

        try:
            # Step 1: Start capture
            if not self.start_capture(capture_file):
                logger.error("Failed to start sysdig capture")
                return False

            # Step 2: Execute traffic
            if not self.execute_traffic(traffic_type):
                logger.error("Failed to execute traffic generation")
                self.stop_capture()
                return False

            # Step 3: Stop capture
            if not self.stop_capture():
                logger.warning("Issues stopping capture")

            logger.info(f"=== {traffic_type} traffic collection completed ===")
            return True

        except Exception as e:
            logger.error(f"Error in collection: {e}")
            self.cleanup()
            return False
    
    def preflight_checks(self):
        """Run comprehensive checks before starting"""
        logger.info("Running preflight checks...")

        # Check locust
        try:
            result = subprocess.run([sys.executable, '-m', 'locust', '--version'],
                                    capture_output=True, check=True, text=True)
            logger.info(f"Locust version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("locust not found or not working")
            return False

        # Check sysdig
        try:
            cmd, sudo_input = sudo_command('sysdig', '--version')
            result = subprocess.run(cmd, input=sudo_input,
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Sysdig is available")
            else:
                logger.warning("sysdig may not be properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("sysdig not found or not responding")
            return False

        # Check target service. pgAdmin can accept TCP connections before login
        # and CSRF handling are ready, so wait for the login page specifically.
        self.wait_for_target()

        # Check sudo permissions for sysdig
        try:
            cmd, sudo_input = sudo_command('true')
            result = subprocess.run(cmd, input=sudo_input, text=True,
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info("Sudo permissions available")
            else:
                logger.warning("May need to enter sudo password")
        except subprocess.TimeoutExpired:
            logger.warning("Sudo check timeout")

        logger.info("Preflight checks completed")
        return True
    
    def run(self, operation):
        """Main execution function"""
        logger.info(f"Starting traffic collection for {self.script_dir.name}")

        if not self.preflight_checks():
            logger.warning("Preflight checks failed - continuing anyway")

        try:
            if operation == 'normal':
                return self.collect_single('normal')
            elif operation == 'malicious':
                return self.collect_single('malicious')
            elif operation == 'both':
                logger.info("=== Starting sequential collection ===")

                if not self.collect_single('normal'):
                    logger.error("Normal collection failed")
                    return False

                logger.info("Waiting 10 seconds before malicious collection...")
                time.sleep(10)

                if not self.collect_single('malicious'):
                    logger.error("Malicious collection failed")
                    return False

                logger.info("=== All collections completed ===")
                return True
            else:
                logger.error(f"Unknown operation: {operation}")
                return False

        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            self.cleanup()
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self.cleanup()
            return False


def collect_traffic(cve_number, operation, port=8080, verbose=False):
    """
    External function interface for traffic collection

    Args:
        cve_number (str): CVE number (e.g., 'CVE-2021-26120')
        operation (str): Type of traffic to collect ('normal', 'malicious', or 'both')
        port (int): Port number for the target service (default: 8080)
        verbose (bool): Enable verbose output

    Returns:
        bool: True if successful, False otherwise
    """
    if operation not in ['normal', 'malicious', 'both']:
        raise ValueError("Operation must be 'normal', 'malicious', or 'both'")

    collector = TrafficCollector(cve_number, port)
    return collector.run(operation)
