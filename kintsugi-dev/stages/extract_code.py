"""
Extract detected anomalous function source code from Docker containers - optimized version
"""

import json
import logging
import argparse
import docker
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import textwrap
import atexit

logger = logging.getLogger(__name__)

_write_executor: Optional[ThreadPoolExecutor] = None
_pending_futures = []


def _get_write_executor() -> ThreadPoolExecutor:
    """Get or create the write thread pool."""
    global _write_executor
    if _write_executor is None:
        _write_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="extract_writer")
        atexit.register(_shutdown_write_executor)
    return _write_executor


def _shutdown_write_executor():
    """Shut down the write thread pool."""
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
    """Wait for all pending write tasks to complete."""
    global _pending_futures
    for future in _pending_futures:
        try:
            future.result()
        except Exception as e:
            logger.error(f"Write task failed: {e}", exc_info=True)
    _pending_futures.clear()


def _write_json_file(output_file: Path, data: list):
    """Write a JSON file in the background."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Failed to write {output_file}: {e}")


# Global function definition database for recovering mismatched function definitions
# Key: (func_name, call_path) -> Value: {'def_path', 'def_start', 'def_end'}
DEFINITION_DB = {}

# Maximum number of call stack ancestor functions to extract (from stack top, i.e. most recent callers)
MAX_ANCESTOR_EXTRACT = 5


class SourceCodeExtractor:
    def __init__(self, container_name: str):
        """
        Initialize the source code extractor.

        Args:
            container_name: Docker container name
        """
        self.container_name = container_name
        self.client = None
        self.container = None
        self.code_cache: Dict[Tuple[str, int, int], str] = {}
        self.file_cache: Dict[str, List[str]] = {}
        self._connect_container()

    def _connect_container(self):
        """Connect to the Docker container."""
        try:
            self.client = docker.from_env()
            self.container = self.client.containers.get(self.container_name)
            logger.info(f"Successfully connected to container: {self.container_name}")
        except docker.errors.NotFound:
            logger.error(f"Container not found: {self.container_name}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to connect to container: {e}")
            sys.exit(1)

    def extract_file_with_ranges(self, file_path: str, line_ranges: List[Tuple[int, int]]) -> Dict[Tuple[str, int, int], str]:
        """
        Extract all required line ranges from a single file.

        Args:
            file_path: Path to the file
            line_ranges: List of line ranges to extract [(start, end), ...]

        Returns:
            Dict {(file_path, start, end): code}
        """
        results = {}

        try:
            if file_path not in self.file_cache:
                cmd = f"cat {file_path}"
                result = self.container.exec_run(cmd)

                if result.exit_code != 0:
                    logger.warning(f"Unable to read file {file_path}")
                    return results

                lines = result.output.decode('utf-8').splitlines()
                self.file_cache[file_path] = lines

            lines = self.file_cache[file_path]

            for start, end in line_ranges:
                key = (file_path, start, end)

                if key not in self.code_cache:
                    # Line numbers are 1-based, array indices are 0-based
                    if start > 0 and end <= len(lines):
                        raw_code = '\n'.join(lines[start-1:end])
                        dedented_code = textwrap.dedent(raw_code)
                        # Calculate original indent level (leading spaces of first non-empty line)
                        first_line = next((line for line in lines[start-1:end] if line.strip()), '')
                        indent_level = len(first_line) - len(first_line.lstrip())
                        self.code_cache[key] = (dedented_code, indent_level)
                        results[key] = (dedented_code, indent_level)
                    else:
                        logger.warning(f"Line range out of bounds {file_path}:{start}-{end} (file has {len(lines)} lines)")

        except Exception as e:
            logger.error(f"Failed to extract {file_path}: {e}")

        return results

    def batch_extract_from_container(self, grouped_requests: Dict[str, List[Tuple[int, int]]]):
        """
        Batch extract source code in parallel.

        Args:
            grouped_requests: Extraction requests grouped by file {file_path: [(start, end), ...]}
        """
        logger.info("Batch extracting source code...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.extract_file_with_ranges, fpath, ranges): fpath
                for fpath, ranges in grouped_requests.items()
            }

            completed = 0
            total = len(futures)

            for future in as_completed(futures):
                file_path = futures[future]
                completed += 1
                try:
                    results = future.result()
                    logger.debug(f"[{completed}/{total}] Extracted file: {file_path} ({len(results)} new snippets)")
                except Exception as e:
                    logger.error(f"[{completed}/{total}] {file_path}: {e}")

        logger.info(f"Cache contains {len(self.code_cache)} code snippets")

    def enhance_entry_with_cache(self, entry: Dict) -> Dict:
        """
        Enhance a single entry using the cache, recovering definition info for mismatched functions.

        Args:
            entry: Function call information

        Returns:
            Enhanced entry
        """
        # Main function
        func = entry.get('function', {})

        # If mismatched (missing definition), attempt recovery from global database
        if not func.get('def_path'):
            key = (func['name'], func.get('path', ''))
            if key in DEFINITION_DB:
                func['def_path'] = DEFINITION_DB[key]['def_path']
                func['def_start'] = DEFINITION_DB[key]['def_start']
                func['def_end'] = DEFINITION_DB[key]['def_end']
                func['_recovered'] = True

        if func.get('def_path'):
            key = (
                func['def_path'],
                func.get('def_start'),
                func.get('def_end')
            )
            if key in self.code_cache:
                dedented_code, indent_level = self.code_cache[key]
                func['source_code'] = dedented_code
                func['indent_level'] = indent_level

        # Call stack ancestor functions (only process the most recent N)
        call_stack = entry.get('call_stack', [])
        ancestors_to_process = call_stack[-MAX_ANCESTOR_EXTRACT:] if len(call_stack) > MAX_ANCESTOR_EXTRACT else call_stack
        for ancestor in ancestors_to_process:
            if not ancestor.get('def_path'):
                key = (ancestor.get('name', ''), ancestor.get('path', ''))
                if key in DEFINITION_DB:
                    ancestor['def_path'] = DEFINITION_DB[key]['def_path']
                    ancestor['def_start'] = DEFINITION_DB[key]['def_start']
                    ancestor['def_end'] = DEFINITION_DB[key]['def_end']
                    ancestor['_recovered'] = True

            if ancestor.get('def_path'):
                key = (
                    ancestor['def_path'],
                    ancestor.get('def_start'),
                    ancestor.get('def_end')
                )
                if key in self.code_cache:
                    dedented_code, indent_level = self.code_cache[key]
                    ancestor['source_code'] = dedented_code
                    ancestor['indent_level'] = indent_level

        # Called functions (same processing)
        for called in entry.get('called_functions', []):
            if not called.get('def_path'):
                key = (called['name'], called.get('path', ''))
                if key in DEFINITION_DB:
                    called['def_path'] = DEFINITION_DB[key]['def_path']
                    called['def_start'] = DEFINITION_DB[key]['def_start']
                    called['def_end'] = DEFINITION_DB[key]['def_end']
                    called['_recovered'] = True

            if called.get('def_path'):
                key = (
                    called['def_path'],
                    called.get('def_start'),
                    called.get('def_end')
                )
                if key in self.code_cache:
                    dedented_code, indent_level = self.code_cache[key]
                    called['source_code'] = dedented_code
                    called['indent_level'] = indent_level

        return entry


def build_definition_database(jsonl_files: List[Path]):
    """
    Scan all JSONL files and build a function definition database for recovering mismatched definitions.

    Args:
        jsonl_files: List of JSONL files
    """
    global DEFINITION_DB

    logger.info("Building function definition database...")

    # Prioritize 'normal' files (definitions from normal execution are more reliable)
    sorted_files = sorted(jsonl_files, key=lambda x: ('normal' not in x.name, x.name))

    for jsonl_file in sorted_files:
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    func = entry.get('function', {})

                    # Only collect functions with complete definition info
                    if func.get('def_path'):
                        key = (func['name'], func.get('path', ''))

                        # Keep the first encountered (from normal files)
                        if key not in DEFINITION_DB:
                            DEFINITION_DB[key] = {
                                'def_path': func['def_path'],
                                'def_start': func['def_start'],
                                'def_end': func['def_end']
                            }

                except json.JSONDecodeError:
                    continue

    logger.info(f"Collected {len(DEFINITION_DB)} function definitions")


def collect_extraction_requests(jsonl_files: List[Path]) -> Set[Tuple[str, int, int]]:
    """
    Traverse all JSONL files and collect unique extraction requests.

    Args:
        jsonl_files: List of JSONL files

    Returns:
        Set of unique extraction requests {(file_path, start_line, end_line), ...}
    """
    logger.info("Collecting extraction requests...")
    requests = set()

    for jsonl_file in jsonl_files:
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    # Main function
                    func = entry.get('function', {})
                    if func.get('def_path') and func.get('def_start') and func.get('def_end'):
                        requests.add((
                            func['def_path'],
                            func['def_start'],
                            func['def_end']
                        ))

                    # Call stack ancestor functions (only extract the most recent N)
                    call_stack = entry.get('call_stack', [])
                    ancestors_to_extract = call_stack[-MAX_ANCESTOR_EXTRACT:] if len(call_stack) > MAX_ANCESTOR_EXTRACT else call_stack
                    for ancestor in ancestors_to_extract:
                        if ancestor.get('def_path') and ancestor.get('def_start') and ancestor.get('def_end'):
                            requests.add((
                                ancestor['def_path'],
                                ancestor['def_start'],
                                ancestor['def_end']
                            ))

                    # Called functions
                    for called in entry.get('called_functions', []):
                        if called.get('def_path') and called.get('def_start') and called.get('def_end'):
                            requests.add((
                                called['def_path'],
                                called['def_start'],
                                called['def_end']
                            ))

                except json.JSONDecodeError:
                    continue

    logger.info(f"Need to extract {len(requests)} unique code snippets")
    return requests


def group_by_file(requests: Set[Tuple[str, int, int]]) -> Dict[str, List[Tuple[int, int]]]:
    """
    Group extraction requests by file path.

    Args:
        requests: Set of extraction requests

    Returns:
        Requests grouped by file {file_path: [(start, end), ...]}
    """
    grouped = defaultdict(list)
    for file_path, start, end in requests:
        grouped[file_path].append((start, end))

    logger.info(f"Spanning {len(grouped)} files")
    return grouped


def extract_source_code(cve):
    """
    Extract source code for a given CVE.

    Args:
        cve: CVEConfig object

    Returns:
        bool: Whether the extraction succeeded
    """
    try:
        input_dir = cve.data_dir / "callstack"
        output_dir = cve.data_dir / "callstack_with_code"

        output_dir.mkdir(parents=True, exist_ok=True)

        jsonl_files = sorted(input_dir.glob("*.jsonl"))

        if not jsonl_files:
            logger.error(f"No JSONL files found in {input_dir}")
            return False

        logger.info(f"Found {len(jsonl_files)} JSONL files")

        # Phase 0: Build function definition database (for recovering mismatched functions)
        build_definition_database(jsonl_files)

        extractor = SourceCodeExtractor(cve.container)

        # Phase 1: Collect all extraction requests
        requests = collect_extraction_requests(jsonl_files)

        if not requests:
            logger.warning("No code to extract")
            return False

        # Phase 2: Group by file
        grouped = group_by_file(requests)

        # Phase 3: Batch parallel extraction (populate cache)
        extractor.batch_extract_from_container(grouped)

        # Phase 4: Assemble all JSONL files
        logger.info("Assembling results...")
        total_entries = 0
        total_with_code = 0

        for file_idx, jsonl_file in enumerate(jsonl_files, 1):
            logger.info(f"[{file_idx}/{len(jsonl_files)}] Processing: {jsonl_file.name}")
            enhanced_entries = []

            with open(jsonl_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        enhanced = extractor.enhance_entry_with_cache(entry)
                        enhanced_entries.append(enhanced)
                        total_entries += 1

                        if enhanced.get('function', {}).get('source_code'):
                            total_with_code += 1

                    except json.JSONDecodeError:
                        continue

            if enhanced_entries:
                output_file = output_dir / f"{jsonl_file.stem}.json"
                executor = _get_write_executor()
                future = executor.submit(_write_json_file, output_file, enhanced_entries)
                _pending_futures.append(future)
                logger.debug(f"Submitted write task: {output_file}")

        logger.info(f"Processing complete: {len(jsonl_files)} files, {total_entries} calls, {total_with_code} with source code extracted")

        logger.info("Waiting for background writes to complete...")
        wait_for_pending_writes()
        logger.info("All writes complete")

        return True

    except Exception as e:
        logger.error(f"Error during processing: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    from config import load_cve_config

    parser = argparse.ArgumentParser(
        description='Extract function source code from Docker containers - optimized version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 extract_code.py --cve CVE-2021-26120

Fixed paths:
  - Input: data/{cve}/callstack/*.jsonl
  - Output: data/{cve}/callstack_with_code/

Optimizations:
  - Automatic deduplication to avoid redundant extraction
  - Global cache with cross-file reuse
  - Parallel processing for 10-50x speedup
  - Batch reads to reduce Docker calls
        """
    )
    parser.add_argument('--cve', required=True,
                        help='CVE identifier (e.g. CVE-2015-8562)')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    cve = load_cve_config(args.cve)
    success = extract_source_code(cve)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)
