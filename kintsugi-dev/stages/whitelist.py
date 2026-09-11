"""
Stage 9: Whitelist Population

Static analysis based on existing callstack data to fill $WHITELIST$ placeholders.
Also generates network whitelists (internal IP lists) for network repair methods.
"""

import json
import logging
import re
from pathlib import Path
from collections import defaultdict

from config import CVEConfig
from utils.whitelist_utils import (
    parse_filter_range,
    extract_syscalls_in_range,
    compute_whitelist,
    format_whitelist,
    get_placeholder_indent,
    PATH_SUPPORTED_SYSCALLS,
)

logger = logging.getLogger(__name__)


def _is_internal_ip(ip: str) -> bool:
    """Check if the IP is an RFC 1918 private address."""
    if ip.startswith('10.'):
        return True
    if ip.startswith('172.'):
        try:
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return True
        except:
            pass
    if ip.startswith('192.168.'):
        return True
    return False


def _extract_dest_ip(fd_name: str) -> str:
    """Extract the destination IP from fd.name.

    Format: '192.168.144.2:51512->192.168.144.3:80'
    Returns: '192.168.144.3'
    """
    try:
        if '->' not in fd_name:
            return None
        dest = fd_name.split('->')[1]
        ip = dest.split(':')[0]
        return ip
    except:
        return None


def _extract_internal_ips_from_syscalls(syscalls: list) -> set:
    """Extract all internal IPs accessed from syscalls."""
    network_syscalls = ['sendto', 'recvfrom', 'connect', 'sendmsg', 'recvmsg']
    internal_ips = set()

    for sc in syscalls:
        if isinstance(sc, dict):
            syscall_type = sc.get('type', '')
            fd_name = sc.get('fd.name', '')

            if syscall_type in network_syscalls and fd_name:
                dest_ip = _extract_dest_ip(fd_name)
                if dest_ip and _is_internal_ip(dest_ip):
                    internal_ips.add(dest_ip)

    return internal_ips


class WhitelistFiller:
    """Whitelist filler."""

    def __init__(self, cve: CVEConfig, min_files: int = 10):
        self.cve = cve
        self.min_files = min_files

        self.input_dir = cve.data_dir / "repair"
        self.output_dir = cve.data_dir / "repair_with_whitelist"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Lazy-loaded: normal samples database
        self._normal_samples_db = None

    @property
    def normal_samples_db(self) -> dict:
        """Load normal samples database on demand."""
        if self._normal_samples_db is None:
            self._normal_samples_db = self._load_all_normal_samples()
            total_samples = sum(len(v) for v in self._normal_samples_db.values())
            logger.info(f"Loaded {total_samples} normal samples, {len(self._normal_samples_db)} distinct functions")
        return self._normal_samples_db

    def run(self):
        """Main workflow."""
        json_files = list(self.input_dir.glob("*_repairs.json"))

        if not json_files:
            logger.warning(f"No repair files found: {self.input_dir}")
            return

        logger.info(f"Found {len(json_files)} repair files")
        run_stats = {
            "stage": 9,
            "input_files": len(json_files),
            "files": [],
            "totals": {
                "repairs_seen": 0,
                "syscall_whitelists_filled": 0,
                "network_whitelists_filled": 0,
                "normal_samples_used": 0,
                "normal_syscalls_extracted": 0,
                "abnormal_syscalls_in_filter_range": 0,
                "abnormal_syscalls_allowed_by_whitelist": 0,
                "abnormal_syscalls_blocked_by_whitelist": 0,
            },
        }

        for json_file in json_files:
            logger.info(f"Processing: {json_file.name}")
            file_stats = self._process_file(json_file)
            if file_stats:
                run_stats["files"].append(file_stats)
                for key in run_stats["totals"]:
                    run_stats["totals"][key] += file_stats.get(key, 0)

        stats_file = self.output_dir / "whitelist_stats.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(run_stats, f, ensure_ascii=False, indent=2)
        logger.info(f"Whitelist stats saved to: {stats_file}")

    def _load_all_normal_samples(self) -> dict:
        """
        Load all normal samples, grouped by (func_name, def_path).

        Returns:
            Dict[(func_name, def_path)] -> List[sample]
        """
        callstack_dir = self.cve.data_dir / "callstack"
        normal_samples_by_func = defaultdict(list)

        if not callstack_dir.exists():
            logger.warning(f"Callstack directory does not exist: {callstack_dir}")
            return normal_samples_by_func

        normal_files = sorted(callstack_dir.glob("normal_*.jsonl"))

        if not normal_files:
            logger.warning(f"No normal_*.jsonl files found in {callstack_dir}")
            return normal_samples_by_func

        for file in normal_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entry = json.loads(line)
                            entry['_source_file'] = file.name
                            func_name = entry['function']['name']
                            func_def_path = entry['function'].get('def_path', '')
                            key = (func_name, func_def_path)
                            normal_samples_by_func[key].append(entry)
            except Exception as e:
                logger.warning(f"Failed to load file {file.name}: {e}")
                continue

        return normal_samples_by_func

    def _process_file(self, json_file: Path):
        """Process a single repair file."""
        with open(json_file, 'r', encoding='utf-8') as f:
            repairs = json.load(f)

        filled_count = 0
        network_count = 0
        file_stats = {
            "input_file": str(json_file),
            "repairs_seen": len(repairs),
            "syscall_whitelists_filled": 0,
            "network_whitelists_filled": 0,
            "normal_samples_used": 0,
            "normal_syscalls_extracted": 0,
            "abnormal_syscalls_in_filter_range": 0,
            "abnormal_syscalls_allowed_by_whitelist": 0,
            "abnormal_syscalls_blocked_by_whitelist": 0,
            "repairs": [],
        }

        for repair in repairs:
            if not repair.get('success') or not repair.get('repair_code'):
                continue

            # network method: generate network whitelist (internal IP list)
            if repair.get('repair_method') == 'network':
                try:
                    self._fill_network_whitelist(repair)
                    network_count += 1
                    file_stats["network_whitelists_filled"] += 1
                    ips = repair.get('network_whitelist', [])
                    logger.info(f"  {repair['function_name']}: Network whitelist generated ({len(ips)} internal IPs)")
                    if ips:
                        logger.info(f"    Whitelist IPs: {', '.join(ips)}")
                except ValueError as e:
                    logger.warning(f"  {repair['function_name']}: Unable to generate network whitelist: {e}")
                    repair['network_whitelist'] = []  # Empty whitelist, block all internal traffic
                continue

            if '$WHITELIST$' not in repair['repair_code']:
                logger.debug(f"  {repair['function_name']}: No filling needed (no placeholder)")
                continue

            try:
                self._fill_whitelist(repair)
                filled_count += 1
                file_stats["syscall_whitelists_filled"] += 1
                whitelist_stats = repair.get("whitelist_stats", {})
                file_stats["normal_samples_used"] += whitelist_stats.get("normal_samples_count", 0)
                file_stats["normal_syscalls_extracted"] += whitelist_stats.get("normal_syscalls_extracted", 0)
                file_stats["abnormal_syscalls_in_filter_range"] += whitelist_stats.get("abnormal_syscalls_in_filter_range", 0)
                file_stats["abnormal_syscalls_allowed_by_whitelist"] += whitelist_stats.get("abnormal_syscalls_allowed_by_whitelist", 0)
                file_stats["abnormal_syscalls_blocked_by_whitelist"] += whitelist_stats.get("abnormal_syscalls_blocked_by_whitelist", 0)
                file_stats["repairs"].append({
                    "function_name": repair.get("function_name"),
                    "filter_start": repair.get("filter_start"),
                    "filter_end": repair.get("filter_end"),
                    **whitelist_stats,
                })
                logger.info(f"  {repair['function_name']}: Whitelist filled (based on {repair.get('normal_samples_count', 1)} normal samples)")
                logger.info(
                    "    Whitelist block stats: "
                    f"abnormal_syscalls={whitelist_stats.get('abnormal_syscalls_in_filter_range', 0)}, "
                    f"allowed={whitelist_stats.get('abnormal_syscalls_allowed_by_whitelist', 0)}, "
                    f"blocked={whitelist_stats.get('abnormal_syscalls_blocked_by_whitelist', 0)}"
                )

                logger.info(f"    Coverage range: lines {repair.get('filter_start')}-{repair.get('filter_end')}")

                covered = repair.get('covered_functions', [])
                logger.info(f"    Covered functions ({len(covered)}):")
                for func in covered:
                    logger.info(f"      - {func['name']} (line {func['line']})")

                logger.info(f"    Whitelist ({repair['whitelist_syscall_count']} syscall types):")
                for sc_type, paths in repair['whitelist'].items():
                    if paths:
                        logger.info(f"      {sc_type}: {paths}")
                    else:
                        logger.info(f"      {sc_type}: (any path)")

                logger.info(f"    Repaired code:")
                for line in repair['repair_code'].split('\n'):
                    logger.info(f"      {line}")
            except ValueError as e:
                logger.error(f"  {repair['function_name']}: {e}")
                repair['success'] = False
                repair['error'] = str(e)

        output_file = self.output_dir / json_file.name
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(repairs, f, ensure_ascii=False, indent=2)

        if network_count > 0:
            logger.info(f"  Saved to: {output_file} ({filled_count} syscall whitelists, {network_count} network whitelists)")
        else:
            logger.info(f"  Saved to: {output_file} ({filled_count} whitelists filled)")
        file_stats["output_file"] = str(output_file)
        return file_stats

    def _fill_whitelist(self, repair: dict):
        """Fill the whitelist for a single repair."""
        # 1. Validate data format
        self._validate_data_format(repair)

        # 2. Parse filter range
        start_line = repair['start_line']
        abnormal_func = repair['function_pair']['abnormal']['function']
        original_code = abnormal_func['source_code']
        full_syscalls = abnormal_func.get('full_syscalls', [])

        filter_start, filter_end = parse_filter_range(repair['repair_code'], start_line, original_code)

        if filter_start is None or filter_end is None:
            logger.warning(f"  Unable to parse filter range, using function-level whitelist")
            filter_start = start_line
            filter_end = repair['end_line']

        # 3. Get function signature, extract syscalls from all normal samples
        func_name = abnormal_func['name']
        func_def_path = abnormal_func.get('def_path', '')  # File where the function is defined

        # Get all matching normal samples (matched by definition path, not call path)
        key = (func_name, func_def_path)
        normal_samples = self.normal_samples_db.get(key, [])

        if not normal_samples:
            raise ValueError(f"No matching normal samples found: {func_name} ({func_def_path})")

        # Extract syscalls from all normal samples (union)
        all_syscalls = []
        for i, sample in enumerate(normal_samples):
            sample_syscalls = sample['function'].get('full_syscalls', [])
            filtered = extract_syscalls_in_range(sample_syscalls, filter_start, filter_end, func_def_path)
            all_syscalls.extend(filtered)

            if logger.isEnabledFor(logging.DEBUG):
                sample_covered = self._extract_covered_functions(sample_syscalls, filter_start, filter_end, func_def_path)
                syscall_types = set(s.get('type') for s in filtered if s.get('type') != '__FCALL__')
                source_file = sample.get('_source_file', '?')
                logger.debug(f"      Sample {i+1}/{len(normal_samples)} [{source_file}]: "
                           f"{len(filtered)} syscalls, {len(sample_covered)} function calls")
                logger.debug(f"        Syscall types: {sorted(syscall_types)}")
                for func in sample_covered:
                    logger.debug(f"        - {func['name']} (line {func['line']})")

        logger.info(f"    Using {len(normal_samples)} normal samples, extracted {len(all_syscalls)} syscalls")

        # Extract function calls in range (use first sample as representative)
        first_sample_syscalls = normal_samples[0]['function'].get('full_syscalls', [])
        covered_functions = self._extract_covered_functions(first_sample_syscalls, filter_start, filter_end, func_def_path)

        # 4. Compute whitelist
        whitelist = compute_whitelist(all_syscalls, language=self.cve.language, min_files=self.min_files)
        abnormal_syscalls = extract_syscalls_in_range(full_syscalls, filter_start, filter_end, func_def_path)
        whitelist_stats = self._compute_whitelist_block_stats(abnormal_syscalls, whitelist)

        # 5. Format and replace (preserving original indentation)
        repair_code = repair['repair_code']
        indent = get_placeholder_indent(repair_code)
        php53_syntax = False
        if self.cve.language == 'php' and self.cve.version == 5:
            php53_syntax = True
        whitelist_code = format_whitelist(whitelist, self.cve.language, php53_syntax=php53_syntax, indent=indent)
        repair['repair_code'] = repair_code.replace('$WHITELIST$', whitelist_code)

        repair['filter_start'] = filter_start
        repair['filter_end'] = filter_end
        repair['covered_functions'] = covered_functions
        repair['whitelist'] = whitelist
        repair['whitelist_syscall_count'] = len(whitelist)
        repair['normal_samples_count'] = len(normal_samples)
        repair['whitelist_stats'] = {
            'normal_samples_count': len(normal_samples),
            'normal_syscalls_extracted': len(all_syscalls),
            **whitelist_stats,
        }

    def _compute_whitelist_block_stats(self, syscalls: list, whitelist: dict) -> dict:
        """Count how many abnormal syscalls in the repaired range match the generated whitelist."""
        allowed = 0
        blocked = 0
        blocked_examples = []
        syscall_counts = defaultdict(int)
        blocked_by_type = defaultdict(int)

        for sc in syscalls:
            sc_type = sc.get('type')
            if not sc_type or sc_type == '__FCALL__':
                continue

            syscall_counts[sc_type] += 1
            ok, reason = self._syscall_allowed_by_whitelist(sc, whitelist)
            if ok:
                allowed += 1
            else:
                blocked += 1
                blocked_by_type[sc_type] += 1
                if len(blocked_examples) < 10:
                    blocked_examples.append({
                        'type': sc_type,
                        'path': self._extract_syscall_path(sc),
                        'reason': reason,
                    })

        return {
            'abnormal_syscalls_in_filter_range': allowed + blocked,
            'abnormal_syscalls_allowed_by_whitelist': allowed,
            'abnormal_syscalls_blocked_by_whitelist': blocked,
            'abnormal_syscall_types': dict(sorted(syscall_counts.items())),
            'blocked_by_type': dict(sorted(blocked_by_type.items())),
            'blocked_examples': blocked_examples,
        }

    def _syscall_allowed_by_whitelist(self, syscall: dict, whitelist: dict) -> tuple[bool, str]:
        sc_type = syscall.get('type')
        if sc_type not in whitelist:
            return False, 'syscall type not in whitelist'

        allowed_paths = whitelist.get(sc_type) or []
        if sc_type not in PATH_SUPPORTED_SYSCALLS or not allowed_paths:
            return True, 'syscall type allowed'

        path = self._extract_syscall_path(syscall)
        if not path:
            return False, 'path-supported syscall has no path'

        for allowed_path in allowed_paths:
            if path == allowed_path or path.startswith(allowed_path.rstrip('/') + '/'):
                return True, 'path allowed'

        return False, 'path not in whitelist'

    def _extract_syscall_path(self, syscall: dict) -> str:
        for field in ['fd.name', 'evt.arg.path', 'evt.arg.filename']:
            value = syscall.get(field)
            if value:
                return value
        return ''

    def _extract_covered_functions(self, syscalls: list, start_line: int, end_line: int, target_path: str = None) -> list:
        """Extract function calls covered within the given line range."""
        functions = []
        in_range = False

        for item in syscalls:
            if item.get('type') == '__FCALL__':
                line = item.get('line', 0)
                if line < 0:
                    continue
                if target_path and item.get('path') != target_path:
                    continue
                if not in_range and start_line <= line <= end_line:
                    in_range = True
                elif in_range and (line < start_line or line > end_line):
                    in_range = False

                if in_range and item.get('path') == target_path:
                    functions.append({
                        'name': item.get('name'),
                        'line': line,
                        'path': item.get('path'),
                    })

        return functions

    def _fill_network_whitelist(self, repair: dict):
        """
        Generate network whitelist (internal IP list) for network repair methods.

        Extracts all internal IPs accessed from normal sample syscalls;
        these IPs will be allowed through in net_filter.
        """
        func_pair = repair.get('function_pair')
        if not func_pair:
            raise ValueError("Missing function_pair data")

        abnormal_func = func_pair.get('abnormal', {}).get('function', {})
        func_name = abnormal_func.get('name', '')
        func_def_path = abnormal_func.get('def_path', '')

        key = (func_name, func_def_path)
        normal_samples = self.normal_samples_db.get(key, [])

        if not normal_samples:
            raise ValueError(f"No matching normal samples found: {func_name} ({func_def_path})")

        # Extract internal IPs from all normal samples (union)
        all_internal_ips = set()
        for sample in normal_samples:
            sample_syscalls = sample['function'].get('full_syscalls') or sample['function'].get('syscalls', [])
            ips = _extract_internal_ips_from_syscalls(sample_syscalls)
            all_internal_ips.update(ips)

        repair['network_whitelist'] = sorted(all_internal_ips)
        repair['normal_samples_count'] = len(normal_samples)

    def _validate_data_format(self, repair: dict):
        """Validate the data format."""
        func_pair = repair.get('function_pair')
        if not func_pair:
            raise ValueError("Missing function_pair data")

        full_syscalls = func_pair.get('abnormal', {}).get('function', {}).get('full_syscalls', [])

        if not full_syscalls:
            raise ValueError("Missing full_syscalls data")

        has_fcall = any(s.get('type') == '__FCALL__' for s in full_syscalls)

        if not has_fcall:
            raise ValueError(
                f"Incompatible data format: missing __FCALL__ markers. Please re-collect data (Stage 2-5)"
            )
