"""
Stage 8: Repair Code Generation

Generate repair code (using $WHITELIST$ placeholder, initially blocking all syscalls)
"""

import json
import csv
import re
import logging
from pathlib import Path

from config import CVEConfig
from utils.repair_utils import (
    create_llm_client,
    call_llm,
    get_repair_prompt,
    get_localization_only_prompt,
    get_single_function_repair_prompt,
    format_llm_input,
    extract_code_block,
    batch_judge_repairs,
    determine_repair_location,
    judge_repair_method,
)

logger = logging.getLogger(__name__)


def load_all_functions_from_callstack(callstack_file: Path) -> list:
    """Load all functions from callstack_with_code file (including main functions, call stack, and called functions)

    Args:
        callstack_file: Path to callstack_with_code JSON file

    Returns:
        Deduplicated list of functions
    """
    with open(callstack_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    functions = []
    seen = set()  # Deduplicate by (def_path, def_start, def_end)

    for entry in data:
        # 1. Main function
        func = entry.get('function', {})
        if func.get('name') and func.get('def_path'):
            key = (func['def_path'], func.get('def_start', 0), func.get('def_end', 0))
            if key not in seen:
                seen.add(key)
                functions.append(func)

        # 2. Call stack ancestor functions
        for ancestor in entry.get('call_stack', []):
            if ancestor.get('name') and ancestor.get('def_path'):
                key = (ancestor['def_path'], ancestor.get('def_start', 0), ancestor.get('def_end', 0))
                if key not in seen:
                    seen.add(key)
                    functions.append(ancestor)

        # 3. Called functions
        for called in entry.get('called_functions', []):
            if called.get('name') and called.get('def_path'):
                key = (called['def_path'], called.get('def_start', 0), called.get('def_end', 0))
                if key not in seen:
                    seen.add(key)
                    functions.append(called)

    return functions


class RepairGenerator:
    """Repair code generator"""

    def __init__(
        self,
        cve: CVEConfig,
        repair_mode: str = "filter",
        whitelist_mode: str = "static",
        feedback_context: str = "",
        feedback_attempt: int = 0,
    ):
        self.cve = cve
        self.repair_mode = repair_mode  # "filter", "direct", or "direct_localization"
        self.whitelist_mode = whitelist_mode  # "static" (filled in Stage 9) or "llm" (generate directly)
        self.feedback_context = feedback_context.strip()
        self.feedback_attempt = feedback_attempt

        self.input_dir = cve.data_dir / "detect"

        # All modes output to the same directory (for subsequent stage 9/10 processing)
        self.output_dir = cve.data_dir / "repair"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.llm_client = create_llm_client()

        # Lazy load: normal samples database (only used when whitelist_mode="llm")
        self._normal_samples_db = None

    @property
    def normal_samples_db(self) -> dict:
        """Load normal samples database on demand"""
        if self._normal_samples_db is None:
            self._normal_samples_db = self._load_all_normal_samples()
            total_samples = sum(len(v) for v in self._normal_samples_db.values())
            logger.info(f"Loaded {total_samples} normal samples across {len(self._normal_samples_db)} distinct functions")
        return self._normal_samples_db

    def _load_all_normal_samples(self) -> dict:
        """Load all normal samples, grouped by (func_name, def_path)

        Returns:
            Dict[(func_name, def_path)] -> List[sample]
        """
        from collections import defaultdict

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

    def run(
        self,
        threshold: float = 0.5,
        backtrack_repair: int | None = None,
        filter_irrelevant: bool = False,
        max_repairs: int = 1,
    ):
        """
        Main workflow

        Args:
            threshold: Anomaly score threshold
            backtrack_repair: Backtrack repair depth (None to disable)
            filter_irrelevant: Whether to enable batch judgment filtering
            max_repairs: Maximum number of repair files (default 1, 0 for all)
        """
        if self.repair_mode == "direct_localization":
            self._run_direct_localization(max_repairs)
            return

        json_files = sorted(self.input_dir.glob("*_pairs.json"))

        if not json_files:
            logger.warning(f"No detection result files found: {self.input_dir}")
            return

        if max_repairs > 0:
            json_files = json_files[:max_repairs]

        logger.info(f"Processing {len(json_files)} detection result files")
        if self.feedback_context:
            logger.info(f"Validation feedback enabled for repair attempt {self.feedback_attempt}")
        run_stats = {
            "stage": 8,
            "threshold": threshold,
            "filter_irrelevant": filter_irrelevant,
            "backtrack_repair": backtrack_repair,
            "max_repairs": max_repairs,
            "feedback_attempt": self.feedback_attempt,
            "feedback_context": self.feedback_context,
            "input_files": len(json_files),
            "files": [],
            "totals": {
                "pairs_input": 0,
                "candidates_after_threshold": 0,
                "candidates_after_batch_judgment": 0,
                "repairs_generated": 0,
                "repairs_success": 0,
                "skipped_below_threshold": 0,
                "skipped_no_source": 0,
                "skipped_no_syscalls": 0,
                "skipped_duplicate": 0,
                "skipped_batch_judgment": 0,
            },
        }

        for json_file in json_files:
            logger.info(f"Processing: {json_file.name}")
            file_stats = self._process_file(json_file, threshold, backtrack_repair, filter_irrelevant)
            if file_stats:
                run_stats["files"].append(file_stats)
                for key in run_stats["totals"]:
                    run_stats["totals"][key] += file_stats.get(key, 0)

        stats_file = self.output_dir / "repair_stats.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(run_stats, f, ensure_ascii=False, indent=2)
        logger.info(f"Repair stats saved to: {stats_file}")

    def _run_direct_localization(self, max_repairs: int = 1):
        """Direct localization + repair mode

        Does not use differential analysis; provides all function code to LLM for localization and repair
        """
        logger.info("Using direct localization mode (direct_localization)")

        callstack_dir = self.cve.data_dir / "callstack_with_code"
        if not callstack_dir.exists():
            logger.error(f"callstack_with_code directory not found: {callstack_dir}")
            return

        callstack_files = sorted(callstack_dir.glob("malicious_*.json"))
        if not callstack_files:
            logger.error("No malicious request callstack files found")
            return

        if max_repairs > 0:
            callstack_files = callstack_files[:max_repairs]

        logger.info(f"Processing {len(callstack_files)} callstack files")

        for callstack_file in callstack_files:
            logger.info(f"Processing: {callstack_file.name}")
            self._process_direct_localization(callstack_file)

    def _process_direct_localization(self, callstack_file: Path):
        """Process a single direct localization request (two-phase mode)

        Phase 1: LLM performs localization only, identifying the vulnerable function
        Phase 2: LLM generates repair code for the identified function
        """
        # 1. Load all functions
        functions = load_all_functions_from_callstack(callstack_file)

        functions = [
            f for f in functions
            if not f.get('is_builtin') and f.get('source_code')
        ]

        if not functions:
            logger.warning("No valid functions found")
            return

        logger.info(f"  Loaded {len(functions)} functions")

        # 2. Extract payload information
        request_prefix = callstack_file.stem  # e.g., "malicious_0"
        payload_info = self._extract_payload_info(request_prefix)

        # 3. Build function list
        function_list = self._format_function_list(functions)

        # ==================== Phase 1: Localization ====================
        logger.info("  [Phase 1] Calling LLM for vulnerability localization...")

        localization_prompt = get_localization_only_prompt(self.cve.language)
        localization_prompt = localization_prompt.format(
            payload_info=payload_info,
            function_list=function_list
        )

        localization_response = call_llm(self.llm_client, localization_prompt, "", max_tokens=4096)

        if not localization_response:
            logger.error("  Localization phase LLM call failed")
            return

        localization_info = self._extract_localization_result(localization_response)

        if not localization_info['function_name']:
            logger.error("  Unable to extract vulnerable function name from response")
            return

        logger.info(f"  Localized vulnerable function: {localization_info['function_name']}")

        func_info = self._find_function_info(functions, localization_info['function_name'])

        if not func_info:
            logger.error(f"  Function info not found: {localization_info['function_name']}")
            return

        if not func_info.get('source_code'):
            logger.error(f"  Function missing source code: {localization_info['function_name']}")
            return

        # ==================== Phase 2: Repair ====================
        logger.info("  [Phase 2] Calling LLM to generate repair code...")

        repair_prompt_template = get_single_function_repair_prompt(self.cve.language)
        repair_prompt = repair_prompt_template.format(
            payload_info=payload_info,
            function_name=func_info.get('name'),
            function_path=func_info.get('def_path', ''),
            source_code=func_info.get('source_code', '')
        )
        if self.feedback_context:
            logger.info(f"  Using validation feedback for repair attempt {self.feedback_attempt}")
            repair_prompt = (
                f"{repair_prompt}\n\n"
                "=== Previous validation feedback ===\n"
                "The previous repair was applied and validated, but it did not pass. "
                "Use this feedback to generate a different or corrected repair. "
                "Do not repeat the same failed placement or strategy if the feedback shows why it failed.\n"
                f"{self.feedback_context}\n"
                "=== End previous validation feedback ===\n"
            )

        repair_response = call_llm(self.llm_client, repair_prompt, "", max_tokens=4096)

        if not repair_response:
            logger.error("  Repair phase LLM call failed")
            return

        repair_code = extract_code_block(repair_response)

        if not repair_code:
            logger.error("  Unable to extract repair code from response")
            return

        logger.info(f"  Successfully generated repair code ({len(repair_code.split(chr(10)))} lines)")

        repair_result = {
            'function_name': func_info.get('name'),
            'function_path': localization_info['function_path'] or func_info.get('def_path'),
            'start_line': func_info.get('def_start'),
            'end_line': func_info.get('def_end'),
            'indent_level': func_info.get('indent_level', 0),
            'repair_code': repair_code,
            'success': True,
            'analysis': repair_response,
            'repair_method': 'direct_localization',
            'feedback_attempt': self.feedback_attempt,
            'feedback_context': self.feedback_context,
            'function_pair': None,  # Direct localization mode has no pair
            'additional_llm_calls': {
                'localization_call': {
                    'prompt': localization_prompt,
                    'response': localization_response,
                    'result': localization_info
                },
                'backtrack_calls': [],
                'batch_judge_call': '',
                'repair_method_decision': {
                    'source': 'Direct localization mode (two-phase)',
                    'prompt': '',
                    'input': '',
                    'response': ''
                }
            }
        }

        output_file = self.output_dir / f"{request_prefix}_repairs.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([repair_result], f, ensure_ascii=False, indent=2)

        logger.info(f"  Saved to: {output_file}")

    def _extract_localization_result(self, response: str) -> dict:
        """Extract results from localization phase LLM response"""
        result = {
            'function_name': None,
            'function_path': None,
            'reason': None
        }

        patterns = [
            r"漏洞函数\s*[:：]\s*(.+)",
            r"函数名\s*[:：]\s*(.+)",
            r"最可能存在漏洞的函数\s*[:：]\s*(.+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, response)
            if match:
                result['function_name'] = match.group(1).strip().strip('`"\'.,;')
                break

        match = re.search(r"漏洞文件\s*[:：]\s*(.+)", response)
        if match:
            result['function_path'] = match.group(1).strip().strip('`"\'.,;')

        match = re.search(r"理由\s*[:：]\s*(.+)", response)
        if match:
            result['reason'] = match.group(1).strip()

        return result

    def _extract_payload_info(self, request_prefix: str) -> str:
        """Extract payload information for malicious requests from the unit directory"""
        unit_dir = self.cve.data_dir / "unit"
        payload_list = []
        seen_payloads = set()

        if unit_dir.exists():
            for csv_file in sorted(unit_dir.glob("malicious_*.csv")):
                try:
                    with open(csv_file, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        first_row = next(reader, None)
                        if first_row:
                            payload = first_row.get('evt.arg.data', '') or first_row.get('evt.buffer', '')
                            if payload:
                                payload_key = payload[:500]
                                if payload_key not in seen_payloads:
                                    seen_payloads.add(payload_key)
                                    payload_list.append({
                                        'file': csv_file.name,
                                        'payload': payload
                                    })
                except Exception as e:
                    logger.warning(f"Failed to read {csv_file.name}: {e}")

        if payload_list:
            lines = []
            for i, p in enumerate(payload_list, 1):
                lines.append(f"[Request {i}] ({p['file']})\n{p['payload']}")
            return "\n\n".join(lines)
        else:
            return "Unknown"

    def _format_function_list(self, functions: list) -> str:
        """Format the function list"""
        lines = []
        for i, func in enumerate(functions, 1):
            name = func.get('name', 'unknown')
            def_path = func.get('def_path', '')
            source_code = func.get('source_code', '// Source code unavailable')

            lines.append(f"=== Function {i}: {name} ===")
            lines.append(f"File: {def_path}")
            lines.append(source_code)
            lines.append("")

        return "\n".join(lines)

    def _find_function_info(self, functions: list, function_name: str) -> dict:
        """Find matching function info from the function list"""
        for func in functions:
            if func.get('name') == function_name:
                return func

        for func in functions:
            if function_name in func.get('name', '') or func.get('name', '') in function_name:
                return func

        return None

    def _process_file(
        self,
        json_file: Path,
        threshold: float,
        backtrack_repair: int | None,
        filter_irrelevant: bool,
    ):
        """Process a single detection result file"""
        with open(json_file, 'r', encoding='utf-8') as f:
            pairs = json.load(f)

        file_stats = {
            "input_file": str(json_file),
            "pairs_input": len(pairs),
            "threshold": threshold,
            "candidates_after_threshold": 0,
            "candidates_after_batch_judgment": 0,
            "repairs_generated": 0,
            "repairs_success": 0,
            "skipped_below_threshold": 0,
            "skipped_no_source": 0,
            "skipped_no_syscalls": 0,
            "skipped_duplicate": 0,
            "skipped_batch_judgment": 0,
        }

        # Track additional LLM calls (for statistics)
        additional_llm_calls = {
            'backtrack_calls': [],
            'batch_judge_call': '',
        }

        # 1. Filter candidate functions
        candidates, filter_stats = self._filter_candidates(pairs, threshold, return_stats=True)
        file_stats.update(filter_stats)
        file_stats["candidates_after_threshold"] = len(candidates)
        logger.info(
            "  Candidate filter stats: "
            f"input={file_stats['pairs_input']}, "
            f"below_threshold={file_stats['skipped_below_threshold']}, "
            f"no_source={file_stats['skipped_no_source']}, "
            f"no_syscalls={file_stats['skipped_no_syscalls']}, "
            f"duplicates={file_stats['skipped_duplicate']}, "
            f"kept={file_stats['candidates_after_threshold']}"
        )

        if not candidates:
            logger.info(f"  No functions need repair")
            return file_stats

        logger.info(f"  Candidate functions: {len(candidates)}")

        # 2. Repair location backtracking
        if backtrack_repair is not None:
            logger.info(f"  Applying repair location backtracking (max {backtrack_repair} levels)")
            new_candidates = []
            for pair in candidates:
                func = pair['abnormal']['function']
                call_stack = pair['abnormal'].get('call_stack', [])

                new_pair = determine_repair_location(self.llm_client, pair, backtrack_repair, return_debug_info=True)

                debug_info = new_pair.pop('_backtrack_debug', {})
                additional_llm_calls['backtrack_calls'].append({
                    'function_name': func.get('name'),
                    'call_stack_depth': len(call_stack),
                    'prompt': debug_info.get('prompt', ''),
                    'input': debug_info.get('input', ''),
                    'response': debug_info.get('response', '')
                })

                new_candidates.append(new_pair)

            candidates = new_candidates

        # 3. Batch judgment filtering
        batch_judge_response = ''
        if filter_irrelevant:
            logger.info("  Applying batch judgment filtering")
            judgment = batch_judge_repairs(self.llm_client, candidates, return_debug_info=True)
            needs_repair_set = set(judgment.get('needs_repair', []))

            debug_info = judgment.get('_debug', {})
            additional_llm_calls['batch_judge_call'] = {
                'description': f"Judged {len(candidates)} candidate functions",
                'prompt': debug_info.get('prompt', ''),
                'input': debug_info.get('input', ''),
                'response': debug_info.get('response', '')
            }

            filtered = []
            for pair in candidates:
                func_name = pair['abnormal']['function']['name']
                if func_name in needs_repair_set:
                    filtered.append(pair)
                else:
                    logger.info(f"    Skipped: {func_name} (batch judgment: no repair needed)")

            file_stats["skipped_batch_judgment"] = len(candidates) - len(filtered)
            candidates = filtered

        if not candidates:
            logger.info(f"  No functions need repair after filtering")
            file_stats["candidates_after_batch_judgment"] = 0
            return file_stats

        file_stats["candidates_after_batch_judgment"] = len(candidates)

        # 4. Generate repair code
        repairs = []
        for pair in candidates:
            repair = self._generate_repair(pair, additional_llm_calls)
            repair["candidate_filter_stats"] = file_stats
            repairs.append(repair)

        # 5. Save results
        output_file = self.output_dir / json_file.name.replace('_pairs.json', '_repairs.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(repairs, f, ensure_ascii=False, indent=2)

        success_count = sum(1 for r in repairs if r.get('success'))
        file_stats["repairs_generated"] = len(repairs)
        file_stats["repairs_success"] = success_count
        file_stats["output_file"] = str(output_file)
        logger.info(f"  Saved to: {output_file} ({success_count}/{len(repairs)} succeeded)")
        return file_stats

    def _filter_candidates(self, pairs: list, threshold: float, return_stats: bool = False) -> list:
        """Filter candidate functions"""
        candidates = []
        seen_functions = set()  # For deduplication: (function_name, def_path)
        stats = {
            "skipped_below_threshold": 0,
            "skipped_no_source": 0,
            "skipped_no_syscalls": 0,
            "skipped_duplicate": 0,
        }

        for pair in pairs:
            score = pair.get('normalized_score', 0)
            if score <= threshold:
                stats["skipped_below_threshold"] += 1
                continue

            func = pair['abnormal']['function']
            if not func.get('source_code'):
                logger.info(f"  Skipped {func['name']}: no source code")
                stats["skipped_no_source"] += 1
                continue

            syscalls = func.get('full_syscalls', func.get('syscalls', []))
            if len(syscalls) < 1:
                logger.info(f"  Skipped {func['name']}: no syscalls")
                stats["skipped_no_syscalls"] += 1
                continue

            # Deduplication: keep only the first occurrence of each function (usually the highest score)
            func_key = (func['name'], func.get('def_path', ''))
            if func_key in seen_functions:
                logger.debug(f"  Skipped {func['name']}: duplicate function")
                stats["skipped_duplicate"] += 1
                continue
            seen_functions.add(func_key)

            candidates.append(pair)

        if return_stats:
            return candidates, stats
        return candidates

    def _determine_repair_method(self, pair: dict) -> tuple[str, dict]:
        """Determine the repair method

        Prioritizes config-specified method, otherwise calls LLM to decide

        Args:
            pair: Function pair

        Returns:
            (repair_method, debug_info_dict)
            - repair_method: "syscall" or "network" or "direct"
            - debug_info_dict: Contains source, prompt, input, response fields
        """
        if self.repair_mode == "direct":
            return "direct", {
                'source': "Direct repair mode: no judgment needed",
                'prompt': '',
                'input': '',
                'response': ''
            }

        if self.cve.repair_method in ("syscall", "network"):
            return self.cve.repair_method, {
                'source': f"Config-specified: {self.cve.repair_method}",
                'prompt': '',
                'input': '',
                'response': ''
            }

        result, debug_info = judge_repair_method(self.llm_client, pair, return_debug_info=True)
        return result, {
            'source': f"LLM judgment: {result}",
            'prompt': debug_info.get('prompt', ''),
            'input': debug_info.get('input', ''),
            'response': debug_info.get('response', '')
        }

    def _generate_repair(self, pair: dict, additional_llm_calls: dict = None) -> dict:
        """Generate repair code for a single function"""
        func = pair['abnormal']['function']
        func_name = func['name']
        func_def_path = func.get('def_path', '')

        if additional_llm_calls is None:
            additional_llm_calls = {
                'backtrack_calls': [],
                'batch_judge_call': '',
            }

        repair_method, method_debug_info = self._determine_repair_method(pair)
        additional_llm_calls['repair_method_decision'] = method_debug_info

        include_raw_syscalls = False
        if self.whitelist_mode == "llm" and repair_method == "syscall":
            key = (func_name, func_def_path)
            normal_samples = self.normal_samples_db.get(key, [])
            if normal_samples:
                pair['normal_samples'] = normal_samples
                include_raw_syscalls = True
                logger.info(f"  Generating repair: {func_name} (method: {repair_method}, whitelist: LLM direct generation, normal samples: {len(normal_samples)})")
            else:
                logger.warning(f"  No normal samples found, falling back to placeholder mode")
                logger.info(f"  Generating repair: {func_name} (method: {repair_method}, mode: {self.repair_mode})")
        else:
            logger.info(f"  Generating repair: {func_name} (method: {repair_method}, mode: {self.repair_mode})")

        prompt = get_repair_prompt(self.cve.language, repair_method, self.repair_mode,
                                   whitelist_mode=self.whitelist_mode if include_raw_syscalls else "static")
        input_text = format_llm_input(pair, include_raw_syscalls=include_raw_syscalls)

        if self.feedback_context:
            input_text = (
                f"{input_text}\n\n"
                "=== Previous validation feedback ===\n"
                "The previous repair was applied and validated, but it did not pass. "
                "Use this feedback to generate a different or corrected repair. "
                "Do not repeat the same failed placement or strategy if the feedback shows why it failed.\n"
                f"{self.feedback_context}\n"
                "=== End previous validation feedback ===\n"
            )

        response = call_llm(self.llm_client, prompt, input_text)

        if not response:
            logger.error(f"    LLM call failed")
            return self._create_repair_result(pair, None, False, "LLM call failed", repair_method, additional_llm_calls)

        repair_code = extract_code_block(response)

        if not repair_code:
            logger.warning(f"    Unable to extract code block")
            return self._create_repair_result(pair, None, False, "Unable to extract code block", repair_method, additional_llm_calls)

        if repair_method == "syscall":
            if self.whitelist_mode == "llm" and include_raw_syscalls:
                if 'syscall_filter' not in repair_code.lower():
                    logger.warning(f"    Repair code does not contain syscall_filter call")
            else:
                if '$WHITELIST$' not in repair_code:
                    logger.warning(f"    Repair code does not contain $WHITELIST$ placeholder")
        elif repair_method == "network":
            if 'net_filter' not in repair_code.lower():
                logger.warning(f"    Repair code does not contain net_filter call")

        logger.info(f"    Success ({len(repair_code.split(chr(10)))} lines)")

        return self._create_repair_result(pair, repair_code, True, response, repair_method, additional_llm_calls)

    def _create_repair_result(
        self,
        pair: dict,
        repair_code: str | None,
        success: bool,
        analysis: str,
        repair_method: str = "syscall",
        additional_llm_calls: dict = None,
    ) -> dict:
        """Create a repair result"""
        func = pair['abnormal']['function']

        if additional_llm_calls is None:
            additional_llm_calls = {
                'backtrack_calls': [],
                'batch_judge_call': '',
                'repair_method_decision': '',
            }

        return {
            'function_name': func['name'],
            'function_path': func.get('def_path'),
            'start_line': func.get('def_start'),
            'end_line': func.get('def_end'),
            'indent_level': func.get('indent_level', 0),
            'repair_code': repair_code,
            'success': success,
            'analysis': analysis,
            'repair_method': repair_method,
            'function_pair': pair,
            'additional_llm_calls': additional_llm_calls,
            'feedback_attempt': self.feedback_attempt,
            'feedback_context': self.feedback_context,
        }
