#!/usr/bin/env python3
"""
Extensible anomaly detection framework
Supports combined detection using multiple similarity algorithms
"""

import json
import logging
import sys
from pathlib import Path
import argparse
from collections import defaultdict
from typing import Dict, List, Tuple
from abc import ABC, abstractmethod
from tqdm import tqdm

logger = logging.getLogger(__name__)


# ============================================================================
# 1. Similarity Algorithm Interface
# ============================================================================

class SimilarityAlgorithm(ABC):
    """Base class for similarity algorithms"""

    @abstractmethod
    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        """
        Compute similarity between abnormal and normal samples

        Args:
            abnormal_entry: Full data of the abnormal function call
            normal_entry: Full data of the normal function call

        Returns:
            float: Similarity [0, 1], 1 = identical, 0 = completely different
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return algorithm name"""
        pass


# ============================================================================
# 2. Algorithm Implementations
# ============================================================================

class JaccardSyscallAlgorithm(SimilarityAlgorithm):
    """Jaccard-based syscall set similarity"""

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_syscalls = self._extract_syscall_types(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_syscalls = self._extract_syscall_types(normal_entry.get('function', {}).get('syscalls', []))

        set1 = set(abnormal_syscalls)
        set2 = set(normal_syscalls)

        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        return len(intersection) / len(union)

    def get_name(self) -> str:
        return "jaccard_syscall"

    def _extract_syscall_types(self, syscalls):
        types = []
        for sc in syscalls:
            if isinstance(sc, str):
                types.append(sc)
            elif isinstance(sc, dict):
                types.append(sc.get('type', 'unknown'))
        return types


class DistinctIPCountAlgorithm(SimilarityAlgorithm):
    """Distinct IP count based network behavior anomaly detection

    Counts distinct destination IPs accessed by a function and computes
    similarity by comparing count differences.
    Useful for detecting abnormal network scanning or SSRF attacks.

    fd.name format: '172.25.0.1:42092->172.25.0.3:80'
    Relevant syscalls: connect, recvfrom, sendto, close
    """

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_ips = self._extract_distinct_ips(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_ips = self._extract_distinct_ips(normal_entry.get('function', {}).get('syscalls', []))

        abnormal_count = len(abnormal_ips)
        normal_count = len(normal_ips)

        if abnormal_count == 0 and normal_count == 0:
            return 1.0

        if abnormal_count == 0 or normal_count == 0:
            return 0.0

        return min(abnormal_count, normal_count) / max(abnormal_count, normal_count)

    def get_name(self) -> str:
        return "distinct_ip_count"

    def _extract_all_ips(self, fd_name: str) -> list:
        """Extract all IPs (source and destination) from fd.name

        Format: '172.25.0.1:42092->172.25.0.3:80'
        Returns: ['172.25.0.1', '172.25.0.3']
        """
        if '->' not in fd_name:
            return []
        try:
            parts = fd_name.split('->')
            src_ip = parts[0].split(':')[0]
            dest_ip = parts[1].split(':')[0]
            return [src_ip, dest_ip]
        except:
            return []

    def _extract_distinct_ips(self, syscalls: List) -> set:
        """Extract all distinct IPs (source + destination)"""
        network_syscalls = ['connect', 'recvfrom', 'sendto', 'close']
        distinct_ips = set()

        for sc in syscalls:
            if isinstance(sc, dict):
                syscall_type = sc.get('type', '')
                fd_name = sc.get('fd.name', '')

                if syscall_type in network_syscalls and fd_name and '->' in fd_name:
                    ips = self._extract_all_ips(fd_name)
                    distinct_ips.update(ips)

        return distinct_ips


class DistinctPortCountAlgorithm(SimilarityAlgorithm):
    """Distinct port count based network behavior anomaly detection

    Counts distinct destination ports accessed by a function and computes
    similarity by comparing count differences.
    Useful for detecting port scanning or abnormal service access.

    fd.name format: '172.25.0.1:42092->172.25.0.3:80'
    Relevant syscalls: connect, recvfrom, sendto, close
    """

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_ports = self._extract_distinct_ports(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_ports = self._extract_distinct_ports(normal_entry.get('function', {}).get('syscalls', []))

        abnormal_count = len(abnormal_ports)
        normal_count = len(normal_ports)

        if abnormal_count == 0 and normal_count == 0:
            return 1.0

        if abnormal_count == 0 or normal_count == 0:
            return 0.0

        return min(abnormal_count, normal_count) / max(abnormal_count, normal_count)

    def get_name(self) -> str:
        return "distinct_port_count"

    def _extract_all_ports(self, fd_name: str) -> list:
        """Extract all ports (source and destination) from fd.name

        Format: '172.25.0.1:42092->172.25.0.3:80'
        Returns: ['42092', '80']
        """
        if '->' not in fd_name:
            return []
        try:
            parts = fd_name.split('->')
            src_port = parts[0].split(':')[1]
            dest_port = parts[1].split(':')[1]
            return [src_port, dest_port]
        except:
            return []

    def _extract_distinct_ports(self, syscalls: List) -> set:
        """Extract all distinct ports (source + destination)"""
        network_syscalls = ['connect', 'recvfrom', 'sendto', 'close']
        distinct_ports = set()

        for sc in syscalls:
            if isinstance(sc, dict):
                syscall_type = sc.get('type', '')
                fd_name = sc.get('fd.name', '')

                if syscall_type in network_syscalls and fd_name and '->' in fd_name:
                    ports = self._extract_all_ports(fd_name)
                    distinct_ports.update(ports)

        return distinct_ports


class NGramSyscallAlgorithm(SimilarityAlgorithm):
    """N-gram based syscall sequence similarity (n=3)"""

    def __init__(self):
        self.n = 3

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_seq = self._extract_syscall_types(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_seq = self._extract_syscall_types(normal_entry.get('function', {}).get('syscalls', []))

        ngrams1 = self._extract_ngrams(abnormal_seq)
        ngrams2 = self._extract_ngrams(normal_seq)

        return self._cosine_similarity(ngrams1, ngrams2)

    def get_name(self) -> str:
        return "ngram_2_syscall"

    def _extract_syscall_types(self, syscalls):
        types = []
        for sc in syscalls:
            if isinstance(sc, str):
                types.append(sc)
            elif isinstance(sc, dict):
                types.append(sc.get('type', 'unknown'))
        return types

    def _extract_ngrams(self, seq: List) -> Dict[tuple, int]:
        """Extract n-gram frequencies"""
        if len(seq) < self.n:
            return {tuple(seq): 1} if seq else {}

        ngrams = {}
        for i in range(len(seq) - self.n + 1):
            gram = tuple(seq[i:i+self.n])
            ngrams[gram] = ngrams.get(gram, 0) + 1
        return ngrams

    def _cosine_similarity(self, ngrams1: Dict, ngrams2: Dict) -> float:
        """Compute cosine similarity"""
        all_grams = set(ngrams1.keys()) | set(ngrams2.keys())
        if not all_grams:
            return 1.0

        dot_product = sum(
            ngrams1.get(g, 0) * ngrams2.get(g, 0)
            for g in all_grams
        )

        norm1 = sum(v**2 for v in ngrams1.values()) ** 0.5
        norm2 = sum(v**2 for v in ngrams2.values()) ** 0.5

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot_product / (norm1 * norm2)


class JaccardFileAccessAlgorithm(SimilarityAlgorithm):
    """Jaccard-based file access set similarity

    Extracts all file names (fd.name) accessed by a function and computes
    Jaccard similarity. Useful for detecting abnormal file access patterns.
    """

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_files = self._extract_file_names(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_files = self._extract_file_names(normal_entry.get('function', {}).get('syscalls', []))

        set1 = set(abnormal_files)
        set2 = set(normal_files)

        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        return len(intersection) / len(union)

    def get_name(self) -> str:
        return "jaccard_file"

    def _extract_file_names(self, syscalls: List) -> List[str]:
        """Extract all file names (fd.name field), excluding network connections"""
        file_names = []
        for sc in syscalls:
            if isinstance(sc, dict):
                fd_name = sc.get('fd.name', '')
                if fd_name and '->' not in fd_name:
                    file_names.append(fd_name)
        return file_names


class InternalNetworkAlgorithm(SimilarityAlgorithm):
    """Internal network access based anomaly detection

    Detects whether a function accesses internal IPs (SSRF indicator):
    - Only flags as anomaly when abnormal accesses internal network but normal does not
    - All other cases (both access, neither access, or only normal accesses) are considered normal

    Note: Only checks the function's own syscalls, not the full call stack (full_syscalls)
    """

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_internal = self._has_internal_network_access(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_internal = self._has_internal_network_access(normal_entry.get('function', {}).get('syscalls', []))

        # Only flag when abnormal accesses internal network but normal does not
        # This avoids false positives when normal requests also access internal services (e.g. database)
        if abnormal_internal and not normal_internal:
            return 0.0
        else:
            return 1.0

    def get_name(self) -> str:
        return "internal_network"

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is an RFC 1918 private address"""
        if ip.startswith('10.'):
            return True
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
                except:
                    pass
        if ip.startswith('192.168.'):
            return True
        return False

    def _extract_dest_ip(self, fd_name: str) -> str:
        """Extract destination IP from fd.name

        Format: '192.168.144.2:51512->192.168.144.3:80'
        Returns: '192.168.144.3'
        """
        if '->' not in fd_name:
            return None
        try:
            dest = fd_name.split('->')[1]
            ip = dest.split(':')[0]
            return ip
        except:
            return None

    def _has_internal_network_access(self, syscalls: List) -> bool:
        """Check if syscalls contain internal network access"""
        network_syscalls = ['sendto', 'recvfrom', 'connect', 'sendmsg', 'recvmsg']

        for sc in syscalls:
            if isinstance(sc, dict):
                syscall_type = sc.get('type', '')
                fd_name = sc.get('fd.name', '')

                if syscall_type in network_syscalls and fd_name:
                    dest_ip = self._extract_dest_ip(fd_name)
                    if dest_ip and self._is_internal_ip(dest_ip):
                        return True
        return False


class JaccardProcessPathAlgorithm(SimilarityAlgorithm):
    """Jaccard-based process path set similarity

    Extracts all process paths (evt.arg.filename) executed by a function and
    computes Jaccard similarity. Useful for detecting abnormal process execution.
    """

    def compute_similarity(self, abnormal_entry: Dict, normal_entry: Dict) -> float:
        abnormal_procs = self._extract_process_paths(abnormal_entry.get('function', {}).get('syscalls', []))
        normal_procs = self._extract_process_paths(normal_entry.get('function', {}).get('syscalls', []))

        set1 = set(abnormal_procs)
        set2 = set(normal_procs)

        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        return len(intersection) / len(union)

    def get_name(self) -> str:
        return "jaccard_proc"

    def _extract_process_paths(self, syscalls: List) -> List[str]:
        """Extract all process paths (evt.arg.filename), only from execve/execveat"""
        proc_paths = []
        for sc in syscalls:
            if isinstance(sc, dict):
                syscall_type = sc.get('type', '')
                if syscall_type in ['execve', 'execveat']:
                    exepath = sc.get('evt.arg.filename', '')
                    if exepath:
                        proc_paths.append(exepath)
        return proc_paths


# ============================================================================
# 3. Extensible Anomaly Detector
# ============================================================================

class ExtensibleAnomalyDetector:
    """Extensible anomaly detector"""

    def __init__(self, algorithms: List[SimilarityAlgorithm]):
        self.algorithms = algorithms
        self.normal_samples = defaultdict(list)
        # Index signatures by function name to avoid O(N) linear search
        self.signatures_by_func = defaultdict(list)
        self.last_detection_stats = {}

    def load_json_file(self, filepath):
        """Load JSON file, returns None on failure"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping corrupted JSON file {filepath}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to load file {filepath}: {e}")
            return None

    def get_function_signature(self, entry):
        """Generate function signature"""
        func_name = entry['function']['name']
        call_stack = tuple(
            (f['name'], f['path'], f['line'])
            for f in entry['call_stack']
        )
        return (func_name, call_stack)

    def load_normal_samples(self, stack_dir):
        """Load normal samples"""
        stack_path = Path(stack_dir)
        normal_files = sorted(stack_path.glob("normal_*.json"))

        if not normal_files:
            logger.warning(f"No normal_*.json files found in {stack_dir}")
            return

        skipped = 0
        for normal_file in normal_files:
            entries = self.load_json_file(normal_file)
            if entries is None:
                skipped += 1
                continue
            for entry in entries:
                signature = self.get_function_signature(entry)
                self.normal_samples[signature].append(entry)

        if skipped > 0:
            logger.warning(f"Skipped {skipped} corrupted files")

        # Build signature index by function name
        self.signatures_by_func.clear()
        for sig in self.normal_samples.keys():
            func_name, _ = sig
            self.signatures_by_func[func_name].append(sig)

        logger.info(f"Loaded {len(normal_files)} normal files, {len(self.normal_samples)} function signatures")

        total_normal = sum(len(samples) for samples in self.normal_samples.values())
        logger.info(f"Total {total_normal} normal function samples")

    def calculate_callstack_similarity(self, stack1, stack2) -> Tuple[float, int]:
        """
        Calculate call stack similarity (matching from top to bottom)

        Matches from stack top (current function) toward stack bottom (outermost caller),
        stops at first mismatch.

        Args:
            stack1: First call stack, format [(func_name, file_path, line), ...]
                   Stack structure: [A, B, C, D, E] where A=bottom(outermost), E=top(current)
            stack2: Second call stack

        Returns:
            (similarity, matched_count)

        Example:
            stack1: [A, B, C, D, E]  (A=bottom, E=top)
            stack2: [X, Y, C, D, E]

            Top-down matching:
            - E == E, D == D, C == C, B != Y (stop)
            matched_count: 3, similarity: 3/5 = 0.6
        """
        funcs1 = [f[0] for f in stack1][::-1]
        funcs2 = [f[0] for f in stack2][::-1]

        matched_count = 0
        min_len = min(len(funcs1), len(funcs2))

        for i in range(min_len):
            if funcs1[i] == funcs2[i]:
                matched_count += 1
            else:
                break

        max_len = max(len(funcs1), len(funcs2))
        if max_len == 0:
            return 1.0, 0

        similarity = matched_count / max_len
        return similarity, matched_count

    def find_similar_by_callstack(
        self,
        target_signature: Tuple,
        top_k: int = 5
    ) -> List[Tuple]:
        """
        Find top-k signatures with the most similar call stacks

        Args:
            target_signature: (func_name, callstack)
            top_k: Return top k results

        Returns:
            [(signature, similarity), ...] sorted by similarity descending
        """
        target_func_name, target_stack = target_signature

        same_name_sigs = self.signatures_by_func.get(target_func_name, [])
        if not same_name_sigs:
            return []

        candidates = []
        for sig in same_name_sigs:
            _, stack = sig
            similarity, matched_count = self.calculate_callstack_similarity(target_stack, stack)
            candidates.append((sig, similarity))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]

    def find_best_normal_match(
        self,
        abnormal_entry: Dict,
        candidate_normals: List[Dict],
        max_samples: int = 50
    ) -> Tuple[Dict, Dict[str, float]]:
        """
        Find the best matching normal sample from candidates

        Args:
            abnormal_entry: Abnormal function entry
            candidate_normals: Candidate normal sample list
            max_samples: Max samples to compare (random sample if exceeded)

        Returns:
            (best_normal_entry, raw_anomaly_scores)
        """
        if not candidate_normals:
            return None, {algo.get_name(): 1.0 for algo in self.algorithms}

        import random
        if len(candidate_normals) > max_samples:
            candidate_normals = random.sample(candidate_normals, max_samples)

        best_normal = None
        best_raw_scores = None
        min_avg_raw = float('inf')

        for normal in candidate_normals:
            raw_scores = {}
            for algo in self.algorithms:
                similarity = algo.compute_similarity(abnormal_entry, normal)
                raw_scores[algo.get_name()] = 1.0 - similarity  # Convert to anomaly score

            avg_raw = sum(raw_scores.values()) / len(raw_scores)

            # Select the one with lowest anomaly score (most similar)
            if avg_raw < min_avg_raw:
                min_avg_raw = avg_raw
                best_normal = normal
                best_raw_scores = raw_scores

        return best_normal, best_raw_scores

    def normalize_scores(
        self,
        all_raw_scores: List[Dict[str, float]]
    ) -> List[float]:
        """
        Normalize scores across all function pairs and compute final scores

        Args:
            all_raw_scores: [{'jaccard': 0.3, 'ngram': 0.5}, ...]

        Returns:
            [final_score_1, final_score_2, ...] normalized to [0, 1]
        """
        if not all_raw_scores:
            return []

        # 1. Compute max per algorithm dimension
        algo_names = list(all_raw_scores[0].keys())
        max_per_algo = {}

        eps = 1e-9
        for algo_name in algo_names:
            max_val = max(scores[algo_name] for scores in all_raw_scores)
            max_per_algo[algo_name] = max_val if max_val > eps else 1.0

        # 2. Normalize per dimension and average
        avg_scores = []
        for raw_scores in all_raw_scores:
            normalized = {}
            for algo_name, raw_score in raw_scores.items():
                normalized[algo_name] = raw_score / max_per_algo[algo_name]

            avg_score = sum(normalized.values()) / len(normalized)
            avg_scores.append(avg_score)

        # 3. Re-normalize averaged scores to [0, 1]
        min_score = min(avg_scores)
        max_score = max(avg_scores)

        if max_score - min_score < 1e-9:
            return avg_scores

        final_scores = [
            (score - min_score) / (max_score - min_score)
            for score in avg_scores
        ]

        return final_scores

    def detect_and_create_pairs(
        self,
        stack_dir,
        anomaly_filename,
        top_k=10,
        match_k=5,
        use_attack_flag=True
    ):
        """
        Detect anomalies and create function pairs

        Args:
            stack_dir: Data directory
            anomaly_filename: Anomaly file name
            top_k: Return top K results
            match_k: Match top K most similar call stacks
            use_attack_flag: Whether to use X-Attack-Flag to distinguish normal/malicious requests

        Returns:
            Sorted list of function pairs
        """
        anomaly_file = Path(stack_dir) / anomaly_filename

        if not anomaly_file.exists():
            logger.error(f"Anomaly file {anomaly_file} does not exist")
            return None

        anomaly_entries = self.load_json_file(anomaly_file)
        if anomaly_entries is None:
            logger.warning(f"Skipping corrupted anomaly file {anomaly_file}")
            return None
        logger.info(f"Loaded {len(anomaly_entries)} abnormal function calls, matching top {match_k} similar call stacks")
        logger.info(f"Using {len(self.algorithms)} algorithms: {[algo.get_name() for algo in self.algorithms]}")

        self.last_detection_stats = {
            "file": anomaly_filename,
            "raw_abnormal_entries": len(anomaly_entries),
            "use_attack_flag": use_attack_flag,
            "contains_attack_flag": None,
            "skipped_no_attack_flag": False,
            "matched_with_normal_before_filter": 0,
            "matched_with_normal_after_filter": 0,
            "dropped_no_normal_match": 0,
            "output_top_k": top_k,
            "output_pairs": 0,
            "avg_normal_candidates_per_abnormal": 0.0,
            "timing": {
                "get_signature": 0.0,
                "find_similar_callstack": 0.0,
                "collect_normal_candidates": 0.0,
                "find_best_normal": 0.0,
            },
        }

        # Phase 0: Check for attack flag (only when use_attack_flag=True)
        if use_attack_flag:
            has_attack_flag = any('X-Attack-Flag' in (entry.get('payload') or '') for entry in anomaly_entries)
            logger.info(f"Raw anomaly entries: {len(anomaly_entries)}, contains X-Attack-Flag: {'yes' if has_attack_flag else 'no'}")
            self.last_detection_stats["contains_attack_flag"] = has_attack_flag

            if not has_attack_flag:
                logger.info("No requests with X-Attack-Flag found, skipping this file")
                self.last_detection_stats["skipped_no_attack_flag"] = True
                return None
        else:
            logger.info(f"Raw anomaly entries: {len(anomaly_entries)} (not using X-Attack-Flag)")

        # Phase 1: Compute raw scores
        temp_results = []
        all_raw_scores = []

        import time
        debug_count = 0
        debug_interval = 10000
        total_time_get_sig = 0
        total_time_find_similar = 0
        total_time_collect = 0
        total_time_find_best = 0
        total_candidates = 0

        for abnormal in tqdm(anomaly_entries, desc="Processing anomalies"):
            t0 = time.time()

            signature = self.get_function_signature(abnormal)
            t1 = time.time()

            similar_sigs = self.find_similar_by_callstack(signature, match_k)
            t2 = time.time()

            candidates = []
            if similar_sigs:
                for sig, _ in similar_sigs:
                    candidates.extend(self.normal_samples[sig])
            t3 = time.time()

            best_normal, raw_scores = self.find_best_normal_match(
                abnormal,
                candidates
            )
            t4 = time.time()

            total_time_get_sig += t1 - t0
            total_time_find_similar += t2 - t1
            total_time_collect += t3 - t2
            total_time_find_best += t4 - t3
            total_candidates += len(candidates)
            debug_count += 1

            if debug_count % debug_interval == 0:
                logger.info(f"[DEBUG cumulative #{debug_count}] avg candidates={total_candidates/debug_count:.1f}")
                logger.info(f"  cumulative time: get_sig={total_time_get_sig:.2f}s, find_similar={total_time_find_similar:.2f}s, collect={total_time_collect:.2f}s, find_best={total_time_find_best:.2f}s")
                logger.info(f"  ratio: get_sig={total_time_get_sig/(t4-t0+0.001)*100:.1f}%, find_similar={total_time_find_similar/(total_time_get_sig+total_time_find_similar+total_time_collect+total_time_find_best)*100:.1f}%, collect={total_time_collect/(total_time_get_sig+total_time_find_similar+total_time_collect+total_time_find_best)*100:.1f}%, find_best={total_time_find_best/(total_time_get_sig+total_time_find_similar+total_time_collect+total_time_find_best)*100:.1f}%")

            temp_results.append({
                'abnormal': abnormal,
                'normal': best_normal,
                'raw_scores': raw_scores
            })
            all_raw_scores.append(raw_scores)

        # Filter: keep only functions that appear in both normal and abnormal scenarios
        filtered_results = []
        filtered_raw_scores = []

        for i, result in enumerate(temp_results):
            if result['normal'] is not None:
                filtered_results.append(result)
                filtered_raw_scores.append(all_raw_scores[i])

        logger.info(f"Before filtering: {len(temp_results)} functions, after: {len(filtered_results)}")
        self.last_detection_stats.update({
            "matched_with_normal_before_filter": len(temp_results),
            "matched_with_normal_after_filter": len(filtered_results),
            "dropped_no_normal_match": len(temp_results) - len(filtered_results),
            "avg_normal_candidates_per_abnormal": (
                total_candidates / debug_count if debug_count else 0.0
            ),
            "timing": {
                "get_signature": total_time_get_sig,
                "find_similar_callstack": total_time_find_similar,
                "collect_normal_candidates": total_time_collect,
                "find_best_normal": total_time_find_best,
            },
        })

        if not filtered_results:
            logger.warning("No functions found in both normal and abnormal scenarios")
            return []

        # Phase 2: Normalize (only filtered functions)
        normalized_scores = self.normalize_scores(filtered_raw_scores)

        final_results = []
        for i, result in enumerate(filtered_results):
            similarities = {
                algo: 1 - result['raw_scores'][algo]
                for algo in result['raw_scores']
            }

            final_results.append({
                'abnormal': result['abnormal'],
                'normal': result['normal'],
                'raw_scores': result['raw_scores'],
                'normalized_score': normalized_scores[i],
                'similarities': similarities
            })

        final_results.sort(key=lambda x: x['normalized_score'], reverse=True)
        self.last_detection_stats["output_pairs"] = len(final_results[:top_k])

        return final_results[:top_k]

    def run_detection(self, cve, top_k: int = 10) -> bool:
        """
        Run anomaly detection for a specific CVE (main entry point)

        Args:
            cve: CVEConfig object
            top_k: Output top K results

        Returns:
            bool: Whether detection succeeded
        """
        try:
            input_dir = cve.data_dir / "callstack_with_code"
            output_dir = cve.data_dir / "detect"

            output_dir.mkdir(parents=True, exist_ok=True)

            malicious_files = list(input_dir.glob("malicious*.json"))

            if not malicious_files:
                logger.error(f"No malicious*.json files found in {input_dir}")
                return False

            logger.info(f"Found {len(malicious_files)} malicious files")

            self.load_normal_samples(input_dir)

            if not self.normal_samples:
                logger.warning("No normal samples found, will only output abnormal functions")

            total_pairs = 0
            stats = {
                "stage": 7,
                "input_dir": str(input_dir),
                "malicious_files": len(malicious_files),
                "normal_function_signatures": len(self.normal_samples),
                "normal_function_samples": sum(len(samples) for samples in self.normal_samples.values()),
                "top_k": top_k,
                "files": [],
                "total_output_pairs": 0,
            }

            for malicious_file in sorted(malicious_files):
                logger.info(f"Processing file: {malicious_file.name}")

                function_pairs = self.detect_and_create_pairs(
                    input_dir,
                    malicious_file.name,
                    top_k=top_k,
                    use_attack_flag=cve.use_attack_flag
                )
                file_stats = dict(self.last_detection_stats)

                if function_pairs:
                    output_file = output_dir / f"{malicious_file.stem}_pairs.json"

                    output_data = []
                    for idx, pair in enumerate(function_pairs, 1):
                        func_name = pair['abnormal']['function']['name']
                        score = pair['normalized_score']

                        logger.info(f"{idx}. {func_name}: score={score:.3f}")

                        output_pair = {
                            'rank': idx,
                            'normalized_score': pair['normalized_score'],
                            'raw_scores': pair['raw_scores'],
                            'similarities': pair['similarities'],
                            'abnormal': pair['abnormal'],
                            'normal': pair['normal']
                        }
                        output_data.append(output_pair)

                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(output_data, f, ensure_ascii=False)

                    logger.info(f"Generated {len(function_pairs)} function pairs -> {output_file.name}")
                    total_pairs += len(function_pairs)
                    file_stats["output_file"] = str(output_file)

                else:
                    logger.info(f"No anomalous function pairs found in {malicious_file.name}")

                stats["files"].append(file_stats)

            stats["total_output_pairs"] = total_pairs
            stats_file = output_dir / "detect_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            logger.info(f"Detection stats saved to: {stats_file}")
            logger.info(f"Anomaly detection complete: {len(malicious_files)} files, {total_pairs} function pairs")

            return True

        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            import traceback
            traceback.print_exc()
            return False


# ============================================================================
# 4. CLI Entry Point
# ============================================================================

def create_detector(algo_list: List[str]) -> ExtensibleAnomalyDetector:
    """Create detector from algorithm list"""
    algorithms = []

    if 'all' in algo_list:
        algorithms = [
            JaccardSyscallAlgorithm(),
            NGramSyscallAlgorithm(),
            DistinctIPCountAlgorithm(),
            DistinctPortCountAlgorithm(),
            JaccardFileAccessAlgorithm(),
            JaccardProcessPathAlgorithm(),
            InternalNetworkAlgorithm(),
        ]
    else:
        for algo_spec in algo_list:
            if algo_spec == 'jaccard':
                algorithms.append(JaccardSyscallAlgorithm())
            elif algo_spec == 'ngram':
                algorithms.append(NGramSyscallAlgorithm())
            elif algo_spec == 'n_ips':
                algorithms.append(DistinctIPCountAlgorithm())
            elif algo_spec == 'n_ports':
                algorithms.append(DistinctPortCountAlgorithm())
            elif algo_spec == 'file':
                algorithms.append(JaccardFileAccessAlgorithm())
            elif algo_spec == 'proc':
                algorithms.append(JaccardProcessPathAlgorithm())
            elif algo_spec == 'internal':
                algorithms.append(InternalNetworkAlgorithm())
            else:
                raise ValueError(f"Unknown algorithm: {algo_spec}")

    return ExtensibleAnomalyDetector(algorithms=algorithms)


if __name__ == "__main__":
    from config import load_cve_config

    parser = argparse.ArgumentParser(
        description='Extensible anomaly detection framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 detect.py --cve CVE-2015-8562 --algo jaccard
  python3 detect.py --cve CVE-2015-8562 --algo jaccard ngram
  python3 detect.py --cve CVE-2015-8562 --algo jaccard ngram --top 20

Algorithms:
  all          - Use all detection algorithms
  jaccard      - Jaccard syscall set similarity
  ngram        - 3-gram syscall sequence similarity
  n_ips        - Distinct IP count detection
  n_ports      - Distinct port count detection
  file         - Jaccard file name set similarity
  proc         - Jaccard process path set similarity
  internal     - Internal network access detection (SSRF indicator)
        """
    )
    parser.add_argument('--cve', required=True, help='CVE number')
    parser.add_argument('--algo', nargs='+', default=['all'],
                        help='Algorithm list (options: all, jaccard, ngram, n_ips, n_ports, file, proc, internal)')
    parser.add_argument('--top', type=int, default=10,
                        help='Output top N results (default: 10)')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    cve = load_cve_config(args.cve)
    detector = create_detector(args.algo)
    success = detector.run_detection(cve, args.top)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)
