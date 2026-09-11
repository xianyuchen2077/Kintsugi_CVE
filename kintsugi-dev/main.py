"""
Pipeline entry point
"""
import json
import argparse
import logging
import shutil
import subprocess
import time
from pathlib import Path
from datetime import datetime

from config import load_cve_config, list_cves, CVEConfig

from stages.collect import TrafficCollector
from stages.parse import parse_sysdig
from stages.segment import split_units
from stages.callstack import process_callstack
from stages.extract_code import extract_source_code
from stages.detect import create_detector
from stages.build import build_plugins

from stages.repair import RepairGenerator
from stages.whitelist import WhitelistFiller
from stages.validate import RepairValidator

logger = logging.getLogger(__name__)


STAGES = {
    0:  ("up",          "Start containers (docker compose up)"),
    1:  ("build",       "Build and install plugins (stack_tracer, syscall_filter, net_filter)"),
    2:  ("collect",     "Collect normal/malicious traffic (sysdig + locust)"),
    3:  ("parse",       "Convert sysdig logs to JSON"),
    4:  ("segment",     "Segment by request units"),
    5:  ("callstack",   "Extract call stacks"),
    6:  ("extract",     "Extract source code from container"),
    7:  ("detect",      "Anomaly detection (jaccard, ngram, etc.)"),
    8:  ("repair",      "Generate repair code (empty filter)"),
    9:  ("whitelist",   "Static analysis to populate whitelist"),
    10: ("validate",    "Restart container and validate repair"),
    11: ("down",        "Stop containers (docker compose down)"),
}


def setup_logging(level: str = "INFO", log_file: str = None, log_mode: str = "a"):
    handlers = [logging.StreamHandler()]
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, mode=log_mode, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )


def get_stages_help() -> str:
    lines = ["Stages:"]
    for num, (name, desc) in STAGES.items():
        lines.append(f"  {num:2}. {name:12} - {desc}")
    return "\n".join(lines)


def clear_stage_outputs(cve: CVEConfig, names: list[str]) -> None:
    """Remove stage output directories before a feedback retry."""
    for name in names:
        output_dir = cve.data_dir / name
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)


def read_validation_summary(cve: CVEConfig) -> dict:
    """Read Stage 10 results and summarize whether any validated repair passed."""
    output_dir = cve.data_dir / "repair_validated"
    files = sorted(output_dir.glob("*_repairs.json"))
    summary = {
        "success": False,
        "files": len(files),
        "normal_ok": None,
        "malicious_blocked": None,
        "errors": [],
        "feedback": "",
    }
    feedback_lines = []

    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            summary["errors"].append(f"{path.name}: {exc}")
            continue

        result = payload.get("validation_result", {}) if isinstance(payload, dict) else {}
        normal_ok = result.get("normal_ok")
        malicious_blocked = result.get("malicious_blocked")
        success = result.get("success") is True
        summary["normal_ok"] = normal_ok if summary["normal_ok"] is None else summary["normal_ok"] and normal_ok
        summary["malicious_blocked"] = (
            malicious_blocked
            if summary["malicious_blocked"] is None
            else summary["malicious_blocked"] and malicious_blocked
        )
        summary["success"] = summary["success"] or success

        repairs = payload.get("repairs", []) if isinstance(payload, dict) else []
        repair = repairs[0] if repairs else {}
        feedback_lines.append(
            f"- {path.name}: success={success}, normal_ok={normal_ok}, "
            f"malicious_blocked={malicious_blocked}, function={repair.get('function_name')}, "
            f"method={repair.get('repair_method')}"
        )
        if repair.get("repair_code"):
            repair_code = str(repair.get("repair_code"))
            feedback_lines.append("  previous repair code:")
            feedback_lines.extend(f"    {line}" for line in repair_code.splitlines()[:160])
        if result.get("error"):
            feedback_lines.append(f"  error: {result.get('error')}")

    log_file = cve.data_dir / "pipeline.log"
    if log_file.exists():
        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
            useful = [
                line for line in lines[-160:]
                if any(token in line for token in [
                    "Validation failed", "Normal request", "Malicious blocked",
                    "stdout", "stderr", "ERROR", "WARNING", "prctl", "payload",
                ])
            ]
            if useful:
                feedback_lines.append("Recent validation log:")
                feedback_lines.extend(f"  {line}" for line in useful[-40:])
        except Exception as exc:
            summary["errors"].append(f"pipeline.log: {exc}")

    summary["feedback"] = "\n".join(feedback_lines)[-12000:]
    return summary


def read_json_file(path: Path) -> dict | list | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def aggregate_repair_stats(value: object) -> dict:
    stats = {
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
    }
    seen = False

    def visit(item: object) -> None:
        nonlocal seen
        if isinstance(item, dict):
            if any(key in item for key in stats):
                seen = True
                for key in stats:
                    number = item.get(key)
                    if isinstance(number, (int, float)):
                        stats[key] += int(number)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return stats if seen else {}


def count_repair_files(cve: CVEConfig, dirname: str) -> int:
    return len(list((cve.data_dir / dirname).glob("*_repairs.json")))


def read_repair_generation_summary(cve: CVEConfig) -> dict:
    repair_stats = read_json_file(cve.data_dir / "repair" / "repair_stats.json")
    aggregate = aggregate_repair_stats(repair_stats)
    return {
        "repair_files": count_repair_files(cve, "repair"),
        "whitelisted_repair_files": count_repair_files(cve, "repair_with_whitelist"),
        "validated_repair_files": count_repair_files(cve, "repair_validated"),
        "repair_stats": aggregate,
    }


def next_lower_threshold(current: float) -> float:
    if current <= 0.05:
        return current
    return max(0.05, round(current - 0.1, 3))


def decide_feedback_route(cve: CVEConfig, validation: dict, threshold: float) -> dict:
    generation = read_repair_generation_summary(cve)
    stats = generation.get("repair_stats") or {}

    if validation.get("success"):
        return {
            "stage": None,
            "reason": "validation_passed",
            "action": "stop feedback loop",
            "generation": generation,
        }

    if generation["repair_files"] == 0:
        lowered = next_lower_threshold(threshold)
        if stats.get("skipped_below_threshold", 0) > 0 and lowered < threshold:
            return {
                "stage": 8,
                "reason": "all_candidates_below_threshold",
                "action": f"lower Stage 8 threshold from {threshold:.2f} to {lowered:.2f}",
                "threshold": lowered,
                "generation": generation,
            }
        if stats.get("skipped_no_source", 0) > 0:
            return {
                "stage": 6,
                "reason": "candidate_source_missing",
                "action": "re-extract source code, then rerun detection and repair",
                "threshold": threshold,
                "generation": generation,
            }
        if stats.get("skipped_no_syscalls", 0) > 0:
            return {
                "stage": 5,
                "reason": "candidate_syscalls_missing",
                "action": "rebuild call stacks before detection and repair",
                "threshold": threshold,
                "generation": generation,
            }
        return {
            "stage": 8,
            "reason": "no_repair_files",
            "action": "ask LLM to generate repair again with failure context",
            "threshold": threshold,
            "generation": generation,
        }

    if generation["whitelisted_repair_files"] == 0:
        return {
            "stage": 9,
            "reason": "no_whitelisted_repair_files",
            "action": "regenerate whitelist for existing repair files",
            "threshold": threshold,
            "generation": generation,
        }

    if generation["validated_repair_files"] == 0:
        return {
            "stage": 10,
            "reason": "no_validation_files",
            "action": "rerun validation for existing whitelisted repairs",
            "threshold": threshold,
            "generation": generation,
        }

    normal_ok = validation.get("normal_ok")
    malicious_blocked = validation.get("malicious_blocked")
    if normal_ok is False and malicious_blocked is True:
        reason = "normal_behavior_broken"
        action = "ask LLM to preserve normal path while keeping the guard"
    elif normal_ok is True and malicious_blocked is False:
        reason = "malicious_behavior_not_blocked"
        action = "ask LLM to move or tighten the guard near the dangerous call"
    elif normal_ok is False and malicious_blocked is False:
        reason = "repair_breaks_normal_and_misses_attack"
        action = "ask LLM for a different repair strategy"
    else:
        reason = "validation_inconclusive"
        action = "rerun validation once, then repair if it remains inconclusive"
        return {"stage": 10, "reason": reason, "action": action, "threshold": threshold, "generation": generation}

    return {"stage": 8, "reason": reason, "action": action, "threshold": threshold, "generation": generation}


def feedback_context_from_decision(summary: dict, decision: dict) -> str:
    lines = [
        "Previous feedback attempt failed.",
        f"Route reason: {decision.get('reason')}",
        f"Requested action: {decision.get('action')}",
        f"Normal validation: {summary.get('normal_ok')}",
        f"Malicious blocked: {summary.get('malicious_blocked')}",
    ]
    generation = decision.get("generation")
    if isinstance(generation, dict):
        lines.append(f"Repair files: {generation.get('repair_files')}")
        lines.append(f"Whitelisted repair files: {generation.get('whitelisted_repair_files')}")
        stats = generation.get("repair_stats")
        if isinstance(stats, dict) and stats:
            lines.append(f"Stage 8 filter stats: {json.dumps(stats, ensure_ascii=False)}")
    if summary.get("feedback"):
        lines.append("")
        lines.append(str(summary.get("feedback")))
    return "\n".join(lines)[-12000:]


def clear_outputs_for_route(cve: CVEConfig, route_stage: int) -> None:
    outputs = {
        5: ["callstack", "callstack_with_code", "detect", "repair", "repair_with_whitelist", "repair_validated"],
        6: ["callstack_with_code", "detect", "repair", "repair_with_whitelist", "repair_validated"],
        7: ["detect", "repair", "repair_with_whitelist", "repair_validated"],
        8: ["repair", "repair_with_whitelist", "repair_validated"],
        9: ["repair_with_whitelist", "repair_validated"],
        10: ["repair_validated"],
    }
    clear_stage_outputs(cve, outputs.get(route_stage, ["repair", "repair_with_whitelist", "repair_validated"]))


def run_feedback_route_stages(
    cve: CVEConfig,
    *,
    route_stage: int,
    attempt: int,
    max_attempts: int,
    max_repairs: int,
    validate_mode: str,
    wait_time: int,
    threshold: float,
    repair_mode: str,
    min_files: int,
    whitelist_mode: str,
    keep_repaired: bool,
    feedback_context: str,
    algo: list[str] | None,
) -> dict:
    stage_durations = {}

    if route_stage <= 5:
        logger.info("Stage 5: callstack (feedback attempt %s/%s)", attempt, max_attempts)
        stage_start = time.time()
        whitelist_path = None
        if cve.use_whitelist:
            wl = cve.env_dir.parent / "whitelist.txt"
            if wl.exists():
                whitelist_path = str(wl)
        process_callstack(cve, whitelist_file=whitelist_path)
        stage_durations["stage_5"] = time.time() - stage_start

    if route_stage <= 6:
        logger.info("Stage 6: extract (feedback attempt %s/%s)", attempt, max_attempts)
        stage_start = time.time()
        extract_source_code(cve)
        stage_durations["stage_6"] = time.time() - stage_start

    if route_stage <= 7:
        logger.info("Stage 7: detect (feedback attempt %s/%s)", attempt, max_attempts)
        stage_start = time.time()
        algo_list = algo if algo is not None else ["all"]
        detector = create_detector(algo_list)
        detector.run_detection(cve)
        stage_durations["stage_7"] = time.time() - stage_start

    if route_stage <= 8:
        logger.info("Stage 8: repair (feedback attempt %s/%s, threshold %.2f)", attempt, max_attempts, threshold)
        stage_start = time.time()
        generator = RepairGenerator(
            cve,
            repair_mode=repair_mode,
            whitelist_mode=whitelist_mode,
            feedback_context=feedback_context,
            feedback_attempt=attempt,
        )
        generator.run(
            threshold=threshold,
            filter_irrelevant=cve.filter_irrelevant,
            backtrack_repair=cve.backtrack_repair,
            max_repairs=max_repairs,
        )
        stage_durations["stage_8"] = time.time() - stage_start

    if route_stage <= 9:
        logger.info("Stage 9: whitelist (feedback attempt %s/%s)", attempt, max_attempts)
        stage_start = time.time()
        filler = WhitelistFiller(cve, min_files=min_files)
        filler.run()
        stage_durations["stage_9"] = time.time() - stage_start

    logger.info("Stage 10: validate (feedback attempt %s/%s)", attempt, max_attempts)
    stage_start = time.time()
    validator = RepairValidator(cve)
    skip_normal = validate_mode == "abnormal"
    skip_malicious = validate_mode == "normal"
    validator.run(
        skip_normal=skip_normal,
        skip_malicious=skip_malicious,
        wait_time=wait_time,
        keep_repaired=keep_repaired,
    )
    stage_durations["stage_10"] = time.time() - stage_start
    return stage_durations


def run_repair_whitelist_validate_with_feedback(
    cve: CVEConfig,
    *,
    max_repairs: int,
    validate_mode: str,
    wait_time: int,
    threshold: float,
    repair_mode: str,
    min_files: int,
    whitelist_mode: str,
    keep_repaired: bool,
    feedback_attempts: int,
    initial_feedback_context: str = "",
    initial_route_stage: int = 8,
    initial_route_reason: str = "initial_attempt",
    initial_route_action: str = "run selected feedback stages",
    algo: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    """Run repair/whitelist/validate with adaptive feedback routing."""
    attempts = []
    feedback_context = initial_feedback_context
    max_attempts = 1 + max(0, feedback_attempts)
    route_stage = initial_route_stage
    current_threshold = threshold
    current_route_reason = initial_route_reason if initial_feedback_context else "initial_attempt"
    current_route_action = initial_route_action

    for attempt in range(1, max_attempts + 1):
        logger.info("-" * 60)
        logger.info(f"Feedback repair attempt {attempt}/{max_attempts}")
        logger.info(
            "Adaptive feedback route: executing from Stage %s (%s)",
            route_stage,
            STAGES.get(route_stage, ("unknown",))[0],
        )
        logger.info("-" * 60)
        clear_outputs_for_route(cve, route_stage)

        attempt_start = time.time()
        stage_durations = run_feedback_route_stages(
            cve,
            route_stage=route_stage,
            attempt=attempt,
            max_attempts=max_attempts,
            max_repairs=max_repairs,
            validate_mode=validate_mode,
            wait_time=wait_time,
            threshold=current_threshold,
            repair_mode=repair_mode,
            min_files=min_files,
            whitelist_mode=whitelist_mode,
            keep_repaired=keep_repaired,
            feedback_context=feedback_context,
            algo=algo,
        )

        summary = read_validation_summary(cve)
        decision = decide_feedback_route(cve, summary, current_threshold)
        summary["attempt"] = attempt
        summary["duration"] = time.time() - attempt_start
        summary["stage_durations"] = stage_durations
        summary["route_stage"] = route_stage
        summary["route_label"] = STAGES.get(route_stage, ("unknown",))[0]
        summary["route_reason"] = current_route_reason
        summary["route_action"] = current_route_action
        summary["threshold"] = current_threshold
        summary["next_route"] = decision
        summary["feedback_triggered"] = bool(initial_feedback_context) or attempt > 1
        attempts.append(summary)

        logger.info(
            "Feedback attempt %s result: success=%s, normal_ok=%s, malicious_blocked=%s, next_route=%s",
            attempt,
            summary.get("success"),
            summary.get("normal_ok"),
            summary.get("malicious_blocked"),
            decision.get("reason"),
        )

        if summary.get("success"):
            break
        if attempt < max_attempts:
            next_stage = decision.get("stage")
            if next_stage is None:
                break
            previous_threshold = current_threshold
            current_threshold = float(decision.get("threshold", current_threshold))
            route_stage = int(next_stage)
            current_route_reason = str(decision.get("reason"))
            current_route_action = str(decision.get("action"))
            feedback_context = feedback_context_from_decision(summary, decision)
            logger.warning(
                "Adaptive feedback route: return to Stage %s (%s); reason=%s; action=%s",
                route_stage,
                STAGES.get(route_stage, ("unknown",))[0],
                decision.get("reason"),
                decision.get("action"),
            )
            if current_threshold != previous_threshold:
                logger.warning(
                    "Adaptive feedback threshold: %.2f -> %.2f",
                    previous_threshold,
                    current_threshold,
                )

    feedback_file = cve.data_dir / "feedback_attempts.json"
    with open(feedback_file, "w", encoding="utf-8") as f:
        json.dump({"max_feedback_attempts": feedback_attempts, "attempts": attempts}, f, ensure_ascii=False, indent=2)
    logger.info(f"Feedback attempts saved to: {feedback_file}")
    return (attempts[-1] if attempts else {"success": False}), attempts


def run_whitelist_validate_then_feedback(
    cve: CVEConfig,
    *,
    max_repairs: int,
    validate_mode: str,
    wait_time: int,
    threshold: float,
    repair_mode: str,
    min_files: int,
    whitelist_mode: str,
    keep_repaired: bool,
    feedback_attempts: int,
    algo: list[str] | None = None,
) -> tuple[dict, list[dict]]:
    """Run Stage 9-10 on existing repairs, then return to Stage 8 if validation fails."""
    attempts = []
    initial_start = time.time()
    stage_durations = {}

    logger.info("-" * 60)
    logger.info("Existing repair validation before feedback")
    logger.info("-" * 60)

    logger.info("Stage 9: whitelist (existing repair validation)")
    stage_start = time.time()
    filler = WhitelistFiller(cve, min_files=min_files)
    filler.run()
    stage_durations["stage_9"] = time.time() - stage_start

    logger.info("Stage 10: validate (existing repair validation)")
    stage_start = time.time()
    validator = RepairValidator(cve)
    skip_normal = validate_mode == "abnormal"
    skip_malicious = validate_mode == "normal"
    validator.run(
        skip_normal=skip_normal,
        skip_malicious=skip_malicious,
        wait_time=wait_time,
        keep_repaired=keep_repaired,
    )
    stage_durations["stage_10"] = time.time() - stage_start

    summary = read_validation_summary(cve)
    summary["attempt"] = 0
    summary["duration"] = time.time() - initial_start
    summary["stage_durations"] = stage_durations
    summary["kind"] = "existing_repair_validation"
    decision = decide_feedback_route(cve, summary, threshold)
    summary["route_stage"] = 9
    summary["route_label"] = "whitelist"
    summary["route_reason"] = "existing_repair_validation"
    summary["route_action"] = "validate existing repair before deciding feedback route"
    summary["threshold"] = threshold
    summary["next_route"] = decision
    summary["feedback_triggered"] = False
    attempts.append(summary)

    logger.info(
        "Existing repair validation result: success=%s, normal_ok=%s, malicious_blocked=%s",
        summary.get("success"),
        summary.get("normal_ok"),
        summary.get("malicious_blocked"),
    )

    final_summary = summary
    if not summary.get("success") and feedback_attempts > 0:
        next_stage = int(decision.get("stage") or 8)
        logger.warning(
            "Adaptive feedback route: return to Stage %s (%s); reason=%s; action=%s",
            next_stage,
            STAGES.get(next_stage, ("unknown",))[0],
            decision.get("reason"),
            decision.get("action"),
        )
        final_summary, feedback_repair_attempts = run_repair_whitelist_validate_with_feedback(
            cve,
            max_repairs=max_repairs,
            validate_mode=validate_mode,
            wait_time=wait_time,
            threshold=threshold,
            repair_mode=repair_mode,
            min_files=min_files,
            whitelist_mode=whitelist_mode,
            keep_repaired=keep_repaired,
            feedback_attempts=max(0, feedback_attempts - 1),
            initial_feedback_context=feedback_context_from_decision(summary, decision),
            initial_route_stage=next_stage,
            initial_route_reason=str(decision.get("reason")),
            initial_route_action=str(decision.get("action")),
            algo=algo,
        )
        attempts.extend(feedback_repair_attempts)

    feedback_file = cve.data_dir / "feedback_attempts.json"
    with open(feedback_file, "w", encoding="utf-8") as f:
        json.dump({"max_feedback_attempts": feedback_attempts, "attempts": attempts}, f, ensure_ascii=False, indent=2)
    logger.info(f"Feedback attempts saved to: {feedback_file}")
    return final_summary, attempts


def run_pipeline(cve: CVEConfig, stages: list[int], max_repairs: int = 1, validate_mode: str = "all",
                 normal_time: int = 60, malicious_time: int = 20, wait_time: int = 60, threshold: float = 0.5,
                 repair_mode: str = "filter", min_files: int = 10, whitelist_mode: str = "static", keep_repaired: bool = False,
                 algo: list[str] = None, feedback_attempts: int = 0):
    env_dir = Path(f"cves/{cve.language}/{cve.cve_id}/env")

    timing = {}
    pipeline_start = time.time()
    skip_stages = set()

    for stage in stages:
        if stage in skip_stages:
            logger.info(f"Stage {stage} handled by feedback loop, skipping duplicate standalone execution")
            continue
        name, desc = STAGES.get(stage, ("unknown", "unknown stage"))
        logger.info("=" * 60)
        logger.info(f"Stage {stage}: {name}")
        logger.info("=" * 60)

        start = time.time()

        if stage == 8 and feedback_attempts > 0 and 9 in stages and 10 in stages:
            final_summary, attempts = run_repair_whitelist_validate_with_feedback(
                cve,
                max_repairs=max_repairs,
                validate_mode=validate_mode,
                wait_time=wait_time,
                threshold=threshold,
                repair_mode=repair_mode,
                min_files=min_files,
                whitelist_mode=whitelist_mode,
                keep_repaired=keep_repaired,
                feedback_attempts=feedback_attempts,
                algo=algo,
            )
            skip_stages.update({9, 10})
            timing["feedback_loop"] = {
                "duration": time.time() - start,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attempts": len(attempts),
                "success": final_summary.get("success"),
                "routes": [
                    {
                        "attempt": item.get("attempt"),
                        "route_stage": item.get("route_stage"),
                        "route_reason": item.get("route_reason"),
                        "threshold": item.get("threshold"),
                        "feedback_triggered": item.get("feedback_triggered"),
                    }
                    for item in attempts
                    if isinstance(item, dict)
                ],
            }

        elif stage == 9 and feedback_attempts > 0 and 10 in stages and 8 not in stages:
            final_summary, attempts = run_whitelist_validate_then_feedback(
                cve,
                max_repairs=max_repairs,
                validate_mode=validate_mode,
                wait_time=wait_time,
                threshold=threshold,
                repair_mode=repair_mode,
                min_files=min_files,
                whitelist_mode=whitelist_mode,
                keep_repaired=keep_repaired,
                feedback_attempts=feedback_attempts,
                algo=algo,
            )
            skip_stages.add(10)
            timing["feedback_loop"] = {
                "duration": time.time() - start,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attempts": len(attempts),
                "success": final_summary.get("success"),
                "routes": [
                    {
                        "attempt": item.get("attempt"),
                        "route_stage": item.get("route_stage"),
                        "route_reason": item.get("route_reason"),
                        "threshold": item.get("threshold"),
                        "feedback_triggered": item.get("feedback_triggered"),
                    }
                    for item in attempts
                    if isinstance(item, dict)
                ],
            }

        elif stage == 0:
            subprocess.run(["docker", "compose", "up", "-d"], cwd=env_dir, check=True)

        elif stage == 1:
            build_plugins(cve)

        elif stage == 2:
            collector = TrafficCollector(cve, normal_time=normal_time, malicious_time=malicious_time)
            if collector.run("both") is False:
                raise RuntimeError("Stage 2 collect failed")

        elif stage == 3:
            if parse_sysdig(cve) is False:
                raise RuntimeError("Stage 3 parse failed")

        elif stage == 4:
            split_units(cve)

        elif stage == 5:
            whitelist_path = None
            if cve.use_whitelist:
                wl = cve.env_dir.parent / "whitelist.txt"
                if wl.exists():
                    whitelist_path = str(wl)
            process_callstack(cve, whitelist_file=whitelist_path)

        elif stage == 6:
            extract_source_code(cve)

        elif stage == 7:
            algo_list = algo if algo is not None else ["all"]
            detector = create_detector(algo_list)
            detector.run_detection(cve)

        elif stage == 8:
            generator = RepairGenerator(cve, repair_mode=repair_mode, whitelist_mode=whitelist_mode)
            generator.run(
                threshold=threshold,
                filter_irrelevant=cve.filter_irrelevant,
                backtrack_repair=cve.backtrack_repair,
                max_repairs=max_repairs,
            )

        elif stage == 9:
            filler = WhitelistFiller(cve, min_files=min_files)
            filler.run()

        elif stage == 10:
            validator = RepairValidator(cve)
            skip_normal = validate_mode == "abnormal"
            skip_malicious = validate_mode == "normal"
            validator.run(skip_normal=skip_normal, skip_malicious=skip_malicious, wait_time=wait_time, keep_repaired=keep_repaired)

        elif stage == 11:
            subprocess.run(["docker", "compose", "down", "-v"], cwd=env_dir, check=True)

        elapsed = time.time() - start
        logger.info(f"Stage {stage} completed in {elapsed:.1f}s")

        timing[f"stage_{stage}"] = {
            "duration": elapsed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    if timing:
        pipeline_elapsed = time.time() - pipeline_start
        timing["total_duration"] = pipeline_elapsed

        timing_file = cve.data_dir / "timing.json"
        timing_file.parent.mkdir(parents=True, exist_ok=True)

        existing_timing = {}
        if timing_file.exists():
            try:
                with open(timing_file, 'r', encoding='utf-8') as f:
                    existing_timing = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Invalid {timing_file}, overwriting with new data")
                existing_timing = {}

        merged_timing = {**existing_timing, **timing}

        with open(timing_file, 'w', encoding='utf-8') as f:
            json.dump(merged_timing, f, ensure_ascii=False, indent=2)

        logger.info(f"Timing saved to: {timing_file}")


def parse_stage_arg(stage_str: str) -> list[int]:
    """
    Parse stage argument.

    Supported formats:
        "3"     -> [3]
        "2-5"   -> [2, 3, 4, 5]
    """
    if "-" in stage_str:
        start, end = stage_str.split("-")
        return list(range(int(start), int(end) + 1))
    else:
        return [int(stage_str)]


def archive_existing_data_dir(data_dir: Path) -> Path | None:
    """
    Preserve the previous fresh-run output before Stage 0 starts.

    The pipeline expects the active output directory to stay at
    data/<language>/<CVE>, so the previous directory is renamed to the first
    available data/<language>/<CVE>-N slot.
    """
    if not data_dir.exists():
        return None

    parent = data_dir.parent
    base_name = data_dir.name
    index = 1
    while True:
        archive_dir = parent / f"{base_name}-{index}"
        if not archive_dir.exists():
            break
        index += 1

    shutil.move(str(data_dir), str(archive_dir))
    return archive_dir


def main():
    epilog = f"""
Examples:
  python main.py --cve CVE-2015-8562 --stage 0                    # Start containers
  python main.py --cve CVE-2015-8562 --stage 2-7                  # Collect and detect
  python main.py --cve CVE-2015-8562 --stage 7 --algo jaccard     # Detect with Jaccard only
  python main.py --cve CVE-2015-8562 --stage 7 --algo ngram file  # Detect with multiple algorithms
  python main.py --cve CVE-2015-8562 --stage 8                    # Generate repair code
  python main.py --cve CVE-2015-8562 --stage 9                    # Populate whitelist
  python main.py --cve CVE-2015-8562 --stage 10                   # Validate repair
  python main.py --cve CVE-2015-8562 --stage 8-10                 # Repair-whitelist-validate
  python main.py --cve CVE-2015-8562 --stage 11                   # Stop containers
  python main.py --cve CVE-2015-8562 --stage 0-11                 # Full pipeline
  python main.py --list                                           # List all CVEs

{get_stages_help()}
"""
    parser = argparse.ArgumentParser(
        description="Vulnerability Repair Pipeline",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cve", help="CVE ID (e.g. CVE-2015-8562)")
    parser.add_argument("--stage", help="Run specific stage (e.g. 3 or 0-10)")
    parser.add_argument("--list", action="store_true", help="List all available CVEs")
    parser.add_argument("--max-repairs", type=int, default=1, help="Max number of repairs (default: 1)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Stage 8 anomaly score threshold (default: 0.5)")
    parser.add_argument("--repair-mode", default="filter", choices=["filter", "direct", "direct_localization"],
                        help="Stage 8 repair mode: filter=filter-based, direct=direct logic repair, direct_localization=LLM localization+repair (default: filter)")
    parser.add_argument("--validate-mode", default="all", choices=["normal", "abnormal", "all"],
                        help="Stage 10 validation mode: normal=normal requests only, abnormal=malicious requests only, all=both (default: all)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log level (default: INFO)")
    parser.add_argument("--log-file",
                        help="Write pipeline logs to this file in addition to the console "
                             "(default: data/<language>/<CVE>/pipeline.log)")
    parser.add_argument("--log-mode", default="append", choices=["append", "overwrite"],
                        help="Log file write mode: append=append to existing log, overwrite=start fresh (default: append)")
    parser.add_argument("--normal-time", type=int, default=60,
                        help="Stage 2 normal traffic collection time in seconds (default: 60)")
    parser.add_argument("--malicious-time", type=int, default=20,
                        help="Stage 2 malicious traffic collection time in seconds (default: 20)")
    parser.add_argument("--wait-time", type=int, default=60,
                        help="Stage 10 wait time after container restart in seconds (default: 60)")
    parser.add_argument("--keep-repaired", action="store_true",
                        help="Stage 10 keep repaired state, do not restore original files (default: False)")
    parser.add_argument("--min-files", type=int, default=10,
                        help="Stage 9 minimum files to trigger directory compression (default: 10)")
    parser.add_argument("--whitelist-mode", default="static", choices=["static", "llm"],
                        help="Stage 8 whitelist generation: static=fill via Stage 9 static analysis, llm=LLM-generated (default: static)")
    parser.add_argument("--feedback-attempts", type=int, default=0,
                        help="Additional LLM repair attempts after failed Stage 10 validation when running Stage 8-10 (default: 0)")
    parser.add_argument("--algo", nargs="+", default=["all"],
                        choices=["all", "jaccard", "ngram", "n_ips", "n_ports", "file", "proc", "internal"],
                        help="Stage 7 detection algorithms: all, jaccard, ngram, n_ips, n_ports, file, proc, internal (default: all, multiple allowed)")
    args = parser.parse_args()

    if args.list:
        setup_logging(args.log_level)
        print("Available CVEs:")
        for cve_id in list_cves():
            print(f"  {cve_id}")
        return

    if not args.cve:
        setup_logging(args.log_level)
        parser.print_help()
        return

    cve = load_cve_config(args.cve)
    stages = parse_stage_arg(args.stage) if args.stage else list(range(0, 12))

    archived_data_dir = None
    if 0 in stages:
        data_dir = Path(f"data/{cve.language}/{args.cve}")
        archived_data_dir = archive_existing_data_dir(data_dir)

    log_file = args.log_file or str(cve.data_dir / "pipeline.log")
    log_mode = "a" if args.log_mode == "append" else "w"
    setup_logging(args.log_level, log_file, log_mode=log_mode)
    logger.info(f"Log file: {log_file} (mode: {args.log_mode})")
    if archived_data_dir:
        logger.info(f"Archived previous data directory: {archived_data_dir}")

    if cve.manual_install:
        logger.warning(f"{args.cve} requires manual installation, please ensure installation steps are completed")

    run_pipeline(cve, stages, max_repairs=args.max_repairs, validate_mode=args.validate_mode,
                 normal_time=args.normal_time, malicious_time=args.malicious_time, wait_time=args.wait_time,
                 threshold=args.threshold, repair_mode=args.repair_mode, min_files=args.min_files,
                 whitelist_mode=args.whitelist_mode, keep_repaired=args.keep_repaired, algo=args.algo,
                 feedback_attempts=args.feedback_attempts)


if __name__ == "__main__":
    main()
