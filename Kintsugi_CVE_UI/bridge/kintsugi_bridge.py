"""Local HTTP bridge between the Kintsugi UI and a Kintsugi checkout."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import secrets
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, Literal

from fastapi import Header, HTTPException, Query, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, SecretStr


ROOT = Path(os.getenv("KINTSUGI_ROOT", Path.cwd())).resolve()
BRIDGE_TOKEN = os.getenv("KINTSUGI_BRIDGE_TOKEN", "").strip()
DEFAULT_SUDO_PASSWORD = os.getenv("KINTSUGI_SUDO_PASSWORD", "")
AUTO_PREPARE_IMAGES = os.getenv("KINTSUGI_AUTO_PREPARE_IMAGES", "1").strip().lower() not in {"0", "false", "no"}
COMMAND_TEMPLATE = os.getenv(
    "KINTSUGI_COMMAND_TEMPLATE",
    f"{sys.executable} main.py --cve {{cve}} --stage {{start_stage}}-{{end_stage}}",
)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "KINTSUGI_UI_ORIGINS",
        "https://kintsugi-cve-console.xianyuchen2077.chatgpt.site,"
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]
ALLOWED_ORIGIN_REGEX = os.getenv(
    "KINTSUGI_UI_ORIGIN_REGEX",
    r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|[0-9.]+)(:\d+)?",
)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_PREFIX_PATTERN = re.compile(r"^(CVE-\d{4}-\d{4,7})")
STAGE_LOG_PATTERN = re.compile(r"Stage\s+(\d+)(?::\s*([A-Za-z_ -]+))?", re.IGNORECASE)
LOCUST_RUNTIME_PATTERN = re.compile(r"Run time limit set to\s+(\d+)\s+seconds", re.IGNORECASE)
STAGE_COMPLETED_PATTERN = re.compile(r"Stage\s+(\d+)\s+completed", re.IGNORECASE)
STAGE_FEEDBACK_HANDLED_PATTERN = re.compile(r"Stage\s+(9|10)\s+handled by feedback loop", re.IGNORECASE)
STAGE_ERROR_HINTS = (
    "ERROR",
    "Traceback",
    "failed",
    "failed to execute traffic generation",
    "collection failed",
    "error during",
)


class RunRequest(BaseModel):
    cve: str
    start_stage: int = Field(0, ge=0, le=11)
    end_stage: int = Field(11, ge=0, le=11)
    collector: Literal["auto", "sysdig", "strace"] = "auto"
    model: str = "deepseek-chat"
    max_repairs: int = Field(1, ge=1, le=20)
    feedback_attempts: int = Field(0, ge=0, le=10)
    threshold: float = Field(0.5, ge=0, le=1)
    repair_mode: Literal["filter", "direct", "direct_localization"] = "filter"
    validate_mode: Literal["normal", "abnormal", "all"] = "all"
    normal_time: int = Field(60, ge=1, le=3600)
    malicious_time: int = Field(20, ge=1, le=3600)
    wait_time: int = Field(60, ge=0, le=3600)
    min_files: int = Field(10, ge=1, le=10000)
    whitelist_mode: Literal["static", "llm"] = "static"
    algo: list[str] = Field(default_factory=lambda: ["all"])
    log_mode: Literal["append", "overwrite"] = "append"
    run_target: Literal["new", "resume"] = "new"
    artifact_directory: str | None = None
    sudo_password: SecretStr | None = Field(default=None, exclude=True)


@dataclass
class Job:
    run_id: str
    request: RunRequest
    command: list[str]
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    return_code: int | None = None
    artifact_directory: str | None = None
    current_stage: int | None = None
    current_stage_label: str = "queued"
    process: asyncio.subprocess.Process | None = None
    events: list[dict] = field(default_factory=list)
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)

    def public(self) -> dict:
        return {
            "run_id": self.run_id,
            "cve": self.request.cve,
            "status": self.status,
            "command": self.command,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "return_code": self.return_code,
            "artifact_directory": self.artifact_directory,
            "current_stage": self.current_stage,
            "current_stage_label": self.current_stage_label,
            "run_target": self.request.run_target,
            "event_count": len(self.events),
            "recent_events": self.events[-240:],
        }


def require_bridge_token(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> None:
    if not BRIDGE_TOKEN:
        return
    supplied = token or ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not secrets.compare_digest(supplied, BRIDGE_TOKEN):
        raise HTTPException(401, "Bridge token is required")


app = FastAPI(title="Kintsugi Local Bridge", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
jobs: dict[str, Job] = {}
run_lock = asyncio.Lock()


@app.middleware("http")
async def enforce_bridge_token(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path == "/auth-status":
        return await call_next(request)
    if not BRIDGE_TOKEN:
        return await call_next(request)
    supplied = request.query_params.get("token") or ""
    authorization = request.headers.get("authorization")
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if supplied and secrets.compare_digest(supplied, BRIDGE_TOKEN):
        return await call_next(request)
    return JSONResponse({"detail": "Bridge token is required"}, status_code=401)


async def docker_available() -> bool:
    try:
        process = await asyncio.create_subprocess_exec(
            "docker", "info",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await asyncio.wait_for(process.wait(), timeout=3) == 0
    except (FileNotFoundError, asyncio.TimeoutError):
        return False


async def main_help() -> tuple[bool, str]:
    main_file = ROOT / "main.py"
    if not main_file.is_file():
        return False, "main.py not found"
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(main_file), "--help",
            cwd=ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=6)
        text = stdout.decode("utf-8", errors="replace").strip()
        return process.returncode == 0, text[-4000:]
    except asyncio.TimeoutError:
        process.kill()
        return False, "main.py --help timed out after 6 seconds"
    except Exception as exc:
        return False, str(exc)


async def probe_command(command: list[str], timeout: float = 5) -> tuple[bool, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        text = stdout.decode("utf-8", errors="replace").strip()
        return process.returncode == 0, text[-1200:]
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return False, f"{' '.join(command)} timed out after {timeout}s"
    except FileNotFoundError:
        return False, f"{command[0]} not found in PATH"
    except Exception as exc:
        return False, str(exc)


async def collector_diagnostics() -> dict:
    sysdig_path = shutil.which("sysdig")
    strace_path = shutil.which("strace")
    sysdig_ok, sysdig_detail = (False, "sysdig not found in PATH")
    if sysdig_path:
        sysdig_ok, sysdig_detail = await probe_command([sysdig_path, "-n", "1"], timeout=5)
        if not sysdig_detail:
            sysdig_detail = "captured one event successfully"
    strace_ok, strace_detail = (False, "strace not found in PATH")
    if strace_path:
        strace_ok, strace_detail = await probe_command([strace_path, "-V"], timeout=3)
        if strace_ok:
            strace_detail = (strace_detail.splitlines() or ["strace available"])[0]
    return {
        "sysdig": {"installed": bool(sysdig_path), "usable": sysdig_ok, "path": sysdig_path, "detail": sysdig_detail},
        "strace": {"installed": bool(strace_path), "usable": strace_ok, "path": strace_path, "detail": strace_detail},
        "fallback_ready": strace_ok,
    }


def _load_json(path: Path) -> dict | list | None:
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return None


def _latest_timestamp(timing: dict) -> str:
    timestamps = [
        value.get("timestamp")
        for value in timing.values()
        if isinstance(value, dict) and value.get("timestamp")
    ]
    return max(timestamps) if timestamps else ""


def _duration_text(seconds: float | int | None) -> str:
    if not seconds:
        return "未统计"
    seconds = int(seconds)
    minutes, rest = divmod(seconds, 60)
    return f"{minutes}m {rest}s" if minutes else f"{rest}s"


def _merge_feedback_stage_timing(timing: dict, feedback: dict | list | None) -> dict:
    """Expose feedback-loop Stage 8-10 durations as normal stage_* keys for the UI track."""
    merged = dict(timing)
    if not isinstance(feedback, dict):
        return merged
    attempts = feedback.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return merged

    stage_totals: dict[str, float] = {}
    latest_timestamp = ""
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        stage_durations = attempt.get("stage_durations")
        if not isinstance(stage_durations, dict):
            continue
        for key, value in stage_durations.items():
            if key in {"stage_8", "stage_9", "stage_10"} and isinstance(value, (int, float)):
                stage_totals[key] = stage_totals.get(key, 0.0) + float(value)
        timestamp = attempt.get("timestamp")
        if isinstance(timestamp, str) and timestamp > latest_timestamp:
            latest_timestamp = timestamp

    fallback_timestamp = latest_timestamp or (
        merged.get("feedback_loop", {}).get("timestamp")
        if isinstance(merged.get("feedback_loop"), dict)
        else ""
    )
    for key, duration in stage_totals.items():
        existing = merged.get(key)
        if isinstance(existing, dict):
            # In feedback modes main.py may record the whole loop under the stage
            # that entered it. Replace Stage 8/9/10 with their actual durations
            # so the overview track reflects what really ran.
            merged[key] = {**existing, "duration": duration, "timestamp": existing.get("timestamp") or fallback_timestamp}
        elif not isinstance(existing, dict):
            merged[key] = {"duration": duration, "timestamp": fallback_timestamp}
    return merged


def _nonempty_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _has_nonempty_glob(directory: Path, pattern: str) -> bool:
    if not directory.is_dir():
        return False
    return any(_nonempty_file(path) for path in directory.glob(pattern))


def _json_has_payload(path: Path) -> bool:
    payload = _load_json(path)
    if isinstance(payload, list):
        return bool(payload)
    if isinstance(payload, dict):
        return bool(payload)
    return False


def _repair_json_has_repairs(path: Path) -> bool:
    payload = _load_json(path)
    if isinstance(payload, list):
        return bool(payload)
    if not isinstance(payload, dict):
        return False
    repairs = payload.get("repairs")
    return isinstance(repairs, list) and bool(repairs)


def _validation_json_has_result(path: Path) -> bool:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        return False
    validation = payload.get("validation_result")
    if not isinstance(validation, dict):
        return False
    return any(key in validation for key in ("normal_ok", "malicious_blocked", "success"))


def _validation_result_state(directory: Path) -> str:
    if not directory.is_dir():
        return "missing"
    saw_result = False
    for path in sorted(directory.glob("*_repairs.json")):
        if not _nonempty_file(path):
            continue
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        validation = payload.get("validation_result")
        if not isinstance(validation, dict):
            continue
        if not any(key in validation for key in ("normal_ok", "malicious_blocked", "success")):
            continue
        saw_result = True
        if validation.get("success") is True:
            return "success"
    return "failed" if saw_result else "missing"


def _any_json(directory: Path, pattern: str, predicate) -> bool:
    if not directory.is_dir():
        return False
    for path in sorted(directory.glob(pattern)):
        if _nonempty_file(path) and predicate(path):
            return True
    return False


def _actual_feedback_retried(feedback: dict | list | None) -> bool:
    if not isinstance(feedback, dict):
        return False
    attempts = feedback.get("attempts")
    if not isinstance(attempts, list):
        return False
    real_attempts = [attempt for attempt in attempts if isinstance(attempt, dict)]
    return len(real_attempts) > 1


def _stage_completion_criterion(data_dir: Path, stage: int, timing: dict, completed: set[int]) -> tuple[bool, str]:
    """Return whether a stage has the output that makes it meaningfully complete."""
    has_timing_or_log = stage in completed or isinstance(timing.get(f"stage_{stage}"), dict)
    if stage in {0, 1, 11}:
        labels = {0: "环境启动完成", 1: "构建命令完成", 11: "环境清理完成"}
        return has_timing_or_log, labels[stage] if has_timing_or_log else "未找到阶段完成记录"

    if stage == 2:
        ok = _nonempty_file(data_dir / "normal.scap") and _nonempty_file(data_dir / "malicious.scap")
        return ok, "normal.scap 与 malicious.scap 均存在" if ok else "缺少 normal/malicious 采集文件"
    if stage == 3:
        ok = _nonempty_file(data_dir / "normal.jsonl") and _nonempty_file(data_dir / "malicious.jsonl")
        return ok, "normal.jsonl 与 malicious.jsonl 均存在" if ok else "缺少 normal/malicious 解析结果"
    if stage == 4:
        ok = _has_nonempty_glob(data_dir / "unit", "normal_*.csv") and _has_nonempty_glob(data_dir / "unit", "malicious_*.csv")
        return ok, "normal/malicious unit CSV 均存在" if ok else "缺少 normal/malicious unit CSV"
    if stage == 5:
        ok = _has_nonempty_glob(data_dir / "callstack", "normal_*.jsonl") and _has_nonempty_glob(data_dir / "callstack", "malicious_*.jsonl")
        return ok, "normal/malicious 调用栈均存在" if ok else "缺少 normal/malicious 调用栈"
    if stage == 6:
        ok = _has_nonempty_glob(data_dir / "callstack_with_code", "normal_*.json") and _has_nonempty_glob(data_dir / "callstack_with_code", "malicious_*.json")
        return ok, "normal/malicious 源码上下文均存在" if ok else "缺少 normal/malicious 源码上下文"
    if stage == 7:
        ok = _any_json(data_dir / "detect", "malicious_*_pairs.json", _json_has_payload)
        return ok, "检测候选非空" if ok else "未生成有效检测候选"
    if stage == 8:
        ok = _any_json(data_dir / "repair", "*_repairs.json", _repair_json_has_repairs)
        return ok, "生成有效修复候选" if ok else "未生成有效修复候选"
    if stage == 9:
        ok = _any_json(data_dir / "repair_with_whitelist", "*_repairs.json", _repair_json_has_repairs)
        return ok, "生成带白名单修复产物" if ok else "未生成带白名单修复产物"
    if stage == 10:
        result_state = _validation_result_state(data_dir / "repair_validated")
        if result_state == "success":
            return True, "验证通过"
        if result_state == "failed":
            return False, "验证未通过"
        return False, "未生成验证结果"
    return False, "未知阶段"


def _stage_statuses(data_dir: Path, timing: dict, feedback: dict | list | None) -> list[dict]:
    statuses = [
        {"stage": index, "status": "missing", "duration": None, "source": "未找到运行证据"}
        for index in range(12)
    ]

    started: set[int] = set()
    completed: set[int] = set()
    errors: dict[int, list[str]] = {}
    current_stage: int | None = None
    log_path = data_dir / "pipeline.log"
    if log_path.exists():
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            lines = []
        for line in lines:
            stage_match = STAGE_LOG_PATTERN.search(line)
            if stage_match:
                stage = int(stage_match.group(1))
                if 0 <= stage < len(statuses):
                    started.add(stage)
                    current_stage = stage
            completed_match = STAGE_COMPLETED_PATTERN.search(line)
            if completed_match:
                stage = int(completed_match.group(1))
                if 0 <= stage < len(statuses):
                    completed.add(stage)
            feedback_match = STAGE_FEEDBACK_HANDLED_PATTERN.search(line)
            if feedback_match:
                stage = int(feedback_match.group(1))
                completed.add(stage)
            lowered = line.lower()
            if current_stage is not None and any(hint.lower() in lowered for hint in STAGE_ERROR_HINTS):
                errors.setdefault(current_stage, []).append(line[-220:])

    feedback_stage_keys: set[str] = set()
    if isinstance(feedback, dict):
        attempts = feedback.get("attempts")
        if isinstance(attempts, list):
            for attempt in attempts:
                if not isinstance(attempt, dict):
                    continue
                stage_durations = attempt.get("stage_durations")
                if not isinstance(stage_durations, dict):
                    continue
                feedback_stage_keys.update(
                    key for key in stage_durations
                    if key in {"stage_8", "stage_9", "stage_10"}
                )
    feedback_retried = _actual_feedback_retried(feedback)

    for index in range(12):
        key = f"stage_{index}"
        item = timing.get(key)
        duration = item.get("duration") if isinstance(item, dict) else None
        criterion_ok, criterion_source = _stage_completion_criterion(data_dir, index, timing, completed)
        executed = index in started or index in completed or isinstance(item, dict)

        if criterion_ok:
            is_feedback_stage = (
                feedback_retried
                and index in {8, 9, 10}
                and (key in feedback_stage_keys or index in completed)
            )
            statuses[index].update({
                "status": "feedback" if is_feedback_stage else "done",
                "duration": duration,
                "source": "反馈重试后完成" if is_feedback_stage else criterion_source,
            })
            continue

        if executed:
            if index in completed or isinstance(item, dict):
                reason = criterion_source
                if errors.get(index):
                    reason = f"{criterion_source}；日志存在异常"
                statuses[index].update({"status": "failed", "duration": duration, "source": reason})
            else:
                statuses[index].update({"status": "started", "duration": duration, "source": "日志出现 Stage 入口，未确认完成"})
            continue

        if isinstance(item, dict):
            statuses[index]["duration"] = duration

    return statuses


def _artifact_status(data_dir: Path) -> tuple[str, str, str, str, int, int, str]:
    validated_files = sorted((data_dir / "repair_validated").glob("*_repairs.json"))
    repair_files = sorted((data_dir / "repair").glob("*_repairs.json"))
    target_files = validated_files or repair_files
    if not target_files:
        return "部分完成", "—", "—", "未生成", 0, 0, "未找到修复验证结果"

    payload = _load_json(target_files[0]) or {}
    repairs = payload.get("repairs", []) if isinstance(payload, dict) else payload if isinstance(payload, list) else []
    repair = repairs[0] if repairs else {}
    validation = payload.get("validation_result", {}) if isinstance(payload, dict) else {}
    normal_ok = validation.get("normal_ok")
    malicious_blocked = validation.get("malicious_blocked")
    success = validation.get("success")
    repair_method = repair.get("repair_method") or repair.get("method") or "repair"
    function_name = repair.get("function_name") or repair.get("function_path") or "未找到函数"
    rules = 0
    whitelist = repair.get("whitelist")
    if isinstance(whitelist, dict):
        rules = sum(len(value) if isinstance(value, list) else 1 for value in whitelist.values())
    elif isinstance(whitelist, list):
        rules = len(whitelist)

    if success is True:
        status = "成功"
    elif validated_files:
        status = "失败"
    else:
        status = "部分完成"

    normal = "✓" if normal_ok is True else "✗" if normal_ok is False else "—"
    malicious = "✓" if malicious_blocked is True else "✗" if malicious_blocked is False else "—"
    return status, normal, malicious, repair_method, len(repairs), rules, function_name


def scan_artifact_runs(cve: str | None = None) -> list[dict]:
    data_root = ROOT / "data"
    if not data_root.is_dir():
        return []

    active_artifacts: dict[str, Job] = {}
    active_jobs: list[tuple[str, Job]] = []
    for job in jobs.values():
        if job.status not in {"queued", "running"}:
            continue
        try:
            language = _language_for_cve(job.request.cve)
        except HTTPException:
            continue
        if cve and job.request.cve != cve:
            continue
        active_jobs.append((language, job))
        active_artifacts[f"data/{language}/{job.request.cve}"] = job
        if job.artifact_directory:
            active_artifacts[job.artifact_directory] = job
    items: list[dict] = []
    active_seen: set[str] = set()
    for language_dir in sorted(path for path in data_root.iterdir() if path.is_dir() and not path.name.startswith(".")):
        language = language_dir.name
        for data_dir in sorted(path for path in language_dir.iterdir() if path.is_dir()):
            match = CVE_PREFIX_PATTERN.match(data_dir.name)
            if not match:
                continue
            cve_id = match.group(1)
            if cve and cve_id != cve:
                continue

            relative_directory = str(data_dir.relative_to(ROOT))
            if data_dir.name == cve_id and relative_directory not in active_artifacts:
                continue

            timing = _load_json(data_dir / "timing.json")
            timing = timing if isinstance(timing, dict) else {}
            feedback = _load_json(data_dir / "feedback_attempts.json")
            timing_for_ui = _merge_feedback_stage_timing(timing, feedback)
            stage_duration = sum(
                value.get("duration", 0)
                for key, value in timing_for_ui.items()
                if key.startswith("stage_") and isinstance(value, dict)
            ) or None
            total_duration = timing.get("total_duration")
            if stage_duration and (total_duration is None or stage_duration > float(total_duration) * 2):
                total_duration = stage_duration
            timestamp = _latest_timestamp(timing)
            if not timestamp:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data_dir.stat().st_mtime))

            status, normal, malicious, repair, candidates, rules, note = _artifact_status(data_dir)
            active_job = active_artifacts.get(relative_directory)
            display_directory = relative_directory
            item_id = f"ART-{language}-{data_dir.name}"
            if active_job:
                active_seen.add(active_job.run_id)
                status = "排队中" if active_job.status == "queued" else "运行中"
                note = active_job.current_stage_label or "任务正在执行"
                if active_job.artifact_directory and (ROOT / active_job.artifact_directory).is_dir():
                    display_directory = active_job.artifact_directory
                    item_id = f"ART-{language}-{Path(display_directory).name}"
            stage_statuses = _stage_statuses(data_dir, timing_for_ui, feedback)
            stage_count = sum(1 for item in stage_statuses if item.get("status") in {"done", "feedback"})
            items.append({
                "id": item_id,
                "cve": cve_id,
                "language": language,
                "directory": display_directory,
                "date": timestamp,
                "status": status,
                "duration": _duration_text(total_duration),
                "seconds": int(total_duration or 0),
                "candidates": candidates,
                "repair": repair,
                "rules": rules,
                "normal": normal,
                "malicious": malicious,
                "collector": "data",
                "note": note,
                "stage_count": stage_count,
                "source": "artifact",
                "mtime": data_dir.stat().st_mtime,
            })
    for language, job in active_jobs:
        if job.run_id in active_seen:
            continue
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.created_at))
        status = "排队中" if job.status == "queued" else "运行中"
        base_directory = f"data/{language}/{job.request.cve}"
        directory = job.artifact_directory if job.artifact_directory and (ROOT / job.artifact_directory).is_dir() else base_directory
        items.append({
            "id": f"ART-{language}-{Path(directory).name}",
            "cve": job.request.cve,
            "language": language,
            "directory": directory,
            "date": timestamp,
            "status": status,
            "duration": _duration_text((time.time() - job.started_at) if job.started_at else None),
            "seconds": int((time.time() - job.started_at) if job.started_at else 0),
            "candidates": 0,
            "repair": "运行中" if job.status == "running" else "排队中",
            "rules": 0,
            "normal": "—",
            "malicious": "—",
            "collector": "bridge",
            "note": job.current_stage_label or status,
            "stage_count": 0,
            "source": "artifact",
            "mtime": job.started_at or job.created_at,
        })
    return sorted(items, key=lambda item: item["mtime"], reverse=True)


def _artifact_path(directory: str) -> Path:
    data_root = (ROOT / "data").resolve()
    candidate = (ROOT / directory).resolve()
    try:
        relative = candidate.relative_to(data_root)
    except ValueError as exc:
        raise HTTPException(422, "Artifact directory must be under data/") from exc
    if len(relative.parts) != 2 or relative.parts[0].startswith("."):
        raise HTTPException(422, "Artifact directory must identify one CVE run")
    if not candidate.is_dir():
        raise HTTPException(404, "Artifact directory not found")
    match = CVE_PREFIX_PATTERN.match(candidate.name)
    if not match:
        raise HTTPException(422, "Artifact directory has an invalid CVE name")
    return candidate


def _language_for_cve(cve: str) -> str:
    cves_root = ROOT / "cves"
    for language_dir in cves_root.iterdir() if cves_root.is_dir() else []:
        if language_dir.is_dir() and (language_dir / cve).is_dir():
            return language_dir.name
    raise HTTPException(404, f"CVE scenario not found: {cve}")


def _dated_artifact_path(language: str, cve: str, timestamp: float | None = None) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(timestamp or time.time()))
    parent = ROOT / "data" / language
    candidate = parent / f"{cve}-{stamp}"
    suffix = 2
    while candidate.exists():
        candidate = parent / f"{cve}-{stamp}-{suffix}"
        suffix += 1
    return candidate


def _reserved_dated_artifact_path(language: str, cve: str, timestamp: float | None = None) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(timestamp or time.time()))
    parent = ROOT / "data" / language
    reserved = {job.artifact_directory for job in jobs.values() if job.artifact_directory}
    candidate = parent / f"{cve}-{stamp}"
    suffix = 2
    while candidate.exists() or str(candidate.relative_to(ROOT)) in reserved:
        candidate = parent / f"{cve}-{stamp}-{suffix}"
        suffix += 1
    return candidate


def _compose_down_for_cve(language: str, cve: str, sudo_password: str | None = None) -> dict:
    env_dir = ROOT / "cves" / language / cve / "env"
    compose_file = env_dir / "docker-compose.yml"
    if not compose_file.is_file():
        return {"attempted": False, "ok": True, "detail": "docker-compose.yml not found"}

    base_cmd = ["docker", "compose", "down", "--remove-orphans"]
    attempts = [base_cmd]
    inputs: list[str | None] = [None]
    if sudo_password:
        attempts.append(["sudo", "-S", "-p", "", *base_cmd])
        inputs.append(f"{sudo_password}\n")

    last_detail = ""
    for command, stdin_text in zip(attempts, inputs):
        result = subprocess.run(
            command,
            cwd=env_dir,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=120,
        )
        detail = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return {"attempted": True, "ok": True, "detail": detail[-2000:]}
        last_detail = detail or f"exit {result.returncode}"

    if "permission denied" in last_detail.lower() or "password" in last_detail.lower():
        raise HTTPException(409, "Docker cleanup needs sudo password")
    raise HTTPException(500, f"Docker cleanup failed: {last_detail[-800:]}")


def _artifact_cve_parts(target: Path) -> tuple[str, str]:
    match = CVE_PREFIX_PATTERN.match(target.name)
    if not match:
        raise HTTPException(422, "Artifact directory has an invalid CVE name")
    return target.parent.name, match.group(1)


def _sudo_command(command: list[str], sudo_password: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    password = sudo_password or DEFAULT_SUDO_PASSWORD
    return subprocess.run(
        ["sudo", "-S", "-p", "", *command],
        input=f"{password}\n",
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _remove_path_later(path: Path, sudo_password: str | None = None) -> None:
    try:
        shutil.rmtree(path)
        return
    except Exception:
        pass
    try:
        _sudo_command(["rm", "-rf", "--", str(path)], sudo_password, timeout=3600)
    except Exception:
        pass


def _run_compose_cleanup_later(language: str, cve: str, sudo_password: str | None) -> None:
    try:
        _compose_down_for_cve(language, cve, sudo_password)
    except Exception:
        pass


def _trash_artifact(target: Path, sudo_password: str | None = None, delete_in_background: bool = True) -> dict:
    trash_root = ROOT / "data" / ".trash"
    trash_root.mkdir(parents=True, exist_ok=True)
    trashed = trash_root / f"{target.name}-{int(time.time())}"
    suffix = 2
    while trashed.exists():
        trashed = trash_root / f"{target.name}-{int(time.time())}-{suffix}"
        suffix += 1
    try:
        target.rename(trashed)
    except OSError:
        result = _sudo_command(["mv", "--", str(target), str(trashed)], sudo_password)
        if result.returncode != 0:
            detail = (result.stdout + result.stderr).strip()[-800:]
            raise HTTPException(500, f"Failed to move artifact to trash: {detail}")

    if delete_in_background:
        threading.Thread(target=_remove_path_later, args=(trashed, sudo_password), daemon=True).start()
    return {"visible_deleted": str(target.relative_to(ROOT)), "trash": str(trashed.relative_to(ROOT))}


def delete_artifact(directory: str, sudo_password: str | None = None) -> dict:
    sudo_password = sudo_password or DEFAULT_SUDO_PASSWORD
    if any(job.status in {"queued", "running"} and job.artifact_directory == directory for job in jobs.values()):
        raise HTTPException(409, "This artifact is being used by an active run")
    target = _artifact_path(directory)
    relative = str(target.relative_to(ROOT))
    for job in jobs.values():
        if job.status in {"queued", "running"} and job.artifact_directory == relative:
            raise HTTPException(409, "This artifact is being used by an active run")
    language, cve = _artifact_cve_parts(target)
    deleted = _trash_artifact(target, sudo_password)
    threading.Thread(target=_run_compose_cleanup_later, args=(language, cve, sudo_password), daemon=True).start()
    return {
        "deleted": relative,
        "docker_cleanup": {"attempted": True, "ok": None, "detail": "scheduled in background"},
        "background_delete": deleted,
    }


def clear_artifact_history(cve: str, sudo_password: str | None = None) -> dict:
    sudo_password = sudo_password or DEFAULT_SUDO_PASSWORD
    if not CVE_PATTERN.fullmatch(cve):
        raise HTTPException(422, "Invalid CVE identifier")
    data_root = ROOT / "data"
    if not data_root.is_dir():
        return {"cleared": 0, "archive": None}

    cleared = []
    cleanup_results = []
    for language_dir in sorted(path for path in data_root.iterdir() if path.is_dir() and not path.name.startswith(".")):
        targets = []
        for data_dir in sorted(path for path in language_dir.iterdir() if path.is_dir()):
            match = CVE_PREFIX_PATTERN.match(data_dir.name)
            if not match or match.group(1) != cve:
                continue
            relative = str(data_dir.relative_to(ROOT))
            if any(job.status in {"queued", "running"} and job.artifact_directory == relative for job in jobs.values()):
                continue
            targets.append((data_dir, relative))
        for data_dir, relative in targets:
            _trash_artifact(data_dir, sudo_password)
            cleared.append(relative)
        if targets:
            threading.Thread(
                target=_run_compose_cleanup_later,
                args=(language_dir.name, cve, sudo_password),
                daemon=True,
            ).start()
            cleanup_results.append({
                "language": language_dir.name,
                "attempted": True,
                "ok": None,
                "detail": "scheduled in background",
            })
    cleared_jobs = [
        run_id for run_id, job in jobs.items()
        if job.request.cve == cve and job.status not in {"queued", "running"}
    ]
    for run_id in cleared_jobs:
        jobs.pop(run_id, None)
    return {"cleared": len(cleared), "cleared_jobs": len(cleared_jobs), "items": cleared, "docker_cleanup": cleanup_results}


def _find_original_source(value: object, function_name: str | None) -> str:
    candidates: list[tuple[str | None, str]] = []

    def collect(item: object) -> None:
        if isinstance(item, dict):
            source = item.get("source_code")
            name = item.get("function_name") or item.get("name")
            if isinstance(source, str) and source:
                candidates.append((name if isinstance(name, str) else None, source))
            for child in item.values():
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)

    collect(value)
    if function_name:
        for name, source in candidates:
            if name == function_name:
                return source
    return candidates[0][1] if candidates else ""


def _collection_params_from_log(data_dir: Path) -> dict:
    log_path = data_dir / "pipeline.log"
    if not log_path.exists():
        return {}

    current: str | None = None
    values: dict[str, int | str] = {"source": str(log_path.relative_to(ROOT))}
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {}

    for line in lines:
        lowered = line.lower()
        if "collecting normal traffic" in lowered:
            current = "normal"
            continue
        if "collecting malicious traffic" in lowered:
            current = "malicious"
            continue

        match = LOCUST_RUNTIME_PATTERN.search(line)
        if match and current:
            values[f"{current}_time"] = int(match.group(1))

    return values if "normal_time" in values or "malicious_time" in values else {}


def artifact_detail(directory: str) -> dict:
    data_dir = _artifact_path(directory)

    repair_files = sorted((data_dir / "repair_validated").glob("*_repairs.json"))
    source = "repair_validated"
    if not repair_files:
        repair_files = sorted((data_dir / "repair_with_whitelist").glob("*_repairs.json"))
        source = "repair_with_whitelist"
    if not repair_files:
        repair_files = sorted((data_dir / "repair").glob("*_repairs.json"))
        source = "repair"

    payload = _load_json(repair_files[0]) if repair_files else {}
    payload = payload if isinstance(payload, dict) else {"repairs": payload if isinstance(payload, list) else []}
    repairs = payload.get("repairs", []) if isinstance(payload, dict) else []
    repair = repairs[0] if repairs else {}
    pair = repair.get("function_pair", {}) if isinstance(repair, dict) else {}
    validation = payload.get("validation_result", {}) if isinstance(payload, dict) else {}
    whitelist = repair.get("whitelist") if isinstance(repair, dict) else None
    rules = 0
    syscall_rules: list[dict] = []
    if isinstance(whitelist, dict):
        for name, values in whitelist.items():
            count = len(values) if isinstance(values, list) else 1
            rules += count
            syscall_rules.append({"name": name, "count": count, "values": values if isinstance(values, list) else [values]})
    elif isinstance(whitelist, list):
        rules = len(whitelist)
        syscall_rules.append({"name": "whitelist", "count": len(whitelist), "values": whitelist})

    log_tail: list[str] = []
    log_path = data_dir / "pipeline.log"
    if log_path.exists():
        try:
            log_tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]
        except Exception:
            log_tail = []

    timing = _load_json(data_dir / "timing.json")
    feedback = _load_json(data_dir / "feedback_attempts.json")
    timing = _merge_feedback_stage_timing(timing if isinstance(timing, dict) else {}, feedback)
    stage_statuses = _stage_statuses(data_dir, timing if isinstance(timing, dict) else {}, feedback)
    function_name = repair.get("function_name") if isinstance(repair, dict) else None
    return {
        "directory": str(data_dir.relative_to(ROOT)),
        "source": source,
        "repair_file": str(repair_files[0].relative_to(ROOT)) if repair_files else None,
        "function_name": function_name,
        "function_path": repair.get("function_path") if isinstance(repair, dict) else None,
        "start_line": repair.get("start_line") if isinstance(repair, dict) else None,
        "end_line": repair.get("end_line") if isinstance(repair, dict) else None,
        "repair_method": repair.get("repair_method") if isinstance(repair, dict) else None,
        "repair_code": repair.get("repair_code") if isinstance(repair, dict) else "",
        "original_code": _find_original_source(repair, function_name),
        "analysis": repair.get("analysis") if isinstance(repair, dict) else "",
        "rank": pair.get("rank") if isinstance(pair, dict) else None,
        "score": pair.get("normalized_score") if isinstance(pair, dict) else None,
        "validation": validation,
        "rules": rules,
        "syscall_rules": syscall_rules[:20],
        "timing": timing if isinstance(timing, dict) else {},
        "stage_statuses": stage_statuses,
        "feedback": feedback if isinstance(feedback, dict) else {},
        "collection": _collection_params_from_log(data_dir),
        "log_tail": log_tail,
    }


def build_command(request: RunRequest) -> list[str]:
    if not CVE_PATTERN.fullmatch(request.cve):
        raise HTTPException(422, "Invalid CVE identifier")
    if request.start_stage > request.end_stage:
        raise HTTPException(422, "start_stage must not exceed end_stage")
    if os.getenv("KINTSUGI_COMMAND_TEMPLATE"):
        values = {
            "cve": request.cve,
            "start_stage": request.start_stage,
            "end_stage": request.end_stage,
            "collector": request.collector,
            "model": request.model,
        }
        try:
            return shlex.split(COMMAND_TEMPLATE.format_map(values))
        except (KeyError, ValueError) as exc:
            raise HTTPException(500, f"Invalid KINTSUGI_COMMAND_TEMPLATE: {exc}") from exc

    command = [
        sys.executable,
        "main.py",
        "--cve", request.cve,
        "--stage", f"{request.start_stage}-{request.end_stage}",
        "--max-repairs", str(request.max_repairs),
        "--feedback-attempts", str(request.feedback_attempts),
        "--threshold", str(request.threshold),
        "--repair-mode", request.repair_mode,
        "--validate-mode", request.validate_mode,
        "--normal-time", str(request.normal_time),
        "--malicious-time", str(request.malicious_time),
        "--wait-time", str(request.wait_time),
        "--min-files", str(request.min_files),
        "--whitelist-mode", request.whitelist_mode,
        "--log-mode", request.log_mode,
        "--algo", *request.algo,
    ]
    return command


def prepare_subprocess_env() -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    notes: list[str] = []

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = env.get(name)
        if value and value.lower().startswith("socks://"):
            env[name] = "http://" + value[len("socks://"):]
            notes.append(f"Bridge normalized {name}: socks:// -> http://")

    return env, notes


def _hash_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


async def run_logged_command(
    job: Job,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    stdin_text: str | None = None,
) -> int:
    await emit(job, "log", line=f"Bridge prepare: {shlex.join(command)}")
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=cwd,
        env=env,
        stdin=asyncio.subprocess.PIPE if stdin_text else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    if stdin_text and process.stdin:
        process.stdin.write(stdin_text.encode("utf-8"))
        await process.stdin.drain()
        process.stdin.close()
    assert process.stdout is not None
    while line := await process.stdout.readline():
        await emit(job, "log", line=line.decode("utf-8", errors="replace").rstrip())
    return await process.wait()


async def run_compose_preparation(
    job: Job,
    env_dir: Path,
    args: list[str],
    env: dict[str, str],
) -> None:
    command = ["docker", "compose", *args]
    return_code = await run_logged_command(job, command, env_dir, env)
    if return_code == 0:
        return
    password = env.get("KINTSUGI_SUDO_PASSWORD") or DEFAULT_SUDO_PASSWORD
    if not password:
        raise RuntimeError(f"Docker compose failed: {shlex.join(command)}")
    sudo_command = ["sudo", "-S", "-p", "", "docker", "compose", *args]
    return_code = await run_logged_command(job, sudo_command, env_dir, env, stdin_text=f"{password}\n")
    if return_code != 0:
        raise RuntimeError(f"Docker compose failed: {shlex.join(command)}")


async def prepare_cve_image(job: Job, env: dict[str, str]) -> None:
    if not AUTO_PREPARE_IMAGES:
        return
    if job.request.cve != "CVE-2023-40033":
        return
    if job.request.start_stage > 1:
        return

    env_dir = ROOT / "cves" / "php" / "CVE-2023-40033" / "env"
    files = [
        env_dir / "Dockerfile",
        env_dir / "docker-compose.yml",
        env_dir / "install.sh",
        env_dir / "startup.sh",
    ]
    if not env_dir.is_dir() or not all(path.is_file() for path in files):
        await emit(job, "log", line="Bridge prepare skipped: CVE-2023-40033 env files are incomplete")
        return

    prepare_dir = ROOT / "data" / ".ui-prepared"
    prepare_dir.mkdir(parents=True, exist_ok=True)
    stamp = prepare_dir / "CVE-2023-40033.sha256"
    current = _hash_files(files)
    if stamp.is_file() and stamp.read_text(encoding="utf-8").strip() == current:
        await emit(job, "log", line="Bridge prepare skipped: CVE-2023-40033 image already matches env scripts")
        return

    await emit(job, "log", line="Bridge prepare: rebuilding CVE-2023-40033 Flarum image")
    await run_compose_preparation(job, env_dir, ["down", "-v", "--remove-orphans"], env)
    await run_compose_preparation(job, env_dir, ["build", "flarum"], env)
    stamp.write_text(current + "\n", encoding="utf-8")
    await emit(job, "log", line="Bridge prepare completed: CVE-2023-40033 image is ready")


def prepare_artifact_workspace(job: Job) -> tuple[Path, Path]:
    """Map one dated artifact to main.py's fixed data/<language>/<CVE> workspace."""
    language = _language_for_cve(job.request.cve)
    base_dir = ROOT / "data" / language / job.request.cve
    base_dir.parent.mkdir(parents=True, exist_ok=True)

    if job.request.run_target == "resume":
        if not job.request.artifact_directory:
            raise HTTPException(422, "artifact_directory is required when resuming a run")
        selected = _artifact_path(job.request.artifact_directory)
        if CVE_PREFIX_PATTERN.match(selected.name).group(1) != job.request.cve:
            raise HTTPException(422, "Selected artifact does not belong to this CVE")
        final_dir = selected if selected != base_dir else _dated_artifact_path(language, job.request.cve, selected.stat().st_mtime)
        if selected != base_dir:
            if base_dir.exists():
                shutil.move(str(base_dir), str(_dated_artifact_path(language, job.request.cve, base_dir.stat().st_mtime)))
            shutil.move(str(selected), str(base_dir))
    else:
        if base_dir.exists():
            shutil.move(str(base_dir), str(_dated_artifact_path(language, job.request.cve, base_dir.stat().st_mtime)))
        final_dir = (ROOT / job.artifact_directory).resolve() if job.artifact_directory else _reserved_dated_artifact_path(language, job.request.cve, job.created_at)

    job.artifact_directory = str(final_dir.relative_to(ROOT))
    return base_dir, final_dir


def finalize_artifact_workspace(base_dir: Path, final_dir: Path, job: Job) -> None:
    if not base_dir.exists():
        job.artifact_directory = None
        return
    if final_dir.exists():
        final_dir = _dated_artifact_path(final_dir.parent.name, job.request.cve)
    shutil.move(str(base_dir), str(final_dir))
    merge_residual_base_dir(base_dir, final_dir)
    job.artifact_directory = str(final_dir.relative_to(ROOT))


def merge_residual_base_dir(base_dir: Path, final_dir: Path) -> None:
    """
    main.py writes to data/<language>/<CVE>; bridge moves that workspace to a
    dated artifact after the process exits. If a small late file is recreated in
    the base workspace during shutdown, fold it into the dated artifact so the UI
    never sees one run as two results.
    """
    for _ in range(8):
        time.sleep(0.15)
        if not base_dir.exists():
            continue
        for child in list(base_dir.iterdir()):
            target = final_dir / child.name
            if target.exists():
                if child.is_file() and child.name in {"timing.json", "feedback_attempts.json"}:
                    target.unlink()
                else:
                    target = final_dir / f".residual-{int(time.time())}-{child.name}"
            shutil.move(str(child), str(target))
        try:
            base_dir.rmdir()
        except OSError:
            pass
        if not base_dir.exists():
            break


async def emit(job: Job, event: str, **payload: object) -> None:
    async with job.changed:
        job.events.append({"event": event, "data": payload, "index": len(job.events)})
        job.changed.notify_all()


def update_job_stage_from_log(job: Job, line: str) -> None:
    match = STAGE_LOG_PATTERN.search(line)
    if not match:
        return
    stage = int(match.group(1))
    raw_label = (match.group(2) or "").strip()
    job.current_stage = stage
    if "completed" in line.lower():
        job.current_stage_label = f"Stage {stage} completed"
    else:
        job.current_stage_label = f"Stage {stage}{': ' + raw_label if raw_label else ''}"


async def execute(job: Job) -> None:
    async with run_lock:
        if job.status == "cancelled":
            return
        job.status = "running"
        job.started_at = time.time()
        base_dir: Path | None = None
        final_dir: Path | None = None
        try:
            base_dir, final_dir = prepare_artifact_workspace(job)
            await emit(
                job, "status", status=job.status, command=job.command,
                artifact_directory=job.artifact_directory, run_target=job.request.run_target,
            )
            await emit(job, "log", line=f"Bridge artifact target: {job.artifact_directory}")
            env, env_notes = prepare_subprocess_env()
            for note in env_notes:
                await emit(job, "log", line=note)
            venv_bin = ROOT / ".venv" / "bin"
            if venv_bin.is_dir():
                env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
            if job.request.sudo_password:
                env["KINTSUGI_SUDO_PASSWORD"] = job.request.sudo_password.get_secret_value()
            elif DEFAULT_SUDO_PASSWORD:
                env["KINTSUGI_SUDO_PASSWORD"] = DEFAULT_SUDO_PASSWORD
            await prepare_cve_image(job, env)
            job.process = await asyncio.create_subprocess_exec(
                *job.command,
                cwd=ROOT,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            assert job.process.stdout is not None
            while line := await job.process.stdout.readline():
                text = line.decode("utf-8", errors="replace").rstrip()
                update_job_stage_from_log(job, text)
                await emit(job, "log", line=text)
            job.return_code = await job.process.wait()
            if job.status != "cancelled":
                job.status = "succeeded" if job.return_code == 0 else "failed"
        except asyncio.CancelledError:
            job.status = "cancelled"
            raise
        except Exception as exc:
            job.status = "failed"
            await emit(job, "error", message=str(exc))
        finally:
            if base_dir is not None and final_dir is not None:
                try:
                    finalize_artifact_workspace(base_dir, final_dir, job)
                    if job.status == "succeeded" and job.request.end_stage >= 10 and job.artifact_directory:
                        artifact_status = _artifact_status(_artifact_path(job.artifact_directory))[0]
                        if artifact_status != "成功":
                            job.status = "failed"
                            await emit(job, "log", line=f"Bridge validation status: {artifact_status}")
                except Exception as exc:
                    job.status = "failed"
                    await emit(job, "error", message=f"Failed to finalize artifact directory: {exc}")
            job.finished_at = time.time()
            await emit(
                job, "status", status=job.status, return_code=job.return_code,
                artifact_directory=job.artifact_directory,
            )


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": app.version,
        "docker": await docker_available(),
        "root": str(ROOT),
        "main_py": (ROOT / "main.py").is_file(),
    }


@app.get("/auth-status")
async def auth_status() -> dict:
    return {
        "token_required": bool(BRIDGE_TOKEN),
        "mode": "token" if BRIDGE_TOKEN else "local",
    }


@app.post("/preflight")
async def preflight(request: RunRequest) -> dict:
    command = build_command(request)
    target_detail = "创建新的日期时间产物目录"
    target_status = "pass"
    if request.run_target == "resume":
        try:
            selected_artifact = _artifact_path(request.artifact_directory or "")
            selected_cve = CVE_PREFIX_PATTERN.match(selected_artifact.name).group(1)
            if selected_cve != request.cve:
                raise HTTPException(422, "Selected artifact does not belong to this CVE")
            target_detail = f"继续运行 {selected_artifact.relative_to(ROOT)}"
        except HTTPException as exc:
            target_status = "fail"
            target_detail = str(exc.detail)
    help_ok, help_output = await main_help()
    docker_ok = await docker_available()
    collectors = await collector_diagnostics()
    stage2_selected = request.start_stage <= 2 <= request.end_stage
    sysdig_required = request.collector == "sysdig" and stage2_selected
    strace_required = request.collector == "strace" and stage2_selected
    auto_ready = collectors["sysdig"]["usable"] or collectors["strace"]["usable"]
    selected_collector_ready = auto_ready if request.collector == "auto" else collectors[request.collector]["usable"]
    checks = [
        {"id": "python", "label": "Python 运行环境", "status": "pass", "critical": True, "detail": sys.version.split()[0]},
        {"id": "main", "label": "main.py", "status": "pass" if (ROOT / "main.py").is_file() else "fail", "critical": True, "detail": str(ROOT / "main.py")},
        {"id": "help", "label": "main.py 参数入口", "status": "pass" if help_ok else "warn", "critical": False, "detail": "--help 可执行" if help_ok else help_output},
        {"id": "docker", "label": "Docker Engine", "status": "pass" if docker_ok else "warn", "critical": request.start_stage <= 2, "detail": "docker info succeeded" if docker_ok else "Docker 不可用或无权限"},
        {"id": "sysdig", "label": "Sysdig 驱动采集", "status": "pass" if collectors["sysdig"]["usable"] else "fail" if sysdig_required else "warn", "critical": sysdig_required, "detail": collectors["sysdig"]["detail"]},
        {"id": "strace", "label": "Strace fallback", "status": "pass" if collectors["strace"]["usable"] else "fail" if strace_required else "warn", "critical": strace_required, "detail": collectors["strace"]["detail"]},
        {"id": "collector", "label": "Stage 2 采集路径", "status": "pass" if not stage2_selected or selected_collector_ready else "fail", "critical": stage2_selected, "detail": "不执行 Stage 2" if not stage2_selected else "Sysdig 可用" if collectors["sysdig"]["usable"] else "将使用 Strace fallback" if collectors["strace"]["usable"] and request.collector != "sysdig" else "没有可用采集器"},
        {"id": "data", "label": "数据目录", "status": "pass" if (ROOT / "data").is_dir() else "warn", "critical": False, "detail": str(ROOT / "data")},
        {"id": "target", "label": "运行目标", "status": target_status, "critical": True, "detail": target_detail},
        {"id": "command", "label": "命令构造", "status": "pass", "critical": True, "detail": shlex.join(command)},
    ]
    ready = not any(item["critical"] and item["status"] != "pass" for item in checks)
    warnings = sum(item["status"] == "warn" for item in checks)
    return {"ready": ready, "warnings": warnings, "checks": checks, "command": command, "help_excerpt": help_output[-1200:], "collectors": collectors}


@app.get("/collectors")
async def collectors() -> dict:
    return await collector_diagnostics()


@app.post("/runs", status_code=202)
async def create_run(request: RunRequest) -> dict:
    if not (ROOT / "main.py").is_file():
        raise HTTPException(503, f"main.py not found under KINTSUGI_ROOT={ROOT}")
    command = build_command(request)
    if request.run_target == "resume":
        selected_artifact = _artifact_path(request.artifact_directory or "")
        if CVE_PREFIX_PATTERN.match(selected_artifact.name).group(1) != request.cve:
            raise HTTPException(422, "Selected artifact does not belong to this CVE")
        artifact_directory = request.artifact_directory
    else:
        language = _language_for_cve(request.cve)
        artifact_directory = str(_reserved_dated_artifact_path(language, request.cve).relative_to(ROOT))
    run_id = f"RUN-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    job = Job(
        run_id=run_id,
        request=request,
        command=command,
        artifact_directory=artifact_directory,
    )
    jobs[run_id] = job
    await emit(job, "status", status=job.status, command=job.command)
    await emit(job, "log", line="Bridge queued: waiting for the single local runner")
    asyncio.create_task(execute(job))
    return {**job.public(), "events_url": f"/runs/{run_id}/events"}


@app.get("/runs")
async def list_runs() -> list[dict]:
    return [job.public() for job in sorted(jobs.values(), key=lambda item: item.created_at, reverse=True)]


@app.get("/artifacts")
async def list_artifacts(cve: str | None = None) -> list[dict]:
    return scan_artifact_runs(cve)


@app.get("/artifact-detail")
async def get_artifact_detail(directory: str) -> dict:
    return artifact_detail(directory)


@app.delete("/artifacts/{cve}")
async def clear_artifacts(cve: str, sudo_password: str | None = None) -> dict:
    return clear_artifact_history(cve, sudo_password)


@app.delete("/artifact")
async def remove_artifact(directory: str, sudo_password: str | None = None) -> dict:
    return delete_artifact(directory, sudo_password)


@app.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    job = jobs.get(run_id)
    if not job:
        raise HTTPException(404, "Run not found")
    return job.public()


@app.delete("/runs/{run_id}")
async def delete_run(run_id: str) -> dict:
    job = jobs.get(run_id)
    if not job:
        raise HTTPException(404, "Run not found")
    if job.status in {"queued", "running"}:
        raise HTTPException(409, "Active runs must be cancelled before deletion")
    jobs.pop(run_id, None)
    return {"deleted": run_id}


async def event_stream(job: Job) -> AsyncIterator[str]:
    cursor = 0
    while True:
        while cursor < len(job.events):
            item = job.events[cursor]
            cursor += 1
            yield f"id: {item['index']}\nevent: {item['event']}\ndata: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
        if job.status in {"succeeded", "failed", "cancelled"}:
            break
        try:
            async with job.changed:
                await asyncio.wait_for(job.changed.wait(), timeout=15)
        except asyncio.TimeoutError:
            yield ": keep-alive\n\n"


@app.get("/runs/{run_id}/events")
async def run_events(run_id: str) -> StreamingResponse:
    job = jobs.get(run_id)
    if not job:
        raise HTTPException(404, "Run not found")
    return StreamingResponse(event_stream(job), media_type="text/event-stream")


@app.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: str) -> dict:
    job = jobs.get(run_id)
    if not job:
        raise HTTPException(404, "Run not found")
    if job.status not in {"queued", "running"}:
        raise HTTPException(409, f"Run is already {job.status}")
    if job.process and job.process.returncode is None:
        try:
            os.killpg(job.process.pid, signal.SIGTERM)
            await asyncio.wait_for(job.process.wait(), timeout=5)
        except asyncio.TimeoutError:
            os.killpg(job.process.pid, signal.SIGKILL)
    job.status = "cancelled"
    job.finished_at = time.time()
    await emit(job, "status", status=job.status)
    return job.public()
