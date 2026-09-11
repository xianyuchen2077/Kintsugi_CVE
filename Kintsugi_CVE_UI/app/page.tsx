"use client";

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { deriveRepairStory } from "./repair-story.mjs";

/**
 * Kintsugi 的固定执行阶段。数组下标就是 Stage 编号，因此不要随意调整顺序。
 * 每项依次为：后端阶段名、中文名称、演示用耗时。
 * 接入真实后端后，耗时应由运行历史接口覆盖，而不是修改这里的示例值。
 */
const stages = [
  ["up", "启动环境", "2.8s"], ["build", "部署插件", "18.4s"],
  ["collect", "采集流量", "64.2s"], ["parse", "解析轨迹", "跳过"],
  ["segment", "请求切分", "4.7s"], ["callstack", "重建调用栈", "12.1s"],
  ["extract", "提取源码", "8.6s"], ["detect", "异常检测", "73.9s"],
  ["repair", "生成修复", "25.3s"], ["whitelist", "填充白名单", "9.8s"],
  ["validate", "验证效果", "31.6s"], ["down", "清理环境", "2.4s"],
];

const cves = [
  { id: "CVE-2023-40033", lang: "PHP", app: "Flarum SSRF" },
  { id: "CVE-2024-25737", lang: "PHP", app: "VuFind" },
  { id: "CVE-2017-18638", lang: "Python", app: "Graphite SSRF" },
  { id: "CVE-2022-4223", lang: "Python", app: "pgAdmin" },
  { id: "CVE-2018-16509", lang: "Python", app: "Pillow" },
  { id: "CVE-2024-25738", lang: "PHP", app: "VuFind" },
  { id: "CVE-2022-46169", lang: "PHP", app: "Cacti" },
  { id: "CVE-2021-33926", lang: "Python", app: "Plone RSS SSRF" },
  { id: "CVE-2023-47116", lang: "Python", app: "Label Studio" },
  { id: "CVE-2025-31116", lang: "Python", app: "MobSF" },
];

const DEFAULT_CVE = "CVE-2024-25737";

const DEFAULT_BRIDGE_URL = "http://localhost:8765";
const BRIDGE_URL_STORAGE_KEY = "kintsugi-bridge-url";
const BRIDGE_TOKEN_STORAGE_KEY = "kintsugi-bridge-token";
const DEFAULT_SUDO_PASSWORD = "";
const detectionAlgoOptions = [
  {value: "all", label: "all · 全部算法"},
  {value: "jaccard", label: "jaccard"},
  {value: "ngram", label: "ngram"},
  {value: "file", label: "file"},
  {value: "proc", label: "proc"},
  {value: "internal", label: "internal"},
  {value: "n_ips", label: "n_ips"},
  {value: "n_ports", label: "n_ports"},
  {value: "jaccard ngram", label: "jaccard + ngram"},
  {value: "ngram file", label: "ngram + file"},
  {value: "jaccard ngram file", label: "jaccard + ngram + file"},
];

const navItems = ["运行总览", "新建任务", "运行控制台", "检测与修复", "白名单与验证", "历史运行", "最近结果"] as const;
const navIcons: Record<(typeof navItems)[number], string> = {
  运行总览: "◎",
  新建任务: "+",
  运行控制台: "▶",
  检测与修复: "◇",
  白名单与验证: "✓",
  历史运行: "↺",
  最近结果: "⌁",
};

type RunStatus = "idle"|"queued"|"running"|"succeeded"|"failed"|"cancelled"|"disconnected";

type BridgeEvent = {
  index?: number;
  event?: string;
  data?: Record<string, unknown>;
};

type BridgeRun = {
  run_id: string;
  cve: string;
  status: RunStatus | string;
  command?: string[];
  created_at?: number;
  started_at?: number | null;
  finished_at?: number | null;
  return_code?: number | null;
  artifact_directory?: string | null;
  current_stage?: number | null;
  current_stage_label?: string;
  run_target?: string;
  event_count?: number;
  recent_events?: BridgeEvent[];
};

type ActiveRunSummary = {
  cve: string;
  runId: string;
  status: RunStatus;
  progress: number;
  running: boolean;
  currentStage?: number | null;
  currentStageLabel?: string;
};

type HistoryRecord = {
  id: string;
  cve: string;
  date: string;
  status: string;
  duration: string;
  seconds: number;
  candidates: number;
  repair: string;
  rules: number;
  normal: string;
  malicious: string;
  collector: string;
  note: string;
  directory?: string;
  source?: string;
  stage_count?: number;
  mtime?: number;
};

type ArtifactSelectionProps = {
  selectedArtifactId?: string;
  onSelectedArtifactIdChange?: (id: string) => void;
};

type ArtifactDetail = {
  directory: string;
  repair_file?: string | null;
  function_name?: string | null;
  function_path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  repair_method?: string | null;
  repair_code?: string;
  original_code?: string;
  analysis?: string;
  rank?: number | null;
  score?: number | null;
  validation?: {normal_ok?: boolean; malicious_blocked?: boolean; success?: boolean};
  rules?: number;
  syscall_rules?: Array<{name:string; count:number; values:string[]}>;
  timing?: Record<string,{duration?:number; timestamp?:string}>;
  stage_statuses?: StageStatus[];
  feedback?: {max_feedback_attempts?: number; attempts?: FeedbackAttempt[]};
  collection?: {normal_time?: number; malicious_time?: number; source?: string};
  log_tail?: string[];
};

type FeedbackAttempt = {
  attempt?: number;
  success?: boolean;
  duration?: number;
  normal_ok?: boolean;
  malicious_blocked?: boolean;
  route_stage?: number;
  route_label?: string;
  route_reason?: string;
  route_action?: string;
  threshold?: number;
  next_route?: {stage?: number | null; reason?: string; action?: string; threshold?: number};
  stage_durations?: Record<string, number>;
  feedback_triggered?: boolean;
};

type StageStatus = {
  stage: number;
  status: "done" | "feedback" | "failed" | "started" | "missing";
  duration?: number | null;
  source?: string;
};

type DiffLine = {
  kind: "context" | "add" | "remove";
  text: string;
  oldLine: number | null;
  newLine: number | null;
};

type RepairDetailView = "summary" | "changes" | "protection" | "validation";

function inferBridgeUrl() {
  if (typeof window === "undefined") return DEFAULT_BRIDGE_URL;
  const saved = window.localStorage.getItem(BRIDGE_URL_STORAGE_KEY);
  if (saved?.trim()) return saved.trim();
  const host = window.location.hostname;
  if (host && host !== "localhost" && host !== "127.0.0.1") {
    return `${window.location.protocol}//${host}:8765`;
  }
  return DEFAULT_BRIDGE_URL;
}

function getBridgeToken() {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(BRIDGE_TOKEN_STORAGE_KEY)?.trim() || "";
}

function bridgeHeaders(headers: HeadersInit = {}) {
  const token = getBridgeToken();
  return token ? {...headers, Authorization: `Bearer ${token}`} : headers;
}

function bridgeFetch(pathOrUrl: string, init: RequestInit = {}) {
  const url = pathOrUrl.startsWith("http") ? pathOrUrl : `${inferBridgeUrl().replace(/\/$/,"")}${pathOrUrl}`;
  return fetch(url, {...init, headers: bridgeHeaders(init.headers || {})});
}

function bridgeEventSourceUrl(path: string, baseUrl = inferBridgeUrl()) {
  const token = getBridgeToken();
  const url = new URL(path, `${baseUrl.replace(/\/$/,"")}/`);
  if (token) url.searchParams.set("token", token);
  return url.toString();
}

function isLocalBrowserHost() {
  if (typeof window === "undefined") return true;
  return ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
}

function buildLineDiff(original: string, repaired: string): DiffLine[] {
  const before = original ? original.replace(/\r\n/g, "\n").split("\n") : [];
  const after = repaired ? repaired.replace(/\r\n/g, "\n").split("\n") : [];
  const table = Array.from({length: before.length + 1}, () => new Uint16Array(after.length + 1));
  for (let i = before.length - 1; i >= 0; i -= 1) {
    for (let j = after.length - 1; j >= 0; j -= 1) {
      table[i][j] = before[i] === after[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < before.length || j < after.length) {
    if (i < before.length && j < after.length && before[i] === after[j]) {
      lines.push({kind:"context", text:before[i], oldLine:i + 1, newLine:j + 1}); i += 1; j += 1;
    } else if (j < after.length && (i === before.length || table[i][j + 1] >= table[i + 1][j])) {
      lines.push({kind:"add", text:after[j], oldLine:null, newLine:j + 1}); j += 1;
    } else {
      lines.push({kind:"remove", text:before[i], oldLine:i + 1, newLine:null}); i += 1;
    }
  }
  return lines;
}

function HighlightedLine({code, language}: {code:string; language:"php"|"python"}) {
  const keywords = language === "php"
    ? "public|protected|private|function|return|if|else|foreach|try|catch|finally|require_once|true|false|null|new|as"
    : "def|return|if|elif|else|for|while|try|except|finally|with|as|import|from|in|is|not|and|or|True|False|None|class|raise";
  const builtins = language === "php"
    ? "array|isset|empty|count|parse_url|filter_var|strtolower|preg_match|curl_exec|json_encode|json_decode"
    : "len|str|int|float|bool|list|dict|set|tuple|open|range|isinstance|json|requests|ValidationError|settings|SimpleUploadedFile";
  const tokenPattern = new RegExp(`("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|//.*$|#.*$|\\b(?:${keywords})\\b|\\b(?:${builtins})\\b|\\b[A-Za-z_]\\w*(?=\\s*\\()|\\$[A-Za-z_]\\w*|\\b\\d+(?:\\.\\d+)?\\b|[{}()[\\].,;:=+\\-*/<>])`, "g");
  return <>{code.split(tokenPattern).filter(part=>part!=="").map((part, index) => {
    let kind = "plain";
    if (/^(\/\/|#)/.test(part)) kind = "comment";
    else if (/^["']/.test(part)) kind = "string";
    else if (/^\$/.test(part)) kind = "variable";
    else if (/^\d/.test(part)) kind = "number";
    else if (new RegExp(`^(?:${keywords})$`).test(part)) kind = "keyword";
    else if (new RegExp(`^(?:${builtins})$`).test(part)) kind = "builtin";
    else if (/^[A-Za-z_]\w*$/.test(part)) kind = "function";
    else if (/^[{}()[\].,;:=+\-*/<>]$/.test(part)) kind = "punctuation";
    return <span className={`syntax-${kind}`} key={`${index}-${part.slice(0,8)}`}>{part}</span>;
  })}</>;
}

function totalRepairAttempts(detail: ArtifactDetail | null | undefined, selected?: HistoryRecord) {
  const attempts = detail?.feedback?.attempts?.length ?? 0;
  if (attempts > 0) return attempts;
  return detail?.repair_file || detail?.validation || selected ? 1 : 0;
}

function durationText(seconds: number | null | undefined) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "—";
  return `${seconds.toFixed(1)}s`;
}

function deriveStageStatuses(detail: ArtifactDetail | null | undefined): StageStatus[] {
  if (detail?.stage_statuses?.length) {
    const byStage = new Map(detail.stage_statuses.map(item => [item.stage, item]));
    return stages.map((_, stage) => byStage.get(stage) || {stage, status: "missing", duration: null, source: "未找到运行证据"});
  }

  const timing = detail?.timing || {};
  const feedbackKeys = new Set<string>();
  const attempts = detail?.feedback?.attempts || [];
  const feedbackRetried = attempts.some(attempt => attempt.feedback_triggered);
  for (const attempt of attempts) {
    if (!attempt.feedback_triggered) continue;
    const stageDurations = attempt.stage_durations;
    if (!stageDurations) continue;
    for (const key of Object.keys(stageDurations)) {
      if (key.startsWith("stage_")) feedbackKeys.add(key);
    }
  }

  return stages.map((_, stage) => {
    const key = `stage_${stage}`;
    const item = timing[key];
    if (item && typeof item === "object") {
      const feedback = feedbackRetried && feedbackKeys.has(key) && stage >= 8 && stage <= 10;
      return {
        stage,
        status: feedback ? "feedback" : "done",
        duration: item.duration,
        source: feedback ? "反馈循环" : "timing.json",
      };
    }
    return {stage, status: "missing", duration: null, source: "未找到运行证据"};
  });
}

function stageVisual(status: StageStatus["status"]) {
  if (status === "done") return {className: "done", mark: "✓", label: "完成"};
  if (status === "feedback") return {className: "feedback", mark: "↺", label: "反馈完成"};
  if (status === "failed") return {className: "failed", mark: "!", label: "异常"};
  if (status === "started") return {className: "started", mark: "…", label: "执行过"};
  return {className: "skipped", mark: "–", label: "未运行"};
}

function parseNumericDraft(value: string, fallback: number, min: number, max: number, integer = false) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const bounded = Math.min(max, Math.max(min, parsed));
  return integer ? Math.round(bounded) : bounded;
}

function normalizeNumericDraft(value: string, fallback: number, min: number, max: number, integer = false) {
  return String(parseNumericDraft(value, fallback, min, max, integer));
}

function isActiveBridgeRun(run?: BridgeRun | null) {
  return run?.status === "queued" || run?.status === "running";
}

function runStatusLabel(status?: string) {
  if (status === "queued") return "排队中";
  if (status === "running") return "运行中";
  if (status === "succeeded") return "成功";
  if (status === "failed") return "失败";
  if (status === "cancelled") return "已取消";
  return "未开始";
}

function runStageLabel(run?: BridgeRun | null) {
  if (!run) return "无任务";
  if (run.status === "queued") return "排队中";
  if (typeof run.current_stage === "number") {
    const stageName = stages[run.current_stage]?.[1] || "运行中";
    return run.current_stage_label || `Stage ${run.current_stage} · ${stageName}`;
  }
  return run.current_stage_label || runStatusLabel(run.status);
}

function bridgeRunProgress(run?: BridgeRun | null) {
  if (!run) return 0;
  if (run.status === "succeeded") return 100;
  if (run.status === "failed" || run.status === "cancelled") return typeof run.current_stage === "number" ? Math.min(100, Math.round(((run.current_stage + 1) / stages.length) * 100)) : 100;
  if (run.status === "queued") return 0;
  if (typeof run.current_stage !== "number") return 4;
  return Math.max(5, Math.min(96, Math.round(((run.current_stage + 1) / stages.length) * 100)));
}

function progressForAbsoluteStage(stage: number) {
  return Math.max(5, Math.min(96, Math.round(((stage + 1) / stages.length) * 100)));
}

function bridgeRunProgressState(run?: BridgeRun | null) {
  const progress = bridgeRunProgress(run);
  let peak = progress;
  let rewindFrom = 0;
  for (const event of run?.recent_events || []) {
    if (event.event !== "log" || event.data?.line === undefined) continue;
    const line = String(event.data.line);
    const stageMatch = line.match(/Stage\s+(\d+)/i);
    if (stageMatch) {
      peak = Math.max(peak, progressForAbsoluteStage(Number(stageMatch[1])));
    }
    const routeMatch = line.match(/feedback route:.*?return to Stage\s+(\d+)/i);
    if (routeMatch) {
      const routeProgress = progressForAbsoluteStage(Number(routeMatch[1]));
      rewindFrom = Math.max(rewindFrom, peak, routeProgress);
      peak = Math.max(peak, rewindFrom);
    }
  }
  if (!isActiveBridgeRun(run)) rewindFrom = 0;
  if (rewindFrom <= progress) rewindFrom = 0;
  return {progress, peak: Math.max(progress, peak), rewindFrom};
}

function runCreatedText(run?: BridgeRun | null) {
  if (!run?.created_at) return "未知时间";
  return new Date(run.created_at * 1000).toLocaleString("zh-CN", {hour12: false});
}

function feedbackRoutes(detail: ArtifactDetail | null | undefined) {
  return (detail?.feedback?.attempts || []).filter(attempt => attempt.feedback_triggered && (typeof attempt.route_stage === "number" || attempt.route_reason || attempt.next_route?.reason));
}

function useBridgeRuns(enabled = true) {
  const [runs, setRuns] = useState<BridgeRun[]>([]);
  const [loading, setLoading] = useState(false);
  const refresh = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    try {
      const response = await bridgeFetch("/runs", {signal: AbortSignal.timeout(3000)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (Array.isArray(data)) setRuns(data as BridgeRun[]);
    } catch {
      setRuns(values => values);
    } finally {
      setLoading(false);
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      await refresh();
    };
    tick();
    const timer = window.setInterval(tick, 1800);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [enabled, refresh]);

  return {runs, loading, refresh};
}

/**
 * 运行控制台通过本地 Bridge 提交任务，并使用 SSE 接收阶段日志。
 */
function RunConsole({ cve, onRunStateChange, onTaskAccepted, selectedArtifactId, onSelectedArtifactIdChange, bridgeAuthRequired = false }: { cve: string; onRunStateChange?: (run: ActiveRunSummary) => void; onTaskAccepted?: (run: BridgeRun) => void; bridgeAuthRequired?: boolean } & ArtifactSelectionProps) {
  const [start, setStart] = useState(0);
  const [end, setEnd] = useState(11);
  const [collector, setCollector] = useState("auto");
  const [thresholdInput, setThresholdInput] = useState("0.5");
  const [repairMode, setRepairMode] = useState<"filter"|"direct"|"direct_localization">("filter");
  const [validateMode, setValidateMode] = useState<"normal"|"abnormal"|"all">("all");
  const [logMode, setLogMode] = useState<"append"|"overwrite">("append");
  const [runTarget, setRunTarget] = useState<"new"|"resume">("new");
  const [artifactDirectory, setArtifactDirectory] = useState("");
  const [maxRepairsInput, setMaxRepairsInput] = useState("1");
  const [feedbackAttemptsInput, setFeedbackAttemptsInput] = useState("1");
  const [normalTimeInput, setNormalTimeInput] = useState("60");
  const [maliciousTimeInput, setMaliciousTimeInput] = useState("20");
  const [algo, setAlgo] = useState("all");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [output, setOutput] = useState<string[]>([]);
  const [bridgeUrl, setBridgeUrl] = useState(inferBridgeUrl);
  const [bridgeToken, setBridgeToken] = useState(getBridgeToken);
  const [connection, setConnection] = useState<"idle"|"testing"|"online"|"offline">("idle");
  const [connectionMessage, setConnectionMessage] = useState("尚未检查本地连接");
  const [runId, setRunId] = useState("");
  const [runStatus, setRunStatus] = useState<RunStatus>("idle");
  const [progressPeak, setProgressPeak] = useState(0);
  const [rewindFrom, setRewindFrom] = useState(0);
  const [feedbackRound, setFeedbackRound] = useState(1);
  const [feedbackTotal, setFeedbackTotal] = useState(1);
  const [currentStage, setCurrentStage] = useState<number | null>(null);
  const [currentStageLabel, setCurrentStageLabel] = useState("尚未开始");
  const [preflight, setPreflight] = useState<{ready:boolean;warnings:number;checks:Array<{id:string;label:string;status:"pass"|"warn"|"fail";critical:boolean;detail:string}>;command:string[]}|null>(null);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logBodyRef = useRef<HTMLDivElement | null>(null);
  const followLogRef = useRef(true);
  const lastEventIndexRef = useRef(-1);
  const lastUserScrollAtRef = useRef(0);
  const finishedRunRef = useRef(false);
  const freezeScrollTopRef = useRef(0);
  const suppressScrollRef = useRef(false);
  const progressPeakRef = useRef(0);
  const rewindFromRef = useRef(0);
  const feedbackRoundRef = useRef(1);
  const [followingLog, setFollowingLog] = useState(true);
  const history = useHistoryData(cve);
  const resumableArtifacts = history.records.filter(record => record.source === "artifact" && record.directory);
  const threshold = parseNumericDraft(thresholdInput, 0.5, 0, 1);
  const maxRepairs = parseNumericDraft(maxRepairsInput, 1, 1, 20, true);
  const feedbackAttempts = parseNumericDraft(feedbackAttemptsInput, 0, 0, 10, true);
  const normalTime = parseNumericDraft(normalTimeInput, 60, 1, 3600, true);
  const maliciousTime = parseNumericDraft(maliciousTimeInput, 20, 1, 3600, true);
  useEffect(() => {
    window.localStorage.setItem(BRIDGE_URL_STORAGE_KEY, bridgeUrl.trim() || DEFAULT_BRIDGE_URL);
  }, [bridgeUrl]);
  useEffect(() => {
    if (bridgeToken.trim()) window.localStorage.setItem(BRIDGE_TOKEN_STORAGE_KEY, bridgeToken.trim());
    else window.localStorage.removeItem(BRIDGE_TOKEN_STORAGE_KEY);
  }, [bridgeToken]);
  const requestBody = {
    cve,
    start_stage: start,
    end_stage: end,
    collector,
    max_repairs: maxRepairs,
    feedback_attempts: feedbackAttempts,
    normal_time: normalTime,
    malicious_time: maliciousTime,
    threshold,
    repair_mode: repairMode,
    validate_mode: validateMode,
    log_mode: logMode,
    run_target: runTarget,
    artifact_directory: runTarget === "resume" ? artifactDirectory : undefined,
    algo: algo.trim().split(/\s+/).filter(Boolean),
  };
  const command = `python main.py --cve ${cve} --stage ${start}-${end} --normal-time ${normalTime} --malicious-time ${maliciousTime} --threshold ${threshold} --repair-mode ${repairMode} --validate-mode ${validateMode} --feedback-attempts ${feedbackAttempts} --log-mode ${logMode} --algo ${requestBody.algo.join(" ")}`;
  const currentStageText = currentStage === null
    ? currentStageLabel
    : `Stage ${currentStage} · ${currentStageLabel || stages[currentStage]?.[1] || "运行中"}`;

  const isLogAtBottom = useCallback(() => {
    const element = logBodyRef.current;
    if (!element) return true;
    if (element.clientHeight === 0) return true;
    return element.scrollHeight - element.scrollTop - element.clientHeight <= 36;
  }, []);

  const progressForStage = useCallback((stage: number) => {
    const boundedStage = Math.max(start, Math.min(end, stage));
    const span = Math.max(1, end - start + 1);
    return Math.max(5, Math.min(96, Math.round(((boundedStage - start) / span) * 100) + 5));
  }, [start, end]);

  const applyRunProgress = useCallback((nextProgress: number, rewound = false) => {
    const next = Math.max(0, Math.min(100, Math.round(nextProgress)));
    setProgress(previous => {
      const peak = Math.max(progressPeakRef.current, previous);
      if (rewound || next < previous) {
        progressPeakRef.current = peak;
        rewindFromRef.current = Math.max(peak, next);
        setProgressPeak(progressPeakRef.current);
        setRewindFrom(rewindFromRef.current);
      } else {
        progressPeakRef.current = Math.max(peak, next);
        setProgressPeak(progressPeakRef.current);
        if (rewindFromRef.current && next >= rewindFromRef.current) {
          rewindFromRef.current = 0;
          setRewindFrom(0);
        }
      }
      return next;
    });
  }, []);

  const appendOutput = useCallback((update: string[] | ((lines: string[]) => string[])) => {
    const shouldFollow = followLogRef.current || isLogAtBottom();
    followLogRef.current = shouldFollow;
    setFollowingLog(shouldFollow);
    const element = logBodyRef.current;
    if (!shouldFollow && element) freezeScrollTopRef.current = element.scrollTop;
    setOutput(lines => Array.isArray(update) ? [...lines, ...update] : update(lines));
  }, [isLogAtBottom]);

  const processRunLogLine = useCallback((line: string) => {
    const routeMatch = line.match(/feedback route:.*?return to Stage\s+(\d+).*?reason=([^;]+)?/i);
    if (routeMatch) {
      const routeStage = Math.max(start, Math.min(end, Number(routeMatch[1])));
      const routeName = stages[routeStage]?.[1] || "反馈回退";
      setCurrentStage(routeStage);
      setCurrentStageLabel(`反馈回到${routeName}`);
      applyRunProgress(progressForStage(routeStage), true);
    }
    const attemptMatch = line.match(/Feedback repair attempt\s+(\d+)\/(\d+)/i);
    if (attemptMatch) {
      const currentAttempt = Number(attemptMatch[1]);
      const maxAttempts = Number(attemptMatch[2]);
      feedbackRoundRef.current = currentAttempt;
      setFeedbackRound(currentAttempt);
      setFeedbackTotal(Math.max(1, maxAttempts));
    }
    const stageMatch = line.match(/Stage\s+(\d+)(?::\s*([A-Za-z_ -]+))?/i);
    if (stageMatch) {
      const stage = Math.max(start, Math.min(end, Number(stageMatch[1])));
      const stageName = stages[stage]?.[1] || stageMatch[2]?.trim() || "运行中";
      setCurrentStage(stage);
      setCurrentStageLabel(line.toLowerCase().includes("completed") ? `${stageName}完成` : stageName);
      const feedbackStageMatch = line.match(/feedback attempt\s+(\d+)\/(\d+)/i);
      const feedbackStage = feedbackStageMatch ? Number(feedbackStageMatch[1]) : feedbackRoundRef.current;
      if (feedbackStageMatch) {
        feedbackRoundRef.current = feedbackStage;
        setFeedbackRound(feedbackStage);
        setFeedbackTotal(Math.max(1, Number(feedbackStageMatch[2])));
      }
      applyRunProgress(progressForStage(stage));
    }
  }, [applyRunProgress, end, progressForStage, start]);

  const appendMissedEvents = useCallback((events: unknown) => {
    if (!Array.isArray(events)) return;
    const missed: string[] = [];
    for (const item of events) {
      if (!item || typeof item !== "object") continue;
      const eventItem = item as {index?: number; event?: string; data?: {line?: unknown}};
      if (typeof eventItem.index === "number" && eventItem.index <= lastEventIndexRef.current) continue;
      if (typeof eventItem.index === "number") lastEventIndexRef.current = Math.max(lastEventIndexRef.current, eventItem.index);
      if (eventItem.event === "log" && eventItem.data?.line !== undefined) {
        const line = String(eventItem.data.line);
        missed.push(line);
        processRunLogLine(line);
      }
    }
    if (missed.length) appendOutput(lines => [...lines.slice(-300), ...missed]);
  }, [appendOutput, processRunLogLine]);

  const finishRun = useCallback((status: RunStatus, payload: Record<string, unknown> = {}) => {
    const done = ["succeeded", "failed", "cancelled"].includes(status);
    setRunStatus(status);
    if (!done) return;
    if (finishedRunRef.current) return;
    finishedRunRef.current = true;
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
    setRunning(false);
    applyRunProgress(100);
    const returnCode = payload.return_code !== undefined ? ` · exit ${payload.return_code}` : "";
    const artifact = payload.artifact_directory ? ` · ${payload.artifact_directory}` : "";
    appendOutput([`${status === "succeeded" ? "SUCCESS" : "STATUS "}  Run ${status}${returnCode}${artifact}`]);
    history.reload();
  }, [appendOutput, applyRunProgress, history]);

  // 页面卸载时必须关闭 SSE，避免切换页面后仍然保留网络连接和事件监听器。
  useEffect(() => () => eventSourceRef.current?.close(), []);

  useEffect(() => {
    setPreflight(null);
  }, [cve, start, end, collector, thresholdInput, repairMode, validateMode, logMode, maxRepairsInput, feedbackAttemptsInput, normalTimeInput, maliciousTimeInput, algo, runTarget, artifactDirectory]);

  useEffect(() => {
    const shared = selectedArtifactId ? resumableArtifacts.find(record => record.id === selectedArtifactId) : null;
    if (shared?.directory && artifactDirectory !== shared.directory) {
      setArtifactDirectory(shared.directory);
      return;
    }
    if (runTarget === "resume" && !resumableArtifacts.some(record => record.directory === artifactDirectory)) {
      setArtifactDirectory(resumableArtifacts[0]?.directory || "");
    }
  }, [runTarget, artifactDirectory, resumableArtifacts, selectedArtifactId]);

  useLayoutEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const element = logBodyRef.current;
      if (!element) return;
      suppressScrollRef.current = true;
      if (followLogRef.current) element.scrollTop = element.scrollHeight;
      else element.scrollTop = freezeScrollTopRef.current;
      window.requestAnimationFrame(() => { suppressScrollRef.current = false; });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [output]);

  const handleLogScroll = () => {
    const element = logBodyRef.current;
    if (!element) return;
    if (suppressScrollRef.current) return;
    const atBottom = isLogAtBottom();
    if (atBottom) {
      followLogRef.current = true;
      setFollowingLog(true);
      return;
    }
    if (Date.now() - lastUserScrollAtRef.current < 900) {
      followLogRef.current = false;
      setFollowingLog(false);
    }
  };

  const jumpToLatest = () => {
    followLogRef.current = true;
    setFollowingLog(true);
    const element = logBodyRef.current;
    if (!element) return;
    suppressScrollRef.current = true;
    element.scrollTop = element.scrollHeight;
    window.requestAnimationFrame(() => { suppressScrollRef.current = false; });
  };

  const handleLogWheel = (event: React.WheelEvent<HTMLDivElement>) => {
    lastUserScrollAtRef.current = Date.now();
    if (event.deltaY < 0) {
      followLogRef.current = false;
      setFollowingLog(false);
      const element = logBodyRef.current;
      if (element) freezeScrollTopRef.current = element.scrollTop;
    }
  };

  const markLogTouch = () => {
    lastUserScrollAtRef.current = Date.now();
  };

  useEffect(() => {
    if (!running || !runId) return;
    let cancelled = false;
    const sync = async () => {
      try {
        const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/runs/${runId}`, {headers: bridgeHeaders(), signal:AbortSignal.timeout(3000)});
        if (!response.ok) return;
        const latest = await response.json();
        if (cancelled) return;
        appendMissedEvents(latest.recent_events);
        if (typeof latest.current_stage === "number") {
          setCurrentStage(latest.current_stage);
          setCurrentStageLabel(String(latest.current_stage_label || stages[latest.current_stage]?.[1] || "运行中"));
        }
        const progressState = bridgeRunProgressState(latest as BridgeRun);
        setProgress(progressState.progress);
        setProgressPeak(progressState.peak);
        setRewindFrom(progressState.rewindFrom);
        progressPeakRef.current = progressState.peak;
        rewindFromRef.current = progressState.rewindFrom;
        const latestStatus = latest.status as RunStatus;
        if (["succeeded","failed","cancelled"].includes(latestStatus)) {
          finishRun(latestStatus, latest);
        }
      } catch {}
    };
    const timer = window.setInterval(sync, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [running, runId, bridgeUrl, appendMissedEvents, finishRun]);

  useEffect(() => {
    onRunStateChange?.({cve, runId, status: runStatus, progress, running, currentStage, currentStageLabel: currentStageText});
  }, [cve, runId, runStatus, progress, running, currentStage, currentStageLabel, currentStageText, onRunStateChange]);

  useEffect(() => {
    if (running) return;
    setOutput([]);
    setProgress(0);
    setProgressPeak(0);
    setRewindFrom(0);
    progressPeakRef.current = 0;
    rewindFromRef.current = 0;
    setFeedbackRound(1);
    feedbackRoundRef.current = 1;
    setFeedbackTotal(Math.max(1, feedbackAttempts + 1));
    setCurrentStage(null);
    setCurrentStageLabel("尚未开始");
    setRunId("");
    setRunStatus("idle");
  }, [cve, feedbackAttempts, running]);

  /** 检查 Bridge 是否在线；失败只更新 UI 状态，不会提交任何任务。 */
  const testConnection = async () => {
    setConnection("testing"); setConnectionMessage("正在检查 /health …");
    try {
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/health`, {headers: bridgeHeaders(), signal:AbortSignal.timeout(3500)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      setConnection("online"); setConnectionMessage(`Bridge ${data.version||"已连接"} · Docker ${data.docker?"可用":"未就绪"}`); return true;
    } catch (error) {
      setConnection("offline"); setConnectionMessage(`无法连接 ${bridgeUrl}，请确认 Bridge 已启动并允许 CORS`); return false;
    }
  };
  /**
   * 请求后端执行运行前检查。ready=false 表示存在阻断项，launch 会拒绝运行。
   * 警告项不会自动阻断，具体规则由 Bridge 根据 Stage 范围和采集器判断。
   */
  const runPreflight = async () => {
    setPreflightLoading(true); setPreflight(null);
    const connected = connection === "online" || await testConnection();
    if (!connected) { setPreflightLoading(false); return null; }
    try {
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/preflight`,{method:"POST",headers:bridgeHeaders({"Content-Type":"application/json"}),body:JSON.stringify(requestBody)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json(); setPreflight(data); setPreflightLoading(false); return data;
    } catch(error) { setPreflightLoading(false); appendOutput([`ERROR    Preflight failed · ${error instanceof Error?error.message:"unknown error"}`]); return null; }
  };
  /** 提交任务；后续日志和取消操作交给全局运行控制台统一处理。 */
  const launch = async () => {
    setProgress(0); setRunId(""); setRunStatus("queued");
    setCurrentStage(null);
    setCurrentStageLabel("排队中");
    setProgressPeak(0);
    setRewindFrom(0);
    progressPeakRef.current = 0;
    rewindFromRef.current = 0;
    setFeedbackRound(1);
    feedbackRoundRef.current = 1;
    setFeedbackTotal(Math.max(1, feedbackAttempts + 1));
    lastEventIndexRef.current = -1;
    finishedRunRef.current = false;
    const report = preflight || await runPreflight();
    if (!report?.ready) { appendOutput(["ERROR    Critical preflight checks did not pass"]); setRunStatus("failed"); return; }
    followLogRef.current = true; setFollowingLog(true);
    setRunning(true); setOutput([`CONNECT  POST ${bridgeUrl}/runs`, `INFO     Submitting ${cve} · Stage ${start}–${end}`]);
    try {
      const runPayload = DEFAULT_SUDO_PASSWORD ? {...requestBody, sudo_password: DEFAULT_SUDO_PASSWORD} : requestBody;
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/runs`, {method:"POST",headers:bridgeHeaders({"Content-Type":"application/json"}),body:JSON.stringify(runPayload)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json() as BridgeRun;
      setRunId(data.run_id); setRunStatus((data.status as RunStatus) || "queued"); applyRunProgress(0);
      appendOutput([`SUCCESS  Task accepted · ${data.run_id}`, `STATUS   已加入全局任务队列`]);
      onTaskAccepted?.(data);
      setRunning(false);
      setConnection("online");
    } catch (error) { setRunning(false); applyRunProgress(100); setRunStatus("failed"); setConnection("offline"); appendOutput([`ERROR    Task submission failed · ${error instanceof Error?error.message:"unknown error"}`]); }
  };
  /** 请求 Bridge 终止整个任务进程组，而不只是关闭浏览器中的日志连接。 */
  const cancelRun = async () => {
    if (!runId) return;
    appendOutput([`INFO     Cancelling ${runId} …`]);
    try {
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/runs/${runId}/cancel`,{method:"POST",headers:bridgeHeaders()});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      eventSourceRef.current?.close(); eventSourceRef.current=null; setRunning(false); setRunStatus("cancelled");
      appendOutput(["STATUS   Run cancelled by user"]);
    } catch(error) { appendOutput([`ERROR    Cancel failed · ${error instanceof Error?error.message:"unknown error"}`]); }
  };
  return <div className="content consolecontent">
    <div className="headline consoleintro"><div><p className="eyebrow">NEW RUN</p><h2>新建任务</h2></div><div className={`runbadge ${running ? "live" : ""}`}><span>{running ? "● 提交中" : progress === 100 ? "✓ 已加入队列" : "准备就绪"}</span><strong>{running ? `${progress}%` : connection==="online"?"Bridge 已连接":"等待连接"}</strong></div></div>
    <section className="panel connectionbar"><div className="connectiontitle"><i>⇄</i><div><b>执行后端</b></div></div><label className="bridgeinput"><span>Bridge URL</span><input value={bridgeUrl} onChange={e=>{setBridgeUrl(e.target.value);setConnection("idle");setPreflight(null)}}/><button disabled={connection==="testing"} onClick={testConnection}>{connection==="testing"?"检查中…":"测试连接"}</button><button className="preflightbtn" disabled={preflightLoading} onClick={runPreflight}>{preflightLoading?"检查中…":"运行预检"}</button></label>{bridgeAuthRequired&&<div className="connectionstate online"><i>●</i><span>已通过访问验证</span></div>}<div className={`connectionstate ${connection}`}><i>●</i><span>{connectionMessage}</span></div></section>
    {preflight&&<section className={`panel preflightpanel ${preflight.ready?"ready":"blocked"}`}><div className="preflighthead"><div><p className="eyebrow">PREFLIGHT</p><h3>{preflight.ready?"运行前检查已完成":"存在阻断项"}</h3></div><div><strong>{preflight.checks.filter(c=>c.status==="pass").length}/{preflight.checks.length}</strong><span>检查通过 · {preflight.warnings} 个警告</span></div></div><div className="checkgrid">{preflight.checks.map(check=><div key={check.id} className={check.status}><i>{check.status==="pass"?"✓":check.status==="warn"?"!":"×"}</i><div><b>{check.label}{check.critical&&<em>关键</em>}</b><small>{check.detail}</small></div></div>)}</div><div className="previewcommand"><span>Bridge 将执行</span><code>{preflight.command.join(" ")}</code><button onClick={()=>navigator.clipboard?.writeText(preflight.command.join(" "))}>复制</button></div></section>}
    <div className="consolegrid">
      <section className="panel configpanel">
        <div className="sectiontitle"><div><h3>00 · 运行目标</h3><span>新建记录，或从已有产物继续</span></div></div>
        <div className="targetchooser">
          <div className="modecontrol"><button disabled={running} className={runTarget==="new"?"active":""} onClick={()=>setRunTarget("new")}>新建运行</button><button disabled={running||!resumableArtifacts.length} className={runTarget==="resume"?"active":""} onClick={()=>setRunTarget("resume")}>继续历史运行</button></div>
          {runTarget==="resume"?<label><span>继续运行的产物</span><select disabled={running} value={artifactDirectory} onChange={event=>{setArtifactDirectory(event.target.value); const record = resumableArtifacts.find(item=>item.directory===event.target.value); if (record) onSelectedArtifactIdChange?.(record.id);}}>{resumableArtifacts.map(record=><option key={record.id} value={record.directory}>{record.date} · {record.status} · {record.directory}</option>)}</select></label>:<p><code>{cve}-YYYYMMDD-HHMMSS</code></p>}
        </div>
        <div className="sectiontitle"><div><h3>01 · 执行范围</h3><span>选择连续的 Stage 区间</span></div></div>
        <div className="fieldgrid">
          <label><span>起始阶段</span><select value={start} disabled={running} onChange={e => { const v=+e.target.value; setStart(v); if(v>end)setEnd(v); }}>{stages.map((s,i)=><option key={i} value={i}>Stage {i} · {s[1]}</option>)}</select></label>
          <label><span>结束阶段</span><select value={end} disabled={running} onChange={e => { const v=+e.target.value; setEnd(v); if(v<start)setStart(v); }}>{stages.map((s,i)=><option key={i} value={i}>Stage {i} · {s[1]}</option>)}</select></label>
        </div>
        <div className="minitrack">{stages.map((s,i)=><button key={i} disabled={running} onClick={()=>{setStart(Math.min(start,i));setEnd(Math.max(start,i));}} className={i>=start&&i<=end?"included":""}><i>{i}</i><span>{s[1]}</span></button>)}</div>
        <div className="sectiontitle configsection"><div><h3>02 · 运行参数</h3><span>参数将在启动前固化</span></div></div>
        <div className="fieldgrid">
          <label><span>采集预检策略</span><select value={collector} disabled={running} onChange={e=>setCollector(e.target.value)}><option value="auto">Auto · 自动选择</option><option value="sysdig">Sysdig</option><option value="strace">Strace fallback</option></select><small>用于预检 Stage 2 采集能力；实际采集仍由 main.py 内部流程决定。</small></label>
          <label><span>异常阈值</span><input className="textinput" type="number" min="0" max="1" step="0.05" value={thresholdInput} disabled={running} onChange={e=>setThresholdInput(e.target.value)} onBlur={()=>setThresholdInput(normalizeNumericDraft(thresholdInput,0.5,0,1))}/><small>范围 0–1，传入 main.py 的 --threshold。</small></label>
          <label><span>修复模式</span><select value={repairMode} disabled={running} onChange={e=>setRepairMode(e.target.value as typeof repairMode)}><option value="filter">filter · 过滤式修复</option><option value="direct">direct · 直接逻辑修复</option><option value="direct_localization">direct_localization</option></select><small>传入 --repair-mode。</small></label>
          <label><span>验证模式</span><select value={validateMode} disabled={running} onChange={e=>setValidateMode(e.target.value as typeof validateMode)}><option value="all">all · 正常和恶意</option><option value="normal">normal · 仅正常</option><option value="abnormal">abnormal · 仅恶意</option></select><small>传入 --validate-mode。</small></label>
          <label><span>检测算法</span><select value={algo} disabled={running} onChange={e=>setAlgo(e.target.value)}>{detectionAlgoOptions.map(option=><option key={option.value} value={option.value}>{option.label}</option>)}</select><small>传入 --algo；组合项会拆成多个算法。</small></label>
          <label><span>正常采集秒数</span><input className="textinput" type="number" min="1" max="3600" step="1" value={normalTimeInput} disabled={running} onChange={e=>setNormalTimeInput(e.target.value)} onBlur={()=>setNormalTimeInput(normalizeNumericDraft(normalTimeInput,60,1,3600,true))}/><small>传入 --normal-time。</small></label>
          <label><span>恶意采集秒数</span><input className="textinput" type="number" min="1" max="3600" step="1" value={maliciousTimeInput} disabled={running} onChange={e=>setMaliciousTimeInput(e.target.value)} onBlur={()=>setMaliciousTimeInput(normalizeNumericDraft(maliciousTimeInput,20,1,3600,true))}/><small>传入 --malicious-time。</small></label>
          <label><span>最多修复数</span><input className="textinput" type="number" min="1" max="20" step="1" value={maxRepairsInput} disabled={running} onChange={e=>setMaxRepairsInput(e.target.value)} onBlur={()=>setMaxRepairsInput(normalizeNumericDraft(maxRepairsInput,1,1,20,true))}/><small>范围 1–20，传入 --max-repairs。</small></label>
          <label><span>反馈重试次数</span><input className="textinput" type="number" min="0" max="10" step="1" value={feedbackAttemptsInput} disabled={running} onChange={e=>setFeedbackAttemptsInput(e.target.value)} onBlur={()=>setFeedbackAttemptsInput(normalizeNumericDraft(feedbackAttemptsInput,0,0,10,true))}/><small>验证未通过后，按失败原因最多回退重试几轮。</small></label>
          <label><span>日志模式</span><select value={logMode} disabled={running} onChange={e=>setLogMode(e.target.value as typeof logMode)}><option value="append">append · 追加</option><option value="overwrite">overwrite · 覆盖</option></select><small>传入 --log-mode。</small></label>
        </div>
      </section>
      <aside className="panel launchpanel">
        <div className="sectiontitle"><div><h3>任务摘要</h3></div><span className={`readydot ${connection!=="online"?"notready":""}`}>● {connection==="online"?"Bridge 可用":"等待连接"}</span></div>
        <dl><div><dt>目标场景</dt><dd>{cve}</dd></div><div><dt>运行方式</dt><dd>{runTarget==="new"?"新建运行":"继续历史"}</dd></div><div><dt>阶段范围</dt><dd>Stage {start} → {end}</dd></div><div><dt>当前阶段</dt><dd>{currentStageText}</dd></div><div><dt>共计阶段</dt><dd>{end-start+1} 个</dd></div><div><dt>采集时长</dt><dd>N {normalTime}s / M {maliciousTime}s</dd></div><div><dt>采集检查</dt><dd>{collector}</dd></div><div><dt>修复模式</dt><dd>{repairMode}</dd></div><div><dt>反馈重试</dt><dd>{feedbackAttempts} 次</dd></div><div><dt>日志</dt><dd>{logMode}</dd></div></dl>
        <div className="command"><span>将执行</span><code>{command}</code><button onClick={()=>navigator.clipboard?.writeText(command)}>复制</button></div>
        {running || progress>0 ? <div className="progressbox"><div><span>{running?runStatus==="queued"?"排队中":runStatus==="disconnected"?"日志连接中断":"正在执行":runStatus==="succeeded"?"执行完成":runStatus==="cancelled"?"已取消":"执行结束"}</span><b>{progress}%</b></div><div className={`progressrail ${running?"active":""} ${rewindFrom>progress?"rewound":""}`} style={{"--progress":`${progress}%`,"--progress-peak":`${progressPeak}%`,"--rollback-start":`${Math.min(progress,rewindFrom)}%`,"--rollback-end":`${Math.max(progress,rewindFrom)}%`} as React.CSSProperties}><span /></div><small>{runId?`${runId} · ${runStatus} · ${currentStageText} · 第 ${feedbackRound}/${feedbackTotal} 次尝试`:running?currentStageText:"所有选定阶段均已结束"}{rewindFrom>progress?" · 已按失败原因回退重试":""}</small></div> : <p className="launchhint">启动后将锁定本页配置。你仍可切换页面查看历史结果。</p>}
        <button className={`launchbutton ${running?"cancel":""}`} onClick={()=>running?cancelRun():launch()}>{running?"■ 取消当前任务":"▶ 提交到 Local Bridge"}</button>
      </aside>
    </div>
  </div>;
}

function TaskMonitor({ runs, loading, selectedRunId, onSelectedRunIdChange, onCancelRun, onCancelAllRuns, onClearCompletedRuns, onOpenLauncher }: {
  runs: BridgeRun[];
  loading: boolean;
  selectedRunId: string;
  onSelectedRunIdChange: (id: string) => void;
  onCancelRun: (id: string) => void;
  onCancelAllRuns: () => void;
  onClearCompletedRuns: () => void;
  onOpenLauncher: () => void;
}) {
  const activeRuns = useMemo(() => runs.filter(isActiveBridgeRun).sort((a, b) => (a.created_at || 0) - (b.created_at || 0)), [runs]);
  const recentRuns = useMemo(() => runs.filter(run => !isActiveBridgeRun(run)).sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).slice(0, 8), [runs]);
  const completedRuns = useMemo(() => runs.filter(run => !isActiveBridgeRun(run)), [runs]);
  const visibleRuns = useMemo(() => [...activeRuns, ...recentRuns], [activeRuns, recentRuns]);
  const selectedRun = runs.find(run => run.run_id === selectedRunId) || visibleRuns[0] || null;
  const logBodyRef = useRef<HTMLDivElement | null>(null);
  const followLogRef = useRef(true);
  const freezeScrollTopRef = useRef(0);
  const suppressScrollRef = useRef(false);
  const lastUserScrollAtRef = useRef(0);
  const [followingLog, setFollowingLog] = useState(true);
  const logLines = useMemo(() => {
    const events = selectedRun?.recent_events || [];
    return events.flatMap(item => {
      if (item.event === "log" && item.data?.line !== undefined) return [String(item.data.line)];
      if (item.event === "status" && item.data?.status !== undefined) return [`STATUS   ${String(item.data.status)}`];
      return [];
    }).slice(-240);
  }, [selectedRun]);
  const selectedProgressState = bridgeRunProgressState(selectedRun);
  const selectedProgress = selectedProgressState.progress;

  const isLogAtBottom = useCallback(() => {
    const element = logBodyRef.current;
    if (!element) return true;
    if (element.clientHeight === 0) return true;
    return element.scrollHeight - element.scrollTop - element.clientHeight <= 36;
  }, []);

  useEffect(() => {
    if (!selectedRunId && visibleRuns[0]?.run_id) onSelectedRunIdChange(visibleRuns[0].run_id);
  }, [onSelectedRunIdChange, selectedRunId, visibleRuns]);

  useEffect(() => {
    followLogRef.current = true;
    setFollowingLog(true);
  }, [selectedRun?.run_id]);

  useLayoutEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const element = logBodyRef.current;
      if (!element) return;
      suppressScrollRef.current = true;
      if (followLogRef.current) element.scrollTop = element.scrollHeight;
      else element.scrollTop = freezeScrollTopRef.current;
      window.requestAnimationFrame(() => { suppressScrollRef.current = false; });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [logLines]);

  const handleLogScroll = () => {
    const element = logBodyRef.current;
    if (!element || suppressScrollRef.current) return;
    const atBottom = isLogAtBottom();
    if (atBottom) {
      followLogRef.current = true;
      setFollowingLog(true);
      return;
    }
    if (Date.now() - lastUserScrollAtRef.current < 900) {
      followLogRef.current = false;
      freezeScrollTopRef.current = element.scrollTop;
      setFollowingLog(false);
    }
  };

  const markLogTouch = () => {
    lastUserScrollAtRef.current = Date.now();
  };

  const handleLogWheel = (event: React.WheelEvent<HTMLDivElement>) => {
    lastUserScrollAtRef.current = Date.now();
    if (event.deltaY < 0) {
      const element = logBodyRef.current;
      followLogRef.current = false;
      if (element) freezeScrollTopRef.current = element.scrollTop;
      setFollowingLog(false);
    }
  };

  const jumpToLatest = () => {
    followLogRef.current = true;
    setFollowingLog(true);
    const element = logBodyRef.current;
    if (!element) return;
    suppressScrollRef.current = true;
    element.scrollTop = element.scrollHeight;
    window.requestAnimationFrame(() => { suppressScrollRef.current = false; });
  };

  return <div className="content monitorcontent">
    <div className="headline consoleintro">
      <div><p className="eyebrow">TASK QUEUE</p><h2>运行控制台</h2></div>
      <div className="monitoractions"><button className="secondary" disabled={!completedRuns.length} onClick={onClearCompletedRuns}>清除已完成</button><button className="cancelghost" disabled={!activeRuns.length} onClick={onCancelAllRuns}>取消所有任务</button><button className="primary compactprimary" onClick={onOpenLauncher}>+ 新建任务</button></div>
    </div>
    <section className="panel taskqueuehero">
      <div>
        <span>当前执行</span>
        <strong>{activeRuns.find(run => run.status === "running")?.cve || "暂无"}</strong>
      </div>
      <div>
        <span>排队任务</span>
        <strong>{activeRuns.filter(run => run.status === "queued").length}</strong>
      </div>
      <div>
        <span>任务总数</span>
        <strong>{runs.length}</strong>
      </div>
      <div>
        <span>已完成记录</span>
        <strong>{completedRuns.length}</strong>
      </div>
    </section>
    <div className="monitormatrix">
      <section className="panel tasklistpanel">
        <div className="sectiontitle"><div><h3>任务列表</h3><span>{loading ? "同步中" : "Bridge 全局队列"}</span></div></div>
        <div className="tasklist">
          {visibleRuns.length ? visibleRuns.map(run => {
            const active = run.run_id === selectedRun?.run_id;
            const canCancel = isActiveBridgeRun(run);
            const progressState = bridgeRunProgressState(run);
            const progress = progressState.progress;
            return <div key={run.run_id} role="button" tabIndex={0} className={`taskitem ${active ? "selected" : ""} ${run.status}`} onClick={() => onSelectedRunIdChange(run.run_id)} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") onSelectedRunIdChange(run.run_id); }}>
              <div className="taskmain"><strong>{run.cve}</strong><span>{run.run_id}</span></div>
              <em className={`taskstate ${run.status}`}>{runStatusLabel(run.status)}</em>
              <div className="taskstage"><span>{runStageLabel(run)}</span><b>{progress}%</b></div>
              <i
                className={`${isActiveBridgeRun(run) ? "active" : ""} ${progressState.rewindFrom > progress ? "rewound" : ""}`}
                style={{
                  "--progress": `${progress}%`,
                  "--rollback-start": `${Math.min(progress, progressState.rewindFrom)}%`,
                  "--rollback-end": `${Math.max(progress, progressState.rewindFrom)}%`,
                } as React.CSSProperties}
              />
              {canCancel && <button type="button" onClick={event => { event.stopPropagation(); onCancelRun(run.run_id); }}>取消</button>}
            </div>;
          }) : <div className="emptyqueue"><b>暂无任务</b><span>可以从“新建任务”提交一次运行。</span></div>}
        </div>
      </section>
      <section className="panel taskdetailpanel">
        <div className="taskdetailhead">
          <div>
            <p className="eyebrow">RUN DETAIL</p>
            <h3>{selectedRun?.cve || "未选择任务"}</h3>
            <span>{selectedRun ? `${selectedRun.run_id} · ${runCreatedText(selectedRun)}` : "从左侧选择一个任务"}</span>
          </div>
          {selectedRun && isActiveBridgeRun(selectedRun) && <button className="cancelghost" onClick={() => onCancelRun(selectedRun.run_id)}>取消任务</button>}
        </div>
        {selectedRun ? <div className="taskprogressbox">
          <div><span>{runStageLabel(selectedRun)}</span><b>{selectedProgress}%</b></div>
          <div className={`progressrail ${isActiveBridgeRun(selectedRun)?"active":""} ${selectedProgressState.rewindFrom>selectedProgress?"rewound":""}`} style={{"--progress":`${selectedProgress}%`,"--progress-peak":`${selectedProgressState.peak}%`,"--rollback-start":`${Math.min(selectedProgress,selectedProgressState.rewindFrom)}%`,"--rollback-end":`${Math.max(selectedProgress,selectedProgressState.rewindFrom)}%`} as React.CSSProperties}><span /></div>
          <dl>
            <div><dt>状态</dt><dd>{runStatusLabel(selectedRun.status)}</dd></div>
            <div><dt>产物</dt><dd>{selectedRun.artifact_directory || "未生成"}</dd></div>
            <div><dt>事件</dt><dd>{selectedRun.event_count ?? 0}</dd></div>
            <div><dt>退出码</dt><dd>{selectedRun.return_code ?? "—"}</dd></div>
          </dl>
        </div> : <div className="emptyqueue large"><b>暂无运行详情</b><span>Bridge 队列为空。</span></div>}
        <div className="monitorlog">
          <div className="terminalhead"><div><span className={selectedRun?.status === "running" ? "pulse" : ""}>●</span><b>运行日志</b></div><div>{!followingLog&&<button className="latestlog" onClick={jumpToLatest}>回到最新</button>}<code>{selectedRun?.artifact_directory || ""}</code></div></div>
          <div className="logbody" ref={logBodyRef} onScroll={handleLogScroll} onWheel={handleLogWheel} onTouchStart={markLogTouch} onPointerDown={markLogTouch}>{logLines.length ? logLines.map((line, index)=><div key={`${index}-${line}`} className={line.includes("SUCCESS")?"successlog":line.includes("ERROR")||line.includes("failed")?"warninglog":""}>{line}</div>) : <div className="emptylog">暂无输出</div>}</div>
        </div>
      </section>
    </div>
  </div>;
}

function useArtifactView(cve: string, selection: ArtifactSelectionProps = {}) {
  const {records, loading} = useHistoryData(cve);
  const artifactRecords = records.filter(r => r.source === "artifact" && r.directory);
  const [localSelectedId, setLocalSelectedId] = useState("");
  const controlledSelectedId = selection.selectedArtifactId;
  const controlledOnChange = selection.onSelectedArtifactIdChange;
  const effectiveSelectedId = controlledSelectedId ?? localSelectedId;
  const selected = artifactRecords.find(r => r.id === effectiveSelectedId) || artifactRecords[0];
  const [detail, setDetail] = useState<ArtifactDetail | null>(null);

  const setSelectedId = useCallback((id: string) => {
    if (controlledOnChange) controlledOnChange(id);
    else setLocalSelectedId(id);
  }, [controlledOnChange]);

  useEffect(() => {
    if (artifactRecords[0] && !artifactRecords.some(record => record.id === effectiveSelectedId)) {
      setSelectedId(artifactRecords[0].id);
    }
  }, [artifactRecords, effectiveSelectedId, setSelectedId]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!selected?.directory) { setDetail(null); return; }
      try {
        const response = await bridgeFetch(`/artifact-detail?directory=${encodeURIComponent(selected.directory)}`, {signal:AbortSignal.timeout(10000)});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!cancelled) setDetail(data);
      } catch {
        if (!cancelled) setDetail(previous => previous?.directory === selected.directory ? previous : null);
      }
    };
    load();
    const timer = window.setInterval(load, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [selected?.directory, selected?.mtime, loading]);

  return {records: artifactRecords, loading, selected, selectedId: selected?.id || effectiveSelectedId, setSelectedId, detail};
}

function ArtifactSelector({records, selectedId, onChange}: {records: HistoryRecord[]; selectedId: string; onChange: (id:string)=>void}) {
  return <section className="panel artifactselect"><label><span>选择运行产物</span><select value={selectedId} onChange={e=>onChange(e.target.value)}>{records.map(record=><option key={record.id} value={record.id}>{record.date} · {record.status} · {record.directory}</option>)}</select></label></section>;
}

function RunOverview({cve, selectedArtifactId, onSelectedArtifactIdChange}: {cve: string} & ArtifactSelectionProps) {
  const [logOpen, setLogOpen] = useState(true);
  const artifact = useArtifactView(cve, {selectedArtifactId, onSelectedArtifactIdChange});
  const detail = artifact.detail;
  const timing = detail?.timing || {};
  const feedbackLimit = detail?.feedback?.max_feedback_attempts ?? 0;
  const totalAttempts = totalRepairAttempts(detail, artifact.selected);
  const collectionText = detail?.collection?.normal_time || detail?.collection?.malicious_time
    ? `N ${detail.collection.normal_time ?? "—"}s / M ${detail.collection.malicious_time ?? "—"}s`
    : "—";
  const stageStatuses = deriveStageStatuses(detail);
  const completedStages = stageStatuses.filter(item => item.status === "done" || item.status === "feedback").length;
  const startedStages = stageStatuses.filter(item => item.status !== "missing").length;
  const routes = feedbackRoutes(detail);
  const lastRoute = routes[routes.length - 1];
  const routeText = lastRoute?.route_stage !== undefined
    ? `Stage ${lastRoute.route_stage} · ${stages[lastRoute.route_stage]?.[1] || lastRoute.route_label || "反馈"}`
    : "—";

  if (artifact.records.length) {
    const success = artifact.selected?.status === "成功";
    return <div className="content">
      <div className="headline"><div><p className="eyebrow">运行摘要</p><h2>{cve} 运行总览</h2><p>选择一次历史运行，查看该运行的阶段轨道、修复函数、验证结果和日志。</p></div><div className={`result ${success?"":"review"}`}><span>最终结论</span><strong>{success?"✓ 修复验证通过":"△ 需要复核"}</strong><small>Normal {artifact.selected?.normal} · Malicious {artifact.selected?.malicious} · 总尝试 {totalAttempts} 次</small></div></div>
      <ArtifactSelector records={artifact.records} selectedId={artifact.selectedId} onChange={artifact.setSelectedId}/>

      <section className="stagecard">
        <div className="sectiontitle"><div><h3>Stage 0–11 运行轨道</h3><span>{completedStages}/{stages.length} 完成 · {startedStages} 个阶段有运行证据 · {artifact.selected?.directory}</span></div></div>
        <div className="track">
          {stages.map((s, i) => {
            const stageStatus = stageStatuses[i] || {stage: i, status: "missing" as const};
            const visual = stageVisual(stageStatus.status);
            return <div className="stage" key={s[0]} title={`Stage ${i}: ${s[0]} · ${visual.label} · ${stageStatus.source || ""}`}>
              <div className={`stagecircle ${visual.className}`}>{visual.mark}</div>
              <b>{i}</b><span>{s[1]}</span><small>{durationText(stageStatus.duration)}</small><em>{visual.label}</em>{i < stages.length - 1 && <i />}
            </div>;
          })}
        </div>
        <div className="skipnote"><b>{artifact.selected?.status}</b><span>{artifact.selected?.note || "该运行产物来自 data 目录。"}</span></div>
      </section>

      <div className="grid overviewgrid">
        <section className="panel funnel">
          <div className="sectiontitle"><div><h3>候选收敛</h3><span>从异常检测到最终验证</span></div></div>
          <div className="convergencegrid">
            <div><span>命中排名</span><strong>{detail?.rank ?? "—"}</strong><small>Stage 7</small></div>
            <div><span>Repair 候选</span><strong>{artifact.selected?.candidates ?? 0}</strong><small>过滤后</small></div>
            <div><span>修复方式</span><strong>{artifact.selected?.repair || "—"}</strong><small>Stage 8</small></div>
            <div><span>总尝试</span><strong>{totalAttempts || "—"}</strong><small>最多 {feedbackLimit + 1} 次</small></div>
            <div><span>采集参数</span><strong>{collectionText}</strong><small>Stage 2</small></div>
            <div><span>反馈回退</span><strong>{routeText}</strong><small>{lastRoute?.route_reason || "未发生"}</small></div>
            <div className={success ? "ok" : "review"}><span>验证结果</span><strong>{success ? "通过" : "复核"}</strong><small>Stage 10</small></div>
          </div>
          <div className="repair"><span className="codeicon">ƒ</span><div><small>最终修复函数</small><code>{detail?.function_name || artifact.selected?.note || "未找到函数"}</code></div><em>{detail?.repair_method || artifact.selected?.repair || "—"}</em></div>
        </section>
        <section className="panel validation">
          <div className="sectiontitle"><div><h3>验证结果</h3><span>Stage 10 · validate</span></div></div>
          <div className="validrow"><span className="check">✓</span><div><b>正常流量</b><small>normal validation</small></div><strong>{artifact.selected?.normal}</strong></div>
          <div className="validrow"><span className="shield">◆</span><div><b>恶意流量</b><small>malicious validation</small></div><strong>{artifact.selected?.malicious}</strong></div>
          <p className={`risk ${success?"":"danger"}`}>规则数量：{detail?.rules ?? artifact.selected?.rules ?? 0} · {artifact.selected?.note}</p>
        </section>
      </div>

      <section className="panel terminal">
        <div className="terminalhead"><div><span className="pulse">●</span><b>运行日志</b><em>{artifact.selected?.directory}</em></div><div><button onClick={() => setLogOpen(!logOpen)}>{logOpen ? "收起" : "展开"}</button></div></div>
        {logOpen && <div className="logbody">{(detail?.log_tail || []).map((line, i) => <div key={i} className={line.includes("✓") || line.includes("Validation passed") ? "successlog" : line.includes("ERROR") || line.includes("WARNING") ? "warninglog" : ""}>{line}</div>)}</div>}
      </section>
    </div>;
  }

  return <div className="content">
    <div className="headline"><div><p className="eyebrow">运行摘要</p><h2>{cve} 运行总览</h2><p>该场景暂未生成总览摘要，可在运行控制台提交任务。</p></div><div className="result review"><span>最终结论</span><strong>△ 待生成</strong><small>暂无历史产物</small></div></div>
    <section className="panel validationresults"><div className="validationtop"><div><p className="eyebrow">RESULTS</p><h3>没有找到历史运行产物</h3></div></div><p className="coveragehint danger">运行完成后，本页会自动从 data 目录读取结果。</p></section>
  </div>;
}

function DetectionRepair({ cve, selectedArtifactId, onSelectedArtifactIdChange }: { cve: string } & ArtifactSelectionProps) {
  const [detailView, setDetailView] = useState<RepairDetailView>("summary");
  const artifact = useArtifactView(cve, {selectedArtifactId, onSelectedArtifactIdChange});
  if (artifact.records.length) {
    const detail = artifact.detail;
    const code = detail?.repair_code || "暂无修复代码";
    const originalCode = detail?.original_code || "";
    const language = detail?.function_path?.toLowerCase().endsWith(".php") ? "php" : "python";
    const diff = buildLineDiff(originalCode, code).slice(0, 1200);
    const additions = diff.filter(line=>line.kind==="add").length;
    const removals = diff.filter(line=>line.kind==="remove").length;
    const totalAttempts = totalRepairAttempts(detail, artifact.selected);
    const functionName = detail?.function_name || artifact.selected?.note || "未找到函数";
    const functionPath = detail?.function_path || detail?.repair_file || artifact.selected?.directory || "—";
    const repairFile = detail?.repair_file || artifact.selected?.directory || "repair json";
    const lineRange = detail?.start_line ? `第 ${detail.start_line}-${detail.end_line} 行` : "行号未记录";
    const normalPassed = detail?.validation?.normal_ok ?? artifact.selected?.normal === "✓";
    const maliciousBlocked = detail?.validation?.malicious_blocked ?? artifact.selected?.malicious === "✓";
    const repairStory = deriveRepairStory({
      functionName: detail?.function_name,
      functionPath: detail?.function_path || detail?.repair_file,
      repairMethod: detail?.repair_method || artifact.selected?.repair,
      lineRange: detail?.start_line ? `${detail.start_line}-${detail.end_line || detail.start_line}` : "",
      normalPassed,
      maliciousBlocked,
    });
    const protectionRules = (detail?.syscall_rules || []).flatMap(rule =>
      (rule.values || []).map(value => ({group: rule.name, value: String(value)})),
    );
    const detailTabs: Array<{id: RepairDetailView; label: string}> = [
      {id: "summary", label: "修补概览"},
      {id: "changes", label: "修改详情"},
      {id: "protection", label: "防护机制"},
      {id: "validation", label: "验证结果"},
    ];
    return <div className="content detectcontent">
      <div className="headline detectintro"><div><p className="eyebrow">STAGE 7–9 · DETECT / REPAIR / WHITELIST</p><h2>检测与修复</h2><p>选择一次历史运行，查看该运行产物中的定位函数、修复方式和修复代码。</p></div><div className="detectsummary"><div><strong>{detail?.rank ?? "—"}</strong><span>命中排名</span></div><i>→</i><div><strong>{totalAttempts || "—"}</strong><span>总尝试次数</span></div><i>→</i><div className="final"><strong>{detail?.repair_method || artifact.selected?.repair || "—"}</strong><span>修复方式</span></div></div></div>
      <ArtifactSelector records={artifact.records} selectedId={artifact.selectedId} onChange={artifact.setSelectedId}/>
      <nav className="repairdetailtabs" aria-label="修补详情视图">
        {detailTabs.map(tab => <button key={tab.id} type="button" className={detailView === tab.id ? "active" : ""} aria-pressed={detailView === tab.id} onClick={() => setDetailView(tab.id)}>{tab.label}</button>)}
      </nav>

      {detailView === "summary" && <section className="panel repairstoryhero">
        <div className="sectiontitle repairplainhead"><div><h3>修补概览</h3><span>用修补位置、防护变化和验证证据说明本次修改</span></div><span className={`repairstorystatus ${repairStory.resultTone}`}>{repairStory.resultTone === "success" ? "证据完整" : "等待复核"}</span></div>
        <div className="repairstorylead">
          <div><p className="eyebrow">本次修补</p><h3>{repairStory.protectionName}</h3><p>{repairStory.protectionSummary}</p></div>
          <code>{repairStory.location}</code>
        </div>
        <div className="repairbeforeafter">
          <article><span>修补前</span><strong>恶意输入可沿原路径触发危险操作</strong><p>已定位到 <code>{functionName}</code>，原逻辑缺少足够的限制条件。</p></article>
          <i aria-hidden="true">→</i>
          <article className="after"><span>修补后</span><strong>危险操作前增加检查与阻断</strong><p>{repairStory.protectionSummary}</p></article>
        </div>
        <div className="repairstoryfacts">
          <div><span>具体位置</span><strong>{repairStory.location}</strong></div>
          <div><span>修改产物</span><code>{repairFile}</code></div>
          <div className={repairStory.resultTone}><span>验证结论</span><strong>{repairStory.resultSummary}</strong></div>
        </div>
      </section>}

      {detailView === "changes" && <>
      <section className="panel repairsummary">
        <div className="sectiontitle repairplainhead">
          <div><h3>检测与修复摘要</h3><span>定位结果、修复说明与验证指标</span></div>
        </div>
        <div className="repairhero">
          <div className="repaircandidate">
            <span>定位结果</span>
            <code>{functionName}</code>
            <div><b>#{detail?.rank ?? 1}</b><strong>{typeof detail?.score === "number" ? detail.score.toFixed(2) : "—"}</strong><em>{detail?.repair_method || artifact.selected?.repair || "—"}</em></div>
          </div>
          <div className="repairanalysisbox">
            <span>修复说明</span>
            <p>{(detail?.analysis || artifact.selected?.note || "该运行已生成修复产物。").slice(0, 560)}</p>
          </div>
          <div className="repairmetrics">
            <div><span>Normal</span><strong>{artifact.selected?.normal}</strong></div>
            <div><span>Malicious</span><strong>{artifact.selected?.malicious}</strong></div>
            <div><span>耗时</span><strong>{artifact.selected?.duration || "—"}</strong></div>
            <div><span>总尝试</span><strong>{totalAttempts || "—"}</strong></div>
          </div>
        </div>
        <div className="repairfacts">
          <div><span>定位函数</span><code>{functionName}</code></div>
          <div><span>源码位置</span><code>{functionPath}</code><b>{lineRange}</b></div>
          <div><span>修复产物</span><code>{repairFile}</code></div>
        </div>
      </section>
      <section className="panel sourcepanel">
        <div className="sourcehead repaircodehead"><div className="sectiontitle repairplainhead"><div><h3>代码修改差异</h3><span>{functionName}</span></div></div><div className="repaircodepath"><span>源码位置</span><code>{functionPath}</code><b>{lineRange}</b></div></div>
        <div className="sourcebody"><div className="codeblock diffblock"><div className="codetabs"><span className="active">修复差异</span><span className="diffstat addstat">+{additions}</span><span className="diffstat removestat">-{removals}</span><span>{language.toUpperCase()}</span></div><div className="diffcode" role="table" aria-label="修复前后代码差异">{diff.map((line,index)=>{const baseLine = detail?.start_line || 1; const oldLine = line.oldLine === null ? "" : line.oldLine + baseLine - 1; const newLine = line.newLine === null ? "" : line.newLine + baseLine - 1; return <div className={`diffline ${line.kind}`} role="row" key={`${index}-${line.kind}`}><span className="diffsign">{line.kind==="add"?"+":line.kind==="remove"?"−":" "}</span><span className="oldline">{oldLine}</span><span className="newline">{newLine}</span><code><HighlightedLine code={line.text || " "} language={language}/></code></div>})}</div></div><div className="explain"><span className="riskicon">i</span><h4>修复结果</h4><dl><div><dt>代码变化</dt><dd><span className="inlineadd">+{additions}</span> <span className="inlineremove">-{removals}</span></dd></div><div><dt>总尝试</dt><dd>{totalAttempts} 次</dd></div><div><dt>验证</dt><dd>N {artifact.selected?.normal} / M {artifact.selected?.malicious}</dd></div><div><dt>规则数</dt><dd>{detail?.rules ?? artifact.selected?.rules ?? 0}</dd></div><div><dt>目录</dt><dd>{artifact.selected?.directory}</dd></div></dl></div></div>
      </section>
      </>}

      {detailView === "protection" && <section className="panel protectionevidence">
        <div className="sectiontitle repairplainhead"><div><h3>防护机制</h3><span>{repairStory.protectionName} · {detail?.rules ?? artifact.selected?.rules ?? 0} 条规则</span></div></div>
        <div className="protectionflow" aria-label="修补后的防护流程">
          <div><span>1</span><strong>请求进入</strong><p>正常请求与恶意请求进入同一业务入口。</p></div><i aria-hidden="true">→</i>
          <div className="guard"><span>2</span><strong>规则检查</strong><p>{repairStory.protectionSummary}</p></div><i aria-hidden="true">→</i>
          <div><span>3</span><strong>分流执行</strong><p>符合规则的操作继续执行，危险路径在敏感操作前被阻断。</p></div>
        </div>
        <div className="protectionrules">
          <div className="sectiontitle"><div><h3>实际规则证据</h3><span>来自该次运行的修补产物</span></div></div>
          {protectionRules.length ? <div className="protectionrulelist">{protectionRules.slice(0, 24).map((rule, index) => <div key={`${rule.group}-${index}`}><span>{rule.group}</span><code>{rule.value}</code></div>)}</div> : <div className="emptyevidence"><strong>产物中未记录逐条规则</strong><p>仍可在“修改详情”中查看实际代码变化；这里不会用示例规则替代真实结果。</p></div>}
        </div>
      </section>}

      {detailView === "validation" && <section className="panel repairvalidation">
        <div className="sectiontitle repairplainhead"><div><h3>验证结果</h3><span>同时检查可用性与攻击阻断效果</span></div><span className={`repairstorystatus ${repairStory.resultTone}`}>{repairStory.resultTone === "success" ? "修补有效" : "证据待补充"}</span></div>
        <div className="repairvalidationrows">
          <div className={normalPassed ? "passed" : "failed"}><span>{normalPassed ? "✓" : "!"}</span><div><strong>正常流程</strong><p>修补后原有业务是否仍可正常运行</p></div><b>{repairStory.normalSummary}</b></div>
          <div className={maliciousBlocked ? "passed" : "failed"}><span>{maliciousBlocked ? "✓" : "!"}</span><div><strong>恶意路径</strong><p>复现攻击时危险行为是否被成功阻断</p></div><b>{repairStory.maliciousSummary}</b></div>
        </div>
        <div className={`repairvalidationconclusion ${repairStory.resultTone}`}><span>结论</span><strong>{repairStory.resultSummary}</strong><small>Stage 10 · validate · {artifact.selected?.directory}</small></div>
        <div className="repairvalidationlog"><div><strong>验证日志证据</strong><span>最近 {Math.min(detail?.log_tail?.length || 0, 12)} 行</span></div>{detail?.log_tail?.length ? <pre>{detail.log_tail.slice(-12).join("\n")}</pre> : <p>该运行产物未提供日志摘要。</p>}</div>
      </section>}
    </div>;
  }
  return <div className="content detectcontent">
    <div className="headline detectintro"><div><p className="eyebrow">STAGE 7–9 · DETECT / REPAIR / WHITELIST</p><h2>检测与修复</h2><p>该场景的检测详情还没有生成可视化摘要。</p></div><div className="detectsummary"><div><strong>—</strong><span>待生成</span></div></div></div>
    <section className="panel sourcepanel"><div className="sourcehead"><div><p className="eyebrow">RESULTS</p><h3>检测结果摘要</h3></div></div><div className="sourcebody"><div className="explain"><h4>{cve}</h4><p>完成运行后，可根据 `detect`、`repair`、`repair_with_whitelist` 和 `repair_validated` 目录生成本页内容。</p><dl><div><dt>当前状态</dt><dd>等待生成摘要</dd></div><div><dt>产物目录</dt><dd>data/*/{cve}</dd></div></dl></div></div></section>
  </div>;
}

function WhitelistValidation({ cve, selectedArtifactId, onSelectedArtifactIdChange }: { cve: string } & ArtifactSelectionProps) {
  const [expanded, setExpanded] = useState("connect");
  const [resultFilter, setResultFilter] = useState("全部");
  const [showLogs, setShowLogs] = useState(true);
  const artifact = useArtifactView(cve, {selectedArtifactId, onSelectedArtifactIdChange});
  if (artifact.records.length) {
    const detail = artifact.detail;
    const resultRows = [
      {type:"正常", request:"validate_normal_request()", expected:"允许", actual:artifact.selected?.normal === "✓" ? "允许" : "未通过", status:artifact.selected?.normal === "✓" ? "通过" : "风险", time:"—"},
      {type:"恶意", request:"validate_malicious_request()", expected:"阻断", actual:artifact.selected?.malicious === "✓" ? "阻断" : "未阻断", status:artifact.selected?.malicious === "✓" ? "拦截" : "风险", time:"—"},
    ];
    const visible = resultFilter === "全部" ? resultRows : resultRows.filter(r=>r.type===resultFilter);
    const totalAttempts = totalRepairAttempts(detail, artifact.selected);
    const rules = detail?.syscall_rules?.length ? detail.syscall_rules : [{name: detail?.repair_method === "network" ? "network_whitelist" : "whitelist", count: detail?.rules ?? artifact.selected?.rules ?? 0, values: detail?.rules ? ["规则已写入修复产物"] : ["未生成显式白名单规则"]}];
    return <div className="content whitelistcontent">
      <div className="headline whitelistintro"><div><p className="eyebrow">STAGE 9–10 · WHITELIST / VALIDATE</p><h2>白名单与验证</h2><p>选择一次历史运行，查看该运行的白名单、验证矩阵和日志。</p></div><div className={`validationbadge ${artifact.selected?.status==="成功"?"passed":"review"}`}><span>{artifact.selected?.status==="成功"?"✓ 验证通过":"△ 需要复核"}</span><strong>Normal {artifact.selected?.normal} · Malicious {artifact.selected?.malicious} · 总尝试 {totalAttempts} 次</strong></div></div>
      <ArtifactSelector records={artifact.records} selectedId={artifact.selectedId} onChange={artifact.setSelectedId}/>
      <div className="whitelistgrid">
        <section className="panel ruletree">
          <div className="sectiontitle"><div><h3>白名单规则</h3><span>{detail?.repair_file || artifact.selected?.directory}</span></div></div>
          <div className="treebody">
            {rules.map(rule=><div className="treegroup" key={rule.name}><button className="treeroot" onClick={()=>setExpanded(expanded===rule.name?"":rule.name)}><i>{expanded===rule.name?"⌄":"›"}</i><code>{rule.name}</code><span>{detail?.repair_method || artifact.selected?.repair}</span><b>{rule.count} 条</b></button>{expanded===rule.name&&<div className="treechildren">{(rule.values||[]).slice(0,12).map((value,i)=><div key={`${rule.name}-${i}`}><span className="branch">└</span><i className="rule">RULE</i><code>{String(value)}</code><small>{i+1}</small></div>)}</div>}</div>)}
          </div>
        </section>
        <aside className="panel coveragepanel">
          <div className="sectiontitle"><div><h3>验证概况</h3><span>{artifact.selected?.duration}</span></div></div>
          <div className={`coveragecircle ${artifact.selected?.status==="成功"?"":"low"}`}><div><strong>{artifact.selected?.status==="成功"?"100":"0"}<small>%</small></strong><span>{artifact.selected?.status}</span></div></div>
          <div className="coveragestats"><div><span>正常验证</span><b>{artifact.selected?.normal}</b></div><div><span>恶意验证</span><b>{artifact.selected?.malicious}</b></div><div><span>总尝试次数</span><b>{totalAttempts}</b></div><div><span>规则数量</span><b>{detail?.rules ?? artifact.selected?.rules ?? 0}</b></div></div>
          <p className={`coveragehint ${artifact.selected?.status==="成功"?"":"danger"}`}>{artifact.selected?.note}</p>
        </aside>
      </div>
      <section className="panel validationresults">
        <div className="validationtop"><div><p className="eyebrow">STAGE 10</p><h3>验证矩阵</h3></div><div className="resultmetrics"><div className="normal"><strong>{artifact.selected?.normal}</strong><span>正常请求</span></div><div className="malicious"><strong>{artifact.selected?.malicious}</strong><span>恶意请求</span></div><div><strong>{totalAttempts}</strong><span>总尝试</span></div><div><strong>{detail?.rules ?? artifact.selected?.rules ?? 0}</strong><span>规则</span></div></div></div>
        <div className="resulttoolbar"><div>{["全部","正常","恶意"].map(f=><button key={f} className={resultFilter===f?"active":""} onClick={()=>setResultFilter(f)}>{f}</button>)}</div></div>
        <div className="resulttable"><div className="resulttr head"><span>类型</span><span>请求</span><span>预期</span><span>实际</span><span>耗时</span><span>结果</span></div>{visible.map((r,i)=>{const ok = r.status==="通过" || r.status==="拦截"; return <button className="resulttr" key={i}><span><i className={r.type==="正常"?"normaldot":"baddot"}/>{r.type}</span><code>{r.request}</code><span>{r.expected}</span><span>{r.actual}</span><span>{r.time}</span><strong className={ok?"pass":"review"}>{ok?"✓":"△"} {r.status}</strong></button>})}</div>
      </section>
      <section className="panel validatelog"><div className="terminalhead"><div><span className="pulse">●</span><b>运行日志</b><em>{artifact.selected?.directory}</em></div><div><button onClick={()=>setShowLogs(!showLogs)}>{showLogs?"收起":"展开"}</button></div></div>{showLogs&&<div className="logbody">{(detail?.log_tail || []).map((line,i)=><div key={i} className={line.includes("✓")||line.includes("Validation passed")?"successlog":line.includes("WARNING")||line.includes("failed")?"warninglog":""}>{line}</div>)}</div>}</section>
    </div>;
  }
  return <div className="content whitelistcontent">
    <div className="headline whitelistintro"><div><p className="eyebrow">STAGE 9–10 · WHITELIST / VALIDATE</p><h2>白名单与验证</h2><p>该场景的验证详情还没有生成可视化摘要。</p></div><div className="validationbadge review"><span>△ 待生成</span><strong>请查看历史运行</strong></div></div>
    <section className="panel validationresults"><div className="validationtop"><div><p className="eyebrow">RESULTS</p><h3>{cve}</h3></div></div><p className="coveragehint danger">历史运行页会列出已有产物；详细矩阵可继续从 `repair_validated` 和 `pipeline.log` 中提取。</p></section>
  </div>;
}

function useHistoryData(cve?: string) {
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const artifactResponse = await bridgeFetch(`/artifacts${cve?`?cve=${encodeURIComponent(cve)}`:""}`, {signal:AbortSignal.timeout(10000)});
      if (!artifactResponse.ok) throw new Error(`HTTP ${artifactResponse.status}`);
      const artifacts = await artifactResponse.json();
      if (!Array.isArray(artifacts)) throw new Error("Invalid artifacts response");
      const artifactRuns = artifacts as HistoryRecord[];
      setRecords(artifactRuns.filter(record => record.source === "artifact"));
    } catch {
      setRecords(previous => previous);
    } finally {
      setLoading(false);
    }
  }, [cve]);
  useEffect(() => { load(); const timer = window.setInterval(load, 5000); return () => window.clearInterval(timer); }, [load]);
  return {records, loading, reload: load};
}

function isActiveHistoryRecord(record: HistoryRecord) {
  return record.status === "运行中" || record.status === "排队中";
}

function canDeleteHistoryRecord(record: HistoryRecord) {
  return !isActiveHistoryRecord(record) && !!(record.directory || record.id);
}

function HistoryTable({
  records,
  onDelete,
  selectedIds,
  onToggleSelect,
  onToggleAll,
}: {
  records: HistoryRecord[];
  onDelete?: (record:HistoryRecord)=>void;
  selectedIds?: Set<string>;
  onToggleSelect?: (record: HistoryRecord) => void;
  onToggleAll?: () => void;
}) {
  const [openRun, setOpenRun] = useState("");
  const deletable = records.filter(canDeleteHistoryRecord);
  const allSelected = !!selectedIds && deletable.length > 0 && deletable.every(record => selectedIds.has(record.id));
  return <div className="historytable"><div className="historyrow head"><span className="rowselect">{selectedIds&&onToggleAll?<input className="historycheck" type="checkbox" checked={allSelected} onChange={onToggleAll} disabled={!deletable.length} aria-label="选择当前列表"/>:null}</span><span>运行 / 时间</span><span>CVE</span><span>状态</span><span>总耗时</span><span>修复方式</span><span>规则</span><span>验证结果</span><span></span></div>{records.map(r=>{const active = isActiveHistoryRecord(r); const selectable = !!selectedIds && !!onToggleSelect && canDeleteHistoryRecord(r); return <div key={r.id} className={`historyrow ${openRun===r.id?"open":""}`}><span className="rowselect">{selectedIds&&onToggleSelect?<input className="historycheck" type="checkbox" checked={selectedIds.has(r.id)} disabled={!selectable} onChange={()=>selectable&&onToggleSelect(r)} aria-label={`选择 ${r.id}`}/>:null}</span><button className="runidentity" onClick={()=>setOpenRun(openRun===r.id?"":r.id)}><code>{r.id}</code><small>{r.date}</small></button><span>{r.cve}</span><strong className={`runstatus ${r.status}`}>{r.status}</strong><span>{r.duration}</span><span>{r.repair}</span><b>{r.rules}</b><span className="validationmini"><i className={r.normal==="✓"?"ok":r.normal==="✗"?"warn":"idle"}/>N {r.normal}<i className={r.malicious==="✓"?"ok":r.malicious==="✗"?"warn":"idle"}/>M {r.malicious}</span><button className="more" aria-label="展开运行详情" onClick={()=>setOpenRun(openRun===r.id?"":r.id)}>•••</button>{openRun===r.id&&<div className="rundrawer"><div><span>来源</span><b>{r.source==="artifact"?"磁盘产物":"Bridge"}</b></div><div><span>目录</span><b>{r.directory||"当前任务"}</b></div><div><span>说明</span><b>{r.note}</b></div>{onDelete&&<button className="deleterun" disabled={active} onClick={()=>!active&&onDelete(r)} aria-label={active?"运行中不能删除":"删除这条历史记录"}>{active?"运行中":"删除"}</button>}</div>}</div>})}</div>;
}

async function deleteWithDockerCleanup(url: string) {
  if (!DEFAULT_SUDO_PASSWORD) return bridgeFetch(url, {method:"DELETE"});
  const separator = url.includes("?") ? "&" : "?";
  const urlWithPassword = `${url}${separator}sudo_password=${encodeURIComponent(DEFAULT_SUDO_PASSWORD)}`;
  return bridgeFetch(urlWithPassword, {method:"DELETE"});
}

async function deleteHistoryRecords(records: HistoryRecord[]) {
  const targets = records.filter(canDeleteHistoryRecord);
  if (!targets.length) {
    window.alert("该运行仍在执行或排队，结束或取消后才能删除。");
    return {deleted: 0, failed: 0};
  }
  const label = targets.length === 1 ? (targets[0].directory || targets[0].id) : `${targets.length} 条记录`;
  if (!window.confirm(`永久删除 ${label}？会先关闭对应 CVE 容器，再删除本地文件。`)) return {deleted: 0, failed: 0};
  let deleted = 0;
  let failed = 0;
  for (const record of targets) {
    const url = record.source === "artifact" && record.directory
      ? `/artifact?directory=${encodeURIComponent(record.directory)}`
      : `/runs/${encodeURIComponent(record.id)}`;
    try {
      const response = await deleteWithDockerCleanup(url);
      if (response.ok) deleted += 1;
      else failed += 1;
    } catch {
      failed += 1;
    }
  }
  if (failed) window.alert(`已删除 ${deleted} 条，失败 ${failed} 条。`);
  return {deleted, failed};
}

async function deleteHistoryRecord(record: HistoryRecord) {
  const result = await deleteHistoryRecords([record]);
  return result.deleted > 0;
}

function HistoryRuns({ cve }: { cve: string }) {
  const [status, setStatus] = useState("全部状态");
  const [search, setSearch] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const {records, loading, reload} = useHistoryData(cve);
  const filteredRuns = records.filter(r=>(status==="全部状态"||r.status===status)&&(search.trim()===""||r.id.toLowerCase().includes(search.toLowerCase())||r.note.toLowerCase().includes(search.toLowerCase())));
  const successCount = records.filter(r=>r.status==="成功").length;
  const activeCount = records.filter(r=>r.status==="运行中"||r.status==="排队中").length;
  const avgSeconds = records.length ? Math.round(records.reduce((sum,r)=>sum+(r.seconds||0),0)/records.length) : 0;
  const selectedRecords = filteredRuns.filter(record => selectedIds.has(record.id) && canDeleteHistoryRecord(record));
  useEffect(() => {
    setSelectedIds(previous => {
      const validIds = new Set(records.filter(canDeleteHistoryRecord).map(record => record.id));
      const next = new Set([...previous].filter(id => validIds.has(id)));
      return next.size === previous.size ? previous : next;
    });
  }, [records]);
  const deleteRecord = async (record: HistoryRecord) => {
    if (await deleteHistoryRecord(record)) {
      setSelectedIds(previous => { const next = new Set(previous); next.delete(record.id); return next; });
      await reload();
    }
  };
  const toggleSelect = (record: HistoryRecord) => {
    if (!canDeleteHistoryRecord(record)) return;
    setSelectedIds(previous => {
      const next = new Set(previous);
      if (next.has(record.id)) next.delete(record.id);
      else next.add(record.id);
      return next;
    });
  };
  const toggleAll = () => {
    const visible = filteredRuns.filter(canDeleteHistoryRecord);
    const allSelected = visible.length > 0 && visible.every(record => selectedIds.has(record.id));
    setSelectedIds(previous => {
      const next = new Set(previous);
      visible.forEach(record => allSelected ? next.delete(record.id) : next.add(record.id));
      return next;
    });
  };
  const deleteSelected = async () => {
    const result = await deleteHistoryRecords(selectedRecords);
    if (result.deleted) {
      setSelectedIds(new Set());
      await reload();
    }
  };
  const clearHistory = async () => {
    if (activeCount) {
      window.alert("当前 CVE 有运行中或排队中的记录，结束或取消后才能清空历史。");
      return;
    }
    if (!window.confirm(`永久清空 ${cve} 的全部历史？会先关闭该 CVE 容器，再删除本地产物目录。`)) return;
    const response = await deleteWithDockerCleanup(`/artifacts/${encodeURIComponent(cve)}`);
    if (!response.ok) { window.alert(`清空失败：HTTP ${response.status}`); return; }
    await reload();
  };
  return <div className="content historycontent">
    <div className="headline historyintro"><div><p className="eyebrow">CURRENT CVE HISTORY</p><h2>{cve} 历史运行</h2><p>仅显示 data 目录中的 CVE 验证产物。</p></div><button className="exporthistory dangerbtn" onClick={clearHistory} disabled={!records.length||!!activeCount}>清空历史记录</button></div>
    <div className="historymetrics"><div><span>历史记录</span><strong>{records.length}</strong><small>{loading?"正在读取":"当前 CVE"}</small></div><div><span>成功记录</span><strong className="greenvalue">{successCount}</strong><small>{records.length?`${Math.round(successCount/records.length*100)}%`:"暂无"}</small></div><div><span>产物记录</span><strong className="ambervalue">{records.filter(r=>r.source==="artifact").length}</strong><small>来自 data 目录</small></div><div><span>平均耗时</span><strong>{avgSeconds?`${Math.floor(avgSeconds/60)}m ${avgSeconds%60}s`:"—"}</strong><small>已有统计</small></div></div>
    <section className="panel historypanel">
      <div className="historytoolbar"><div><label>⌕<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="搜索记录"/></label><select value={status} onChange={e=>setStatus(e.target.value)}><option>全部状态</option><option>运行中</option><option>排队中</option><option>成功</option><option>部分完成</option><option>需复核</option><option>失败</option></select></div><div className="batchactions"><span>{filteredRuns.length} / {records.length} 条</span><button className="dangerbtn batchdelete" onClick={deleteSelected} disabled={!selectedRecords.length}>删除选中{selectedRecords.length?` ${selectedRecords.length}`:""}</button></div></div>
      {filteredRuns.length ? <HistoryTable records={filteredRuns} onDelete={deleteRecord} selectedIds={selectedIds} onToggleSelect={toggleSelect} onToggleAll={toggleAll}/> : <div className="emptylog">{loading?"正在读取历史记录…":"当前 CVE 暂无历史记录"}</div>}
    </section>
  </div>;
}

function RecentResults() {
  const [search, setSearch] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const {records, loading, reload} = useHistoryData();
  const filtered = records.filter(r=>search.trim()===""||r.cve.toLowerCase().includes(search.toLowerCase())||r.id.toLowerCase().includes(search.toLowerCase())||r.note.toLowerCase().includes(search.toLowerCase()));
  const latest = filtered[0];
  const selectedRecords = filtered.filter(record => selectedIds.has(record.id) && canDeleteHistoryRecord(record));
  useEffect(() => {
    setSelectedIds(previous => {
      const validIds = new Set(records.filter(canDeleteHistoryRecord).map(record => record.id));
      const next = new Set([...previous].filter(id => validIds.has(id)));
      return next.size === previous.size ? previous : next;
    });
  }, [records]);
  const deleteRecord = async (record: HistoryRecord) => {
    if (await deleteHistoryRecord(record)) {
      setSelectedIds(previous => { const next = new Set(previous); next.delete(record.id); return next; });
      await reload();
    }
  };
  const toggleSelect = (record: HistoryRecord) => {
    if (!canDeleteHistoryRecord(record)) return;
    setSelectedIds(previous => {
      const next = new Set(previous);
      if (next.has(record.id)) next.delete(record.id);
      else next.add(record.id);
      return next;
    });
  };
  const toggleAll = () => {
    const visible = filtered.filter(canDeleteHistoryRecord);
    const allSelected = visible.length > 0 && visible.every(record => selectedIds.has(record.id));
    setSelectedIds(previous => {
      const next = new Set(previous);
      visible.forEach(record => allSelected ? next.delete(record.id) : next.add(record.id));
      return next;
    });
  };
  const deleteSelected = async () => {
    const result = await deleteHistoryRecords(selectedRecords);
    if (result.deleted) {
      setSelectedIds(new Set());
      await reload();
    }
  };
  return <div className="content historycontent">
    <div className="headline historyintro"><div><p className="eyebrow">RECENT RESULTS</p><h2>最近结果</h2><p>汇总所有 CVE 的最近任务和磁盘产物，用于快速查看整体进展。</p></div></div>
    {latest&&<section className="panel recenthero"><div><span>最近记录</span><h3>{latest.cve}</h3><p>{latest.note}</p></div><strong className={`runstatus ${latest.status}`}>{latest.status}</strong><code>{latest.directory||latest.id}</code></section>}
    <section className="panel historypanel">
      <div className="historytoolbar"><div><label>⌕<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="搜索 CVE 或 Run ID"/></label></div><div className="batchactions"><span>{filtered.length} 条记录</span><button className="dangerbtn batchdelete" onClick={deleteSelected} disabled={!selectedRecords.length}>删除选中{selectedRecords.length?` ${selectedRecords.length}`:""}</button></div></div>
      {filtered.length ? <HistoryTable records={filtered} onDelete={deleteRecord} selectedIds={selectedIds} onToggleSelect={toggleSelect} onToggleAll={toggleAll}/> : <div className="emptylog">{loading?"正在读取最近结果…":"暂无最近结果"}</div>}
    </section>
  </div>;
}

type AuthState = {
  status: "checking" | "unlocked" | "token-required" | "remote-blocked" | "bridge-offline";
  tokenRequired: boolean;
  message: string;
};

function AuthScreen({state, theme, onThemeToggle, onUnlock}: {state: AuthState; theme: "light"|"dark"; onThemeToggle: () => void; onUnlock: () => void}) {
  const [token, setToken] = useState("");
  const [message, setMessage] = useState(state.message);
  const [checking, setChecking] = useState(false);
  const bridgeUrl = inferBridgeUrl();
  const header = (label: string) => <div className="authheader"><p className="eyebrow">{label}</p><button className="auth-themebutton" onClick={onThemeToggle} aria-label="切换暗色模式">{theme === "dark" ? "☀" : "☾"}</button></div>;
  const verify = async () => {
    setChecking(true);
    setMessage("正在验证访问口令...");
    try {
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/health`, {
        headers: token.trim() ? {Authorization: `Bearer ${token.trim()}`} : {},
        signal: AbortSignal.timeout(4000),
      });
      if (!response.ok) throw new Error(response.status === 401 ? "口令不正确" : `HTTP ${response.status}`);
      window.localStorage.setItem(BRIDGE_TOKEN_STORAGE_KEY, token.trim());
      onUnlock();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "验证失败");
    } finally {
      setChecking(false);
    }
  };
  if (state.status === "remote-blocked") {
    return <main className="authshell"><section className="authcard">{header("LOCAL MODE")}<h1>Kintsugi 仅允许本机访问</h1><p>{state.message}</p><code>请在这台电脑打开 http://127.0.0.1:5173</code></section></main>;
  }
  if (state.status === "bridge-offline") {
    return <main className="authshell"><section className="authcard">{header("BRIDGE OFFLINE")}<h1>等待 Bridge 启动</h1><p>{state.message}</p><code>{bridgeUrl}</code><button onClick={onUnlock}>重新检查</button></section></main>;
  }
  return <main className="authshell"><section className="authcard">{header("TOKEN MODE")}<h1>Kintsugi 访问验证</h1><p>{message}</p><label><span>访问口令</span><input type="password" value={token} autoComplete="current-password" autoFocus onChange={event=>setToken(event.target.value)} onKeyDown={event=>{if(event.key==="Enter")verify();}} placeholder="请输入 token"/></label><button disabled={checking || !token.trim()} onClick={verify}>{checking ? "验证中..." : "进入控制台"}</button></section></main>;
}

export default function Home() {
  const [selected, setSelected] = useState(DEFAULT_CVE);
  const [activeNav, setActiveNav] = useState("运行总览");
  const [logOpen, setLogOpen] = useState(true);
  const [activeRun, setActiveRun] = useState<ActiveRunSummary>({cve: DEFAULT_CVE, runId: "", status: "idle", progress: 0, running: false});
  const [query, setQuery] = useState("");
  const [selectedArtifacts, setSelectedArtifacts] = useState<Record<string,string>>({});
  const [selectedMonitorRunId, setSelectedMonitorRunId] = useState("");
  const [theme, setTheme] = useState<"light"|"dark">("light");
  const [themeLoaded, setThemeLoaded] = useState(false);
  const [auth, setAuth] = useState<AuthState>({status: "checking", tokenRequired: false, message: "正在检查访问模式..."});
  const [cvePickerOpen, setCvePickerOpen] = useState(false);
  const {runs: bridgeRuns, loading: bridgeRunsLoading, refresh: refreshBridgeRuns} = useBridgeRuns(auth.status === "unlocked");
  const filtered = useMemo(() => cves.filter(c => c.id.toLowerCase().includes(query.toLowerCase()) || c.app.toLowerCase().includes(query.toLowerCase())), [query]);
  const selectedCve = cves.find(c => c.id === selected) || cves[0];
  const handleRunState = useCallback((run: ActiveRunSummary) => setActiveRun(run), []);
  const handleArtifactSelect = useCallback((id: string) => {
    setSelectedArtifacts(values => ({...values, [selected]: id}));
  }, [selected]);
  const activeBridgeRuns = useMemo(() => bridgeRuns.filter(isActiveBridgeRun).sort((a, b) => {
    if (a.status === "running" && b.status !== "running") return -1;
    if (a.status !== "running" && b.status === "running") return 1;
    return (a.created_at || 0) - (b.created_at || 0);
  }), [bridgeRuns]);
  const currentBridgeRun = activeBridgeRuns[0] || null;
  const running = Boolean(currentBridgeRun);
  const currentProgressState = bridgeRunProgressState(currentBridgeRun);
  const currentProgress = currentProgressState.progress;
  const currentStageText = runStageLabel(currentBridgeRun);
  const jumpToBridgeRun = useCallback((run: BridgeRun | null) => {
    if (run) {
      setSelected(run.cve);
      setSelectedMonitorRunId(run.run_id);
      setActiveNav("运行控制台");
      return;
    }
    setActiveNav("新建任务");
  }, []);
  const handleTaskAccepted = useCallback((run: BridgeRun) => {
    setSelected(run.cve);
    setSelectedMonitorRunId(run.run_id);
    setActiveNav("运行控制台");
    refreshBridgeRuns();
  }, [refreshBridgeRuns]);
  const cancelBridgeRun = useCallback(async (runId: string) => {
    try {
      await bridgeFetch(`/runs/${runId}/cancel`, {method: "POST"});
      await refreshBridgeRuns();
    } catch {}
  }, [refreshBridgeRuns]);
  const cancelAllBridgeRuns = useCallback(async () => {
    const active = bridgeRuns.filter(isActiveBridgeRun);
    await Promise.allSettled(active.map(run => bridgeFetch(`/runs/${run.run_id}/cancel`, {method: "POST"})));
    await refreshBridgeRuns();
  }, [bridgeRuns, refreshBridgeRuns]);
  const clearCompletedBridgeRuns = useCallback(async () => {
    const completed = bridgeRuns.filter(run => !isActiveBridgeRun(run));
    await Promise.allSettled(completed.map(run => bridgeFetch(`/runs/${run.run_id}`, {method: "DELETE"})));
    await refreshBridgeRuns();
  }, [bridgeRuns, refreshBridgeRuns]);

  useEffect(() => {
    if (!selectedMonitorRunId && currentBridgeRun?.run_id) setSelectedMonitorRunId(currentBridgeRun.run_id);
  }, [currentBridgeRun, selectedMonitorRunId]);

  useEffect(() => {
    const saved = window.localStorage.getItem("kintsugi-theme");
    const initial = saved === "dark" || saved === "light"
      ? saved
      : window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    setTheme(initial);
    setThemeLoaded(true);
  }, []);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    if (themeLoaded) window.localStorage.setItem("kintsugi-theme", theme);
  }, [theme, themeLoaded]);

  const checkAuth = useCallback(async () => {
    const bridgeUrl = inferBridgeUrl();
    try {
      const response = await fetch(`${bridgeUrl.replace(/\/$/,"")}/auth-status`, {signal: AbortSignal.timeout(3500)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const tokenRequired = Boolean(data.token_required);
      if (!tokenRequired) {
        window.localStorage.removeItem(BRIDGE_TOKEN_STORAGE_KEY);
        if (!isLocalBrowserHost()) {
          setAuth({status: "remote-blocked", tokenRequired: false, message: "当前 Bridge 以无 token 本机模式启动，远程设备不能进入控制台。"});
          return;
        }
        setAuth({status: "unlocked", tokenRequired: false, message: ""});
        return;
      }
      const token = getBridgeToken();
      if (token) {
        const health = await fetch(`${bridgeUrl.replace(/\/$/,"")}/health`, {
          headers: {Authorization: `Bearer ${token}`},
          signal: AbortSignal.timeout(3500),
        });
        if (health.ok) {
          setAuth({status: "unlocked", tokenRequired: true, message: ""});
          return;
        }
      }
      setAuth({status: "token-required", tokenRequired: true, message: "请输入启动时配置的访问口令。"});
    } catch {
      if (isLocalBrowserHost()) setAuth({status: "unlocked", tokenRequired: false, message: ""});
      else setAuth({status: "bridge-offline", tokenRequired: false, message: "无法连接本机 Bridge，请确认 start.sh 已启动且 Bridge 地址可访问。"});
    }
  }, []);

  useEffect(() => { checkAuth(); }, [checkAuth]);

  if (auth.status === "checking") return <main className="authshell"><section className="authcard"><div className="authheader"><p className="eyebrow">KINTSUGI</p><button className="auth-themebutton" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="切换暗色模式">{theme === "dark" ? "☀" : "☾"}</button></div><h1>正在检查访问模式</h1><p>{auth.message}</p></section></main>;
  if (auth.status !== "unlocked") return <AuthScreen state={auth} theme={theme} onThemeToggle={() => setTheme(theme === "dark" ? "light" : "dark")} onUnlock={checkAuth}/>;

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><div><b>Kintsugi</b><span>实验控制台</span></div></div>
        <label className="search"><span>⌕</span><input value={query} onChange={e => setQuery(e.target.value)} placeholder="搜索 CVE 或应用" /></label>
        <div className="filterrow"><span className="filter active">全部 {cves.length}</span></div>
        <button className={`mobilecvepicker ${cvePickerOpen ? "open" : ""}`} onClick={() => setCvePickerOpen(open => !open)} aria-expanded={cvePickerOpen} aria-controls="mobile-cve-list">
          <div><strong>{selected}</strong><span>{selectedCve.lang} · {selectedCve.app}</span></div><i>⌄</i>
        </button>
        <div className={`cvelist ${cvePickerOpen ? "open" : ""}`} id="mobile-cve-list">
          {filtered.map(c => <button key={c.id} className={`cve ${selected === c.id ? "selected" : ""}`} onClick={() => { setSelected(c.id); setCvePickerOpen(false); }}>
            <div><strong>{c.id}</strong></div>
            <small><em>{c.lang}</em>{c.app}</small>
          </button>)}
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><h1>{selected}</h1><span className="pill">{selectedCve.lang}</span><span className="pill dark">{selectedCve.app}</span></div>
          <div className="actions">{running&&<button className="health activejob" onClick={() => jumpToBridgeRun(currentBridgeRun)}>● {currentBridgeRun?.cve} · {currentStageText} · {currentProgress}%</button>}<button className="themebutton" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="切换暗色模式">{theme === "dark" ? "☀" : "☾"}</button><button className="secondary" onClick={() => setActiveNav("最近结果")}>打开最近结果</button><button className="primary" onClick={() => jumpToBridgeRun(currentBridgeRun)}>{running ? "查看当前任务" : "+ 新建任务"}</button></div>
          {running&&<button className="mobileactivejob" onClick={() => jumpToBridgeRun(currentBridgeRun)}><div><span>{currentBridgeRun?.cve}</span><b>{currentStageText} · {currentProgress}%</b></div><i className={`active ${currentProgressState.rewindFrom > currentProgress ? "rewound" : ""}`} style={{"--progress": `${currentProgress}%`,"--rollback-start":`${Math.min(currentProgress,currentProgressState.rewindFrom)}%`,"--rollback-end":`${Math.max(currentProgress,currentProgressState.rewindFrom)}%`} as React.CSSProperties}/></button>}
        </header>

        <nav className="tabs">{navItems.map(n => <button key={n} onClick={() => setActiveNav(n)} className={activeNav === n ? "active" : ""} aria-current={activeNav === n ? "page" : undefined}><span className="tabicon" aria-hidden="true">{navIcons[n]}</span>{n}</button>)}</nav>

        <div className={`viewpane ${activeNav === "新建任务" ? "active" : ""}`}>{activeNav === "新建任务" && <RunConsole cve={selected} onRunStateChange={handleRunState} onTaskAccepted={handleTaskAccepted} selectedArtifactId={selectedArtifacts[selected]} onSelectedArtifactIdChange={handleArtifactSelect} bridgeAuthRequired={auth.tokenRequired}/>}</div>
        <div className={`viewpane ${activeNav === "运行控制台" ? "active" : ""}`}>{activeNav === "运行控制台" && <TaskMonitor runs={bridgeRuns} loading={bridgeRunsLoading} selectedRunId={selectedMonitorRunId} onSelectedRunIdChange={runId => { setSelectedMonitorRunId(runId); const run = bridgeRuns.find(item => item.run_id === runId); if (run) setSelected(run.cve); }} onCancelRun={cancelBridgeRun} onCancelAllRuns={cancelAllBridgeRuns} onClearCompletedRuns={clearCompletedBridgeRuns} onOpenLauncher={() => setActiveNav("新建任务")}/>}</div>
        <div className={`viewpane ${activeNav === "检测与修复" ? "active" : ""}`}>{activeNav === "检测与修复" && <DetectionRepair cve={selected} selectedArtifactId={selectedArtifacts[selected]} onSelectedArtifactIdChange={handleArtifactSelect}/>}</div>
        <div className={`viewpane ${activeNav === "白名单与验证" ? "active" : ""}`}>{activeNav === "白名单与验证" && <WhitelistValidation cve={selected} selectedArtifactId={selectedArtifacts[selected]} onSelectedArtifactIdChange={handleArtifactSelect}/>}</div>
        <div className={`viewpane ${activeNav === "历史运行" ? "active" : ""}`}>{activeNav === "历史运行" && <HistoryRuns cve={selected}/>}</div>
        <div className={`viewpane ${activeNav === "最近结果" ? "active" : ""}`}>{activeNav === "最近结果" && <RecentResults/>}</div>
        <div className={`viewpane ${activeNav === "运行总览" ? "active" : ""}`}>{activeNav === "运行总览" && <RunOverview cve={selected} selectedArtifactId={selectedArtifacts[selected]} onSelectedArtifactIdChange={handleArtifactSelect}/>}</div>
      </section>
    </main>
  );
}
