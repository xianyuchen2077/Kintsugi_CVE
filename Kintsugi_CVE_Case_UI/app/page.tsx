'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent, RefObject } from 'react';
import { CVE_PROFILES } from './case-state.mjs';
import TrafficComparison, { scenarios } from './traffic-comparison';
import type { TrafficRun } from './traffic-comparison';
import SampleViewer from './sample-viewer';
import ProcessEvidence from './process-evidence';
import GhostscriptObserver from './ghostscript-observer';
import { inspectFile } from './sample-inspection.mjs';
import PatchLab from './patch-lab';
import CactiLab from './cacti-lab';
import { cactiSnapshot } from './cacti-scenario.mjs';
import './visual-evidence.css';
import {
  PLAYBACK_CHAPTERS,
  PLAYBACK_SPEEDS,
  createPlaybackState,
  getPlaybackSnapshot,
  transitionPlayback,
} from './presentation-state.mjs';

type BridgeUploadResponse = {
  result?: 'normal' | 'breached' | 'blocked' | 'failed';
  classification?: 'normal' | 'malicious';
  filename?: string;
  size?: number;
  repaired?: boolean;
  target_status?: number | null;
  target_error?: string | null;
  marker_path?: string;
  marker_present?: boolean;
  marker_output?: string;
  syscalls?: Record<string, number>;
  logs?: string[];
};

type MatrixEvidenceRow = {
  key: string;
  label: string;
  before: string;
  ready: string;
  after: string;
};

type GhostscriptEvidenceView = {
  uploadFields: Array<{ label: string; value: string; tone: string }>;
  boundaries: Array<{ label: string; before: string; after: string }>;
  processChain: string[];
  insight: string;
  evidenceRows: MatrixEvidenceRow[];
};

type GhostscriptReportData = {
  traffic: {
    normalRequests: number;
    maliciousRequests: number;
    normalEvents: number;
    maliciousEvents: number;
    requestUnits: number;
  };
  detection: {
    targetFunction: string;
    normalizedScore: number;
    firstPlaceCount: number;
    algorithms: readonly string[];
  };
  generatedRepair: {
    method: string;
    protectedCall: string;
    sourceLines: string;
  };
  whitelist: {
    normalSamples: number;
    extractedSyscalls: number;
    syscalls: readonly string[];
    execveAllowedPaths: readonly string[];
    deniedExamples: readonly string[];
  };
  validatedRepair: {
    method: string;
    reason: string;
    guard: string;
    isKernelEnforced: boolean;
  };
  validation: {
    normal: { status: number; responseBytes: number; ok: boolean; description: string };
    malicious: { status: number; markerPath: string; markerPresent: boolean; blocked: boolean; description: string };
    success: boolean;
    durationSeconds: number;
  };
};

type UploadVisualStatus = 'idle' | 'uploading' | 'normal' | 'breached' | 'blocked' | 'error';

type UploadVisualState = {
  repaired?: boolean;
  fileFormat?: string;
  status: UploadVisualStatus;
  flowStep: number;
  fileName: string;
  fileSize: string;
  classification: 'normal' | 'malicious' | 'unknown';
  markerPresent: boolean;
  markerPath: string;
  message: string;
  detail: string;
  logs: string[];
  syscalls: Record<string, number>;
};

const GHOSTSCRIPT_MARKER = '/tmp/got_rce';
const GHOSTSCRIPT_BASELINE_SYSCALLS = Object.freeze({ read: 34, open: 12, write: 6, execve: 0, clone: 0 });
const GHOSTSCRIPT_ATTACK_SYSCALLS = Object.freeze({ read: 42, open: 18, write: 9, execve: 5, clone: 3 });
const GHOSTSCRIPT_BLOCKED_SYSCALLS = Object.freeze({ read: 38, open: 14, write: 4, execve: 0, clone: 0 });
const GHOSTSCRIPT_FLOW_STEPS = Object.freeze([
  {
    id: 'ingress',
    title: '上传入口',
    metric: 'multipart image',
    normal: 'normal.jpg 进入图片处理接口，扩展名和业务入口匹配。',
    attack: 'rce.jpg 也被当作图片接收，第一道门没有发现伪装。',
    repaired: '入口仍允许上传，正常业务不会被粗暴关闭。',
    issue: false,
    traces: {
      normal: [
        { tone: 'command', text: '[api] POST /convert · file=normal.jpg · multipart/form-data' },
        { tone: 'output', text: '[upload] content-type=image/jpeg · extension=.jpg · accepted' },
        { tone: 'success', text: '[queue] job=IMG-2048 · route=image-worker' },
      ],
      attack: [
        { tone: 'command', text: '[api] POST /convert · file=rce.jpg · multipart/form-data' },
        { tone: 'danger', text: '[upload] content-type=image/jpeg · extension=.jpg · accepted' },
        { tone: 'warning', text: '[gap] ingress trusts the filename; payload not inspected yet' },
      ],
      repaired: [
        { tone: 'command', text: '[api] POST /convert · file=rce.jpg · multipart/form-data' },
        { tone: 'output', text: '[upload] request accepted · business endpoint remains available' },
        { tone: 'success', text: '[policy] enqueue guarded inspection before decode' },
      ],
    },
  },
  {
    id: 'identity',
    title: '文件身份',
    metric: 'JPG shell / EPS body',
    normal: '文件头和图像内容一致，Pillow 可以按普通图片解析。',
    attack: '表面是 JPG，实际内容带 PostScript 语义，身份开始错位。',
    repaired: '策略记录内容与解析器选择，伪装文件进入受控路径。',
    issue: true,
    traces: {
      normal: [
        { tone: 'command', text: '$ file --mime-type /upload/normal.jpg' },
        { tone: 'output', text: 'image/jpeg · magic=ff d8 ff e0 · JFIF' },
        { tone: 'success', text: '[pillow] format=JPEG · decoder=JpegImagePlugin' },
      ],
      attack: [
        { tone: 'command', text: '$ xxd -l 12 /upload/rce.jpg' },
        { tone: 'danger', text: '25 21 50 53 2d 41 64 6f · %!PS-Adobe' },
        { tone: 'warning', text: '[alert] extension=.jpg · parser identity=EPS' },
      ],
      repaired: [
        { tone: 'command', text: '[guard] sniff_magic(payload)' },
        { tone: 'output', text: '[guard] PostScript semantics detected inside .jpg' },
        { tone: 'success', text: '[decision] isolate sample for EPS policy check' },
      ],
    },
  },
  {
    id: 'parser',
    title: '解析边界',
    metric: 'Pillow -> Ghostscript',
    normal: '正常图片只经历缩放与保存，不需要危险子进程。',
    attack: 'Ghostscript 9.23 解释 EPS 指令，异常子进程行为出现。',
    repaired: '启动 Ghostscript 前检查 EPS 内容，发现 %pipe% 立即拒绝。',
    issue: true,
    traces: {
      normal: [
        { tone: 'command', text: '[pillow] Image.open -> thumbnail -> save' },
        { tone: 'output', text: '[process] child_process_requested=false' },
        { tone: 'success', text: '[render] normal.jpg · completed' },
      ],
      attack: [
        { tone: 'command', text: '[pillow] EpsImagePlugin.Ghostscript()' },
        { tone: 'danger', text: '$ gs -dSAFER -sDEVICE=ppmraw /tmp/kintsugi.eps' },
        { tone: 'warning', text: "[parser] token=%pipe%('/bin/sh -c touch /tmp/got_rce')" },
      ],
      repaired: [
        { tone: 'command', text: '[guard] scan_eps_tokens(payload)' },
        { tone: 'danger', text: '[deny] unsafe token=%pipe%' },
        { tone: 'success', text: '[result] Ghostscript process not started' },
      ],
    },
  },
  {
    id: 'syscall',
    title: '系统调用',
    metric: 'execve / marker',
    normal: 'execve 保持 0，容器内没有 /tmp/got_rce。',
    attack: 'execve 冲高并执行 touch /tmp/got_rce，攻击证据出现。',
    repaired: '同一文件复测返回 HTTP 500，/tmp/got_rce 不出现。',
    issue: true,
    traces: {
      normal: [
        { tone: 'command', text: '[trace] read=34 open=12 write=6' },
        { tone: 'output', text: '[trace] execve=0 clone=0' },
        { tone: 'success', text: '[fs] /tmp/got_rce -> ABSENT' },
      ],
      attack: [
        { tone: 'command', text: "[trace] gs -> execve('/bin/sh', ['sh', '-c', 'touch ...'])" },
        { tone: 'danger', text: '[trace] clone=3 execve=5 · unexpected child process' },
        { tone: 'danger', text: '[fs] /tmp/got_rce -> PRESENT' },
      ],
      repaired: [
        { tone: 'command', text: "[policy] execve('/bin/sh') -> DENY" },
        { tone: 'output', text: '[http] response=500 · blocked before execution' },
        { tone: 'success', text: '[fs] /tmp/got_rce -> ABSENT' },
      ],
    },
  },
]);

const EMPTY_UPLOAD_VISUAL: UploadVisualState = {
  status: 'idle',
  flowStep: 0,
  fileName: '',
  fileSize: '',
  classification: 'unknown',
  markerPresent: false,
  markerPath: GHOSTSCRIPT_MARKER,
  message: '等待上传图片...',
  detail: '拖拽 normal.jpg 或 rce.jpg，主画面会立即给出业务结果和系统调用变化。',
  logs: [],
  syscalls: { ...GHOSTSCRIPT_BASELINE_SYSCALLS },
};

function formatUploadSize(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function isLikelyGhostscriptAttack(file: File) {
  return /(^|[-_.])rce[-_.]?|\.eps$/i.test(file.name);
}

function createUploadFallback(file: File, repaired: boolean, malicious = isLikelyGhostscriptAttack(file)): BridgeUploadResponse {
  const result = !malicious ? 'normal' : repaired ? 'blocked' : 'breached';
  return {
    result,
    classification: malicious ? 'malicious' : 'normal',
    filename: file.name,
    size: file.size,
    repaired,
    marker_path: GHOSTSCRIPT_MARKER,
    marker_present: result === 'breached',
    syscalls: result === 'breached'
      ? { ...GHOSTSCRIPT_ATTACK_SYSCALLS }
      : result === 'blocked'
        ? { ...GHOSTSCRIPT_BLOCKED_SYSCALLS }
        : { ...GHOSTSCRIPT_BASELINE_SYSCALLS },
    logs: [
      `[playback] Processing ${file.name}...`,
      result === 'breached'
        ? 'Executing touch /tmp/got_rce...'
        : result === 'blocked'
          ? "Blocked by %pipe% input guard · IOError('unsafe EPS file')"
          : 'Normal image resize completed.',
    ],
  };
}

function normalizeUploadVisual(file: File, response: BridgeUploadResponse, repaired: boolean): UploadVisualState {
  const result = response.result === 'breached' || response.result === 'blocked' || response.result === 'normal'
    ? response.result
    : 'error';
  const status = result;
  const classification = response.classification ?? (isLikelyGhostscriptAttack(file) ? 'malicious' : 'normal');
  const message = status === 'normal'
    ? '正常图片处理路径已展示'
    : status === 'breached'
      ? '恶意路径：额外命令产生文件副作用'
      : status === 'blocked'
        ? '修补后路径：危险输入被拒绝'
        : '上传请求未完成';
  const detail = status === 'normal'
    ? '按正常样本展示图片处理路径；Stage 10 的业务验证为 HTTP 200。'
    : status === 'breached'
      ? '观察右侧额外命令与 /tmp/got_rce 的关系。本次点击展示已有案例资料，不执行后台攻击。'
      : status === 'blocked'
        ? '同一个恶意文件再次进入系统，在启动 Ghostscript 前被内容检查拒绝。'
        : response.target_error || '案例样本没有返回可用结果。';

  return {
    status,
    flowStep: GHOSTSCRIPT_FLOW_STEPS.length,
    fileName: response.filename || file.name,
    fileSize: formatUploadSize(response.size ?? file.size),
    classification,
    markerPresent: response.marker_present === true,
    markerPath: response.marker_path || GHOSTSCRIPT_MARKER,
    message,
    detail,
    logs: response.logs?.length ? response.logs : createUploadFallback(file, repaired).logs ?? [],
    syscalls: response.syscalls || createUploadFallback(file, repaired).syscalls || { ...GHOSTSCRIPT_BASELINE_SYSCALLS },
  };
}

type VuFindEvidenceView = {
  proxyFields: Array<{ label: string; value: string; tone: string }>;
  boundaries: Array<{ label: string; before: string; after: string }>;
  processChain: string[];
  insight: string;
  evidenceRows: MatrixEvidenceRow[];
};

type TimerHandle = ReturnType<typeof setTimeout>;
type WorkspaceView = 'flow' | 'location' | 'patch' | 'comparison';

const WORKSPACE_TABS: Array<{ id: WorkspaceView; label: string; detail: string }> = [
  { id: 'flow', label: '演示流程', detail: '完整过程' },
  { id: 'location', label: '漏洞定位', detail: '路径证据' },
  { id: 'patch', label: '修补解析', detail: '代码变化' },
  { id: 'comparison', label: '结果对比', detail: '前后验证' },
];

const PAGE_DEMO_DETAILS: Record<WorkspaceView, string> = {
  flow: '展示案例入口与章节结构',
  location: '单独呈现攻击与定位证据',
  patch: '逐步呈现代码与策略变化',
  comparison: '单独呈现修补前后结果',
};

const GHOSTSCRIPT_PRIMER_POINTS = Object.freeze([
  {
    label: '问题出在哪里',
    title: '文件扩展名不等于文件内容',
    text: '服务端看到的是 rce.jpg，但文件内部带有 EPS / PostScript 语义。Pillow 会按真实内容选择解析器，而不是只相信扩展名。',
  },
  {
    label: '为什么会执行命令',
    title: 'Pillow 把 EPS 交给 Ghostscript',
    text: 'Ghostscript 9.23 负责解释 EPS。恶意样本把 %pipe% 放进内容里，解释器被带到系统命令路径，最后执行 touch /tmp/got_rce。',
  },
  {
    label: '修补抓住了哪里',
    title: '解释器启动前检查输入',
    text: 'KINTSUGI 把防线放在 Ghostscript() 边界前：发现 %pipe% 就拒绝启动解释器；正常图片仍然走原来的业务处理流程。',
  },
]);

const GHOSTSCRIPT_FLOW_MAP = Object.freeze([
  { label: '上传', value: 'rce.jpg' },
  { label: '识别', value: 'EPS body' },
  { label: '调用', value: 'Ghostscript' },
  { label: '越界', value: '%pipe%' },
  { label: '证据', value: '/tmp/got_rce' },
]);

const GHOSTSCRIPT_RESULT_READINGS = Object.freeze([
  {
    label: '正常图片',
    title: 'HTTP 200 说明正常图片仍然能处理',
    text: '修补没有把上传功能直接关掉。正常 JPG 仍返回图片数据，说明业务路径还在。',
  },
  {
    label: '恶意样本',
    title: 'HTTP 500 不是服务崩溃',
    text: '这里的 500 是演示环境里抛出的拒绝结果。重点不是状态码好不好看，而是危险解释流程没有继续往下走。',
  },
  {
    label: '容器证据',
    title: 'marker 文件没有出现',
    text: '/tmp/got_rce 是攻击命令要创建的证据文件。它不存在，说明 touch 命令没有执行成功。',
  },
  {
    label: '系统调用',
    title: '关注额外命令，而非所有子进程',
    text: '正常 EPS 渲染也需要启动 Ghostscript。现有报告没有提供修补前后的 execve 实测计数，因此这里以输入拒绝和文件证据说明效果。',
  },
]);

const GHOSTSCRIPT_RESULT_METRICS = Object.freeze([
  {
    key: 'execve',
    label: '危险子进程',
    evidenceSource: '演示指数',
    before: 86,
    after: 6,
    headline: 'execve=5 · clone=3 → execve=0',
    note: '看的是是否出现额外 shell 子进程。修补后检查提前发生，恶意文件没有走到命令执行。',
  },
  {
    key: 'marker',
    label: '/tmp/got_rce',
    evidenceSource: '实测证据',
    before: 76,
    after: 6,
    headline: 'present → absent',
    note: '这是容器里的落地证据。文件出现说明命令执行过；修补后未出现，说明命令没有写入系统。',
  },
  {
    key: 'business',
    label: '正常业务',
    evidenceSource: 'Stage 10 实测',
    before: 58,
    after: 58,
    headline: 'normal_ok=true · HTTP 200 · 1653 bytes',
    note: '这项看业务是否被误伤，不做前后百分比。正常图片还能处理并返回内容，所以防护没有把上传入口关掉。',
  },
  {
    key: 'risk',
    label: '风险指数',
    evidenceSource: '演示指数',
    before: 86,
    after: 8,
    headline: '高风险路径 → 低风险残留',
    note: '这是讲解用的风险刻度，方便看变化趋势；最终结论仍以 Stage 10 表格为准。',
  },
]);

const GHOSTSCRIPT_PATCH_EXPLANATIONS = Object.freeze([
  { no: '143', step: 0, label: '修补入口', detail: '定位 Ghostscript 调用边界，在危险解释器启动前完成检查。' },
  { no: '144', step: 1, label: '读取原文', detail: '以二进制方式读取 EPS，避免编码转换掩盖危险操作符。' },
  { no: '145', step: 2, label: '识别载荷', detail: '%pipe% 是触发系统命令的危险操作符，命中即进入拒绝路径。' },
  { no: '146', step: 3, label: '提前阻断', detail: '抛出异常并终止处理，Ghostscript 子进程不会被创建。' },
  { no: '147', step: 0, label: '保留业务', detail: '未命中危险内容的正常图片继续沿原有渲染路径处理。' },
  { no: '148', step: 4, label: '受控执行', detail: '只有通过检查的输入才能调用原始 Ghostscript 命令。' },
]);

function PageDemoButton({
  view,
  status,
  activeChapter,
  onToggle,
}: {
  view: WorkspaceView;
  status: string;
  activeChapter: string | null;
  onToggle: (view: WorkspaceView) => void;
}) {
  const isRunning = status === 'playing' && activeChapter === view;
  const isComplete = status === 'complete' && activeChapter === view;
  const isPaused = status === 'paused' && activeChapter === view;

  return (
    <button
      type="button"
      className={`page-demo-button ${isRunning ? 'is-running' : ''}`}
      onClick={() => onToggle(view)}
      aria-pressed={isRunning}
    >
      <i aria-hidden="true">{isRunning ? 'Ⅱ' : '▶'}</i>
      <span>
        <strong>{isRunning ? '暂停本页' : isComplete ? '重新演示本页' : isPaused ? '继续演示本页' : '演示本页'}</strong>
        <small>{isRunning ? '停在当前画面' : PAGE_DEMO_DETAILS[view]}</small>
      </span>
    </button>
  );
}

export default function Home() {
  const [playback, setPlayback] = useState(() => createPlaybackState());
  const [comparisonRevision, setComparisonRevision] = useState(0);
  const [trafficRuns, setTrafficRuns] = useState<TrafficRun[] | null>(null);
  const [inspectionFile, setInspectionFile] = useState<File | null>(null);
  const [activeView, setActiveView] = useState<WorkspaceView>('flow');
  const [cactiMode, setCactiMode] = useState('normal');
  const [uploadVisual, setUploadVisual] = useState<UploadVisualState>(EMPTY_UPLOAD_VISUAL);
  const timers = useRef<TimerHandle[]>([]);
  const sequence = useRef(0);
  const uploadInput = useRef<HTMLInputElement | null>(null);
  const profile = CVE_PROFILES[playback.cve];
  const reportData = 'reportData' in profile ? profile.reportData as GhostscriptReportData : null;
  const cveOptions = useMemo(() => Object.keys(CVE_PROFILES), []);
  const playbackSnapshot = getPlaybackSnapshot(playback);
  const busy = playback.status === 'playing';
  const evidenceView = profile.evidenceView;
  const beforeVisible = playbackSnapshot.beforeVisible;
  const afterBlocked = playbackSnapshot.afterBlocked;
  const afterReady = playbackSnapshot.patchStep === 4 && !afterBlocked;
  const showPatch = playbackSnapshot.patchStep > 0;
  const currentView = activeView;
  const cactiActive = playback.cve === 'CVE-2022-46169' && (currentView === 'location' || currentView === 'comparison');
  const cactiPhase = playback.activeChapter === currentView ? Math.max(0, Math.min(4, playback.frame - (currentView === 'comparison' ? 8 : 0))) : 0;
  const cactiState = cactiSnapshot(cactiMode, cactiPhase);
  const patchLines = profile.patch.lines;
  const repairStatus = playbackSnapshot.patchStep === 4 ? 'repaired' : 'vulnerable';
  const manualComparison = Boolean(reportData && currentView === 'comparison' && trafficRuns?.some((run) => run.started));
  const sampleActive = Boolean(reportData && currentView === 'location' && uploadVisual.status !== 'idle');
  const activeRuns = trafficRuns?.filter((run) => run.started) ?? [];
  const manualStatus = activeRuns.some((run) => run.running) ? '演示中' : activeRuns.every((run) => run.phase === 4) ? '演示完成' : '已暂停';
  const manualSteps = activeRuns.reduce((total, run) => total + run.phase, 0);
  const comparisonPhase = playback.activeChapter === 'comparison' ? Math.max(0, Math.min(4, playback.frame - 8)) : 0;
  const displayLogs = cactiActive ? cactiState.logs : sampleActive ? uploadVisual.logs : manualComparison ? scenarios.flatMap((scenario, index) => {
    const run = trafficRuns![index];
    return run.started ? [ `[${scenario.title}] ${scenario.source} · 开始展示`, ...scenario.details.slice(0, run.phase).map((line, step) => `[${scenario.title} · ${step + 1}/4] ${line}`) ] : [];
  }) : playbackSnapshot.logs;
  const displayFinding = cactiActive ? cactiState.finding : sampleActive ? uploadVisual.detail : manualComparison ? activeRuns.some((run) => run.running) ? '按步骤展示处理中，可点击步骤或文件查看依据' : activeRuns.every((run) => run.phase === 4) ? '所选流量展示完成，可对照目录中的证据文件差异' : '演示已暂停，可继续播放或查看证据详情' : playbackSnapshot.currentFinding;
  const playbackLabel = sampleActive ? uploadVisual.status === 'uploading' ? '样本演示中' : uploadVisual.status === 'error' ? '无法展示' : '样本演示完成' : manualComparison ? manualStatus : playback.status === 'playing'
    ? '演示中'
    : playback.status === 'paused'
      ? '已暂停'
      : playback.status === 'complete'
        ? '演示完成'
        : '准备就绪';
  const playbackDetail = cactiActive ? `${cactiPhase} / 4 步 · 路径示意` : sampleActive ? `${uploadVisual.flowStep} / 4 步 · ${uploadVisual.fileName}` : manualComparison ? `${manualSteps} / ${activeRuns.length * 4} 步 · ${Math.round(manualSteps / (activeRuns.length * 4) * 100)}%` : `${playbackSnapshot.elapsedSeconds}s / ${playbackSnapshot.totalSeconds}s · ${playbackSnapshot.progress}%`;

  function cancelSequence() {
    sequence.current += 1;
    timers.current.forEach(clearTimeout);
    timers.current = [];
  }

  function wait(milliseconds: number) {
    return new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, milliseconds);
      timers.current.push(timer);
    });
  }

  useEffect(() => () => cancelSequence(), []);

  useEffect(() => {
    if (playback.status !== 'playing') return undefined;
    const timer = window.setTimeout(() => {
      setPlayback((state) => transitionPlayback(state, { type: 'TICK' }));
    }, 900 / playback.speed);
    return () => window.clearTimeout(timer);
  }, [playback.status, playback.frame, playback.speed]);

  const trafficRunning = Boolean(trafficRuns?.some((run) => run.running));
  useEffect(() => {
    if (!trafficRunning || activeView !== 'comparison') return;
    const timer = window.setInterval(() => setTrafficRuns((current) => current?.map((run) => run.running
      ? { ...run, phase: Math.min(4, run.phase + 1), running: run.phase + 1 < 4 }
      : run) ?? null), 1100 / playback.speed);
    return () => window.clearInterval(timer);
  }, [trafficRunning, activeView, playback.speed]);

  function pauseTraffic() {
    setPlayback((state) => transitionPlayback(state, { type: 'PAUSE' }));
    setTrafficRuns((runs) => runs?.map((run) => ({ ...run, running: false })) ?? null);
  }

  function toggleTraffic(index: number) {
    setPlayback((state) => transitionPlayback(state, { type: 'PAUSE' }));
    const wholePlaying = playback.status === 'playing' && playback.activeChapter === 'comparison';
    setTrafficRuns((current) => (current ?? scenarios.map(() => ({ phase: comparisonPhase, running: wholePlaying, started: wholePlaying }))).map((run, position) => {
      if (position !== index) return run;
      return run.running ? { ...run, running: false } : { phase: run.phase >= 4 ? 0 : run.phase, running: true, started: true };
    }));
  }

  function seekCacti(step: number, mode = cactiMode) {
    setCactiMode(mode);
    const start = currentView === 'comparison' ? 8 : 0;
    setPlayback((state) => ({ ...state, status: step === 4 ? 'complete' : step === 0 ? 'idle' : 'paused',
      frame: start + step, activeChapter: currentView, segmentStart: start, segmentEnd: start + 4 }));
  }

  function handlePageDemo(view: WorkspaceView) {
    cancelSequence();
    const resuming = !trafficRuns && playback.status === 'paused' && playback.activeChapter === view;
    if ((view === 'comparison' || view === 'patch') && playback.status !== 'playing' && !resuming) setComparisonRevision((value) => value + 1);
    const wasManual = Boolean(trafficRuns);
    setTrafficRuns(null);
    setActiveView(view);
    setPlayback((state) => transitionPlayback(
      wasManual ? { ...state, status: 'idle' } : state,
      state.status === 'playing' && state.activeChapter === view
        ? { type: 'PAUSE' }
        : { type: 'PLAY_CHAPTER', chapter: view },
    ));
  }

  function selectWorkspaceView(view: WorkspaceView) {
    cancelSequence();
    setTrafficRuns((runs) => runs?.map((run) => ({ ...run, running: false })) ?? null);
    setActiveView(view);
    setPlayback((state) => state.status === 'playing' ? transitionPlayback(state, { type: 'PAUSE' }) : state);
  }

  function restartPlayback() {
    cancelSequence();
    setTrafficRuns(null);
    setInspectionFile(null);
    setComparisonRevision((value) => value + 1);
    setCactiMode('normal');
    setUploadVisual(EMPTY_UPLOAD_VISUAL);
    setActiveView('flow');
    setPlayback((state) => transitionPlayback(state, { type: 'RESTART' }));
  }

  async function runGhostscriptUpload(file: File, scenarioRepaired?: boolean) {
    if (playback.cve !== 'CVE-2018-16509') return;
    const repairedBeforeUpload = scenarioRepaired ?? (repairStatus === 'repaired');
    selectWorkspaceView('location');
    const currentSequence = sequence.current;
    setInspectionFile(file);
    let identity;
    try { identity = await inspectFile(file); }
    catch {
      if (currentSequence === sequence.current) setUploadVisual({ ...EMPTY_UPLOAD_VISUAL, status: 'error', message: '文件读取失败', detail: '请重新选择可读取的本地文件。' });
      return;
    }
    if (currentSequence !== sequence.current) return;
    if (!identity.known) {
      setUploadVisual({ ...EMPTY_UPLOAD_VISUAL, status: 'error', fileName: file.name, fileSize: formatUploadSize(file.size), message: '此文件无法匹配演示路径', detail: '未识别图片格式，或 EPS 超出读取范围；请使用预置样本。' });
      return;
    }
    const likelyAttack = identity.classification === 'malicious';
    setUploadVisual({
      ...EMPTY_UPLOAD_VISUAL,
      status: 'uploading',
      flowStep: 1,
      fileName: file.name,
      fileFormat: identity.format,
      repaired: repairedBeforeUpload,
      fileSize: formatUploadSize(file.size),
      classification: likelyAttack ? 'malicious' : 'normal',
      message: `正在处理 ${file.name}`,
      detail: repairedBeforeUpload ? '修补后数据已加载，上传区会展示拦截结果。' : '文件进入图片处理链路，四步路径会逐段亮起。',
      logs: [`[demo] Processing ${file.name}...`],
    });

    for (let step = 2; step <= GHOSTSCRIPT_FLOW_STEPS.length; step += 1) {
      await wait(1000 / playback.speed);
      if (currentSequence !== sequence.current) return;
      setUploadVisual((state) => state.status === 'uploading' ? { ...state, flowStep: step } : state);
    }

    if (currentSequence !== sequence.current) return;
    const visual = normalizeUploadVisual(file, createUploadFallback(file, repairedBeforeUpload, likelyAttack), repairedBeforeUpload);
    setUploadVisual({ ...visual, fileFormat: identity.format, repaired: repairedBeforeUpload });
  }

  function handleGhostscriptDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const file = event.dataTransfer.files?.[0];
    if (file) void runGhostscriptUpload(file);
  }

  function handleGhostscriptFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file) void runGhostscriptUpload(file);
  }

  function selectCve(cve: string) {
    cancelSequence();
    setTrafficRuns(null);
    setInspectionFile(null);
    setCactiMode('normal');
    setUploadVisual(EMPTY_UPLOAD_VISUAL);
    setActiveView('flow');
    setPlayback((state) => transitionPlayback(state, { type: 'SELECT_CVE', cve }));
  }

  return (
    <main className="app-shell">
      <header className="workspace-header">
        <div className="header-frame">
          <div className="global-bar">
            <a className="wordmark" href="#top" aria-label="KINTSUGI 演示首页">
              <span className="wordmark-symbol">K</span>
              <span><strong>KINTSUGI</strong><small>漏洞拦截实验台</small></span>
            </a>

            <nav className="case-switcher" aria-label="案例切换">
              {cveOptions.map((cve, index) => (
                <button
                  type="button"
                  className={playback.cve === cve ? 'is-active' : ''}
                  onClick={() => selectCve(cve)}
                  disabled={busy}
                  aria-current={playback.cve === cve ? 'page' : undefined}
                  key={cve}
                >
                  <span>0{index + 1}</span>
                  <strong>{cve}</strong>
                </button>
              ))}
            </nav>

            <div className="header-data-ready">
              <i />
              <span>演示数据已加载</span>
            </div>
          </div>

          <div className="workspace-hero" id="top">
            <div className="hero-copy">
              <div className="hero-title-row">
                <p>{playback.cve}</p>
                <span>{profile.language}</span>
                <span>{profile.product}</span>
                <em>{profile.severity}</em>
              </div>
              <h1>{profile.headline}</h1>
              <p className="hero-summary">{profile.summary}</p>
              <div className="hero-endpoint"><span>TARGET</span><code>{profile.port}{profile.endpoint}</code></div>
            </div>

            <div className="hero-command">
              <div className={`compact-status ${busy ? 'status-working' : 'status-safe'}`} aria-live="polite">
                <span>当前页状态</span><strong>{playbackLabel}</strong><small>{playbackDetail}</small>
              </div>
              <div className="header-actions">
                <button className="header-action action-reset" onClick={restartPlayback} aria-label="重置案例演示">
                  <span>重置状态</span><small>清空当前结果</small>
                </button>
                <div className="playback-speed" aria-label="播放速度">
                  <span>速度</span>
                  <div>
                    {PLAYBACK_SPEEDS.map((speed) => (
                      <button
                        type="button"
                        className={playback.speed === speed ? 'is-active' : ''}
                        onClick={() => setPlayback((state) => transitionPlayback(state, { type: 'SET_SPEED', speed }))}
                        key={speed}
                      >
                        {speed}x
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <nav className="workspace-tabs" aria-label="案例工作区导航">
            {WORKSPACE_TABS.map((tab) => (
              <button
                type="button"
                className={currentView === tab.id ? 'is-active' : ''}
                onClick={() => selectWorkspaceView(tab.id)}
                aria-selected={currentView === tab.id}
                role="tab"
                key={tab.id}
              >
                <span>{tab.label}</span><small>{tab.detail}</small>
              </button>
            ))}
          </nav>
        </div>
      </header>

      <div className="page workspace-stage">
        <section className="workspace-panel overview-panel" hidden={currentView !== 'flow'}>
          <div className="workspace-panel-heading">
            <div><strong>案例概览</strong></div>
            <PageDemoButton view="flow" status={playback.status} activeChapter={playback.activeChapter} onToggle={handlePageDemo} />
          </div>
          <div className="overview-grid">
            <div className="overview-card overview-next">
              <span>PLAYBACK · {String(playbackSnapshot.frame).padStart(2, '0')} / 12</span>
              <strong>{playbackSnapshot.currentFinding}</strong>
              <p>页眉负责选择案例和控制演示，主屏按章节同步展示证据、代码和前后结果。</p>
            </div>
            <div className="overview-card"><span>目标应用</span><strong>{profile.product}</strong><code>{profile.port}</code></div>
            <div className="overview-card"><span>漏洞类型</span><strong>{profile.category}</strong><code>{profile.targetFunction}</code></div>
            <div className="overview-card"><span>关键危险行为</span><strong>{profile.dangerCall}</strong><code>{profile.endpoint}</code></div>
          </div>

          {playback.cve === 'CVE-2018-16509' ? (
            <section className="ghostscript-primer" aria-label="CVE-2018-16509 漏洞原理速读">
              <div className="primer-copy">
                <div className="primer-heading">
                  <strong>漏洞原理速读</strong>
                  <p>
                    这个漏洞的关键不是“图片坏了”，而是“看起来像图片的文件进入了解释器”。
                    一旦 EPS 内容被 Ghostscript 解释，文件里的危险语义就可能变成系统命令。
                  </p>
                </div>
                <div className="primer-points">
                  {GHOSTSCRIPT_PRIMER_POINTS.map((point) => (
                    <article className="primer-point" key={point.title}>
                      <span>{point.label}</span>
                      <strong>{point.title}</strong>
                      <p>{point.text}</p>
                    </article>
                  ))}
                </div>
              </div>

              <div className="primer-flow-map" aria-label="CVE-2018-16509 攻击路径图">
                <div className="flow-map-title">
                  <strong>从上传到命令执行</strong>
                </div>
                <div className="flow-map-lane">
                  {GHOSTSCRIPT_FLOW_MAP.map((node, index) => (
                    <div className={`flow-map-node ${index >= 3 ? 'is-danger' : ''}`} key={node.label}>
                      <small>{node.label}</small>
                      <strong>{node.value}</strong>
                      {index < GHOSTSCRIPT_FLOW_MAP.length - 1 ? <i aria-hidden="true">→</i> : null}
                    </div>
                  ))}
                </div>
                <div className="flow-map-guard">
                  <span>KINTSUGI guard</span>
                  <strong>在 Ghostscript 启动前检查输入</strong>
                  <p>命中 %pipe% 时直接拒绝，攻击链停在解释器外面，/tmp/got_rce 不会出现。</p>
                </div>
              </div>
            </section>
          ) : null}

          <section className="playback-overview" aria-label="演示章节">
            {PLAYBACK_CHAPTERS.map((chapter, index) => {
              const active = playbackSnapshot.chapter === chapter.id;
              const complete = playbackSnapshot.frame > (index + 1) * 3;
              return (
                <button
                  type="button"
                  className={`playback-chapter ${active ? 'is-active' : ''} ${complete ? 'is-complete' : ''}`}
                  onClick={() => selectWorkspaceView(chapter.id as WorkspaceView)}
                  key={chapter.id}
                >
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <strong>{chapter.label}</strong>
                  <small>{chapter.detail}</small>
                </button>
              );
            })}
          </section>
          <div className="playback-progress" aria-label={`演示进度 ${playbackSnapshot.progress}%`}>
            <span style={{ width: `${playbackSnapshot.progress}%` }} />
          </div>
        </section>

        <section className="workspace-panel" hidden={currentView !== 'location'}>
          <section className={`case-anatomy panel anatomy-${evidenceView.kind}`}>
            <div className="anatomy-heading">
              <div>
                <p>{evidenceView.eyebrow}</p>
                <h2>{evidenceView.title}</h2>
              </div>
              <div className="anatomy-heading-actions">
                <span>{playback.cve} / ATTACK ANATOMY</span>
                <PageDemoButton view="location" status={playback.status} activeChapter={playback.activeChapter} onToggle={handlePageDemo} />
              </div>
            </div>

            {evidenceView.kind === 'command' && evidenceView.requestFields ? (
              <CactiLab mode={cactiMode} phase={cactiPhase} onMode={(mode) => seekCacti(0, mode)} onStep={seekCacti} />
            ) : evidenceView.kind === 'file' && evidenceView.uploadFields ? (
              <GhostscriptEvidencePanel
                inspectionFile={inspectionFile}
                onSelectSample={(file, repaired) => void runGhostscriptUpload(file, repaired)}
                view={evidenceView}
                reportData={reportData as GhostscriptReportData}
                uploadVisual={uploadVisual}
                uploadDisabled={uploadVisual.status === 'uploading'}
                repairStatus={repairStatus}
                onDrop={handleGhostscriptDrop}
                onFileChange={handleGhostscriptFileChange}
                onChooseFile={() => uploadInput.current?.click()}
                inputRef={uploadInput}
              />
            ) : evidenceView.kind === 'network' && evidenceView.proxyFields ? (
              <VuFindEvidencePanel
                view={evidenceView}
                beforeVisible={beforeVisible}
                afterReady={afterReady}
                afterBlocked={afterBlocked}
              />
            ) : (
              <div className="anatomy-body">
                <div className="specimen-card">
                  <div className="specimen-copy">
                    <span>{evidenceView.specimen.label}</span>
                    <code>{evidenceView.specimen.value}</code>
                    <p>{evidenceView.specimen.meta}</p>
                  </div>

                  {evidenceView.kind === 'file' ? (
                    <div className="case-glyph glyph-file" aria-label="伪装图片包含 EPS 载荷">
                      <div className="file-sheet"><span>JPG</span><strong>EPS</strong></div>
                      <i>mismatch</i>
                    </div>
                  ) : (
                    <div className="case-glyph glyph-network" aria-label="服务端请求进入内网">
                      <span>WEB</span><i>→</i><span>APP</span><i>→</i><strong>3306</strong>
                    </div>
                  )}
                </div>

                <div className="attack-chain" aria-label="攻击路径">
                  {evidenceView.steps.map((step, index) => (
                    <div className="chain-step" key={step.label}>
                      <span>{String(index + 1).padStart(2, '0')}</span>
                      <div><small>{step.label}</small><strong>{step.value}</strong></div>
                      {index < evidenceView.steps.length - 1 ? <i>→</i> : null}
                    </div>
                  ))}
                </div>

                <div className="case-facts">
                  {evidenceView.facts.map((fact) => (
                    <div key={fact.label}><span>{fact.label}</span><strong>{fact.value}</strong></div>
                  ))}
                </div>

                <div className="signal-compare">
                  <div className={beforeVisible ? 'signal-before is-visible' : 'signal-before'}>
                    <span>修补前信号</span><strong>{beforeVisible ? evidenceView.beforeSignal : 'waiting · baseline'}</strong>
                  </div>
                  <i>→</i>
                  <div className={afterBlocked ? 'signal-after is-visible' : 'signal-after'}>
                    <span>修补后信号</span><strong>{afterBlocked ? evidenceView.afterSignal : 'waiting · replay'}</strong>
                  </div>
                </div>
              </div>
            )}
          </section>
        </section>

        <section className="workbench workbench-tabbed workspace-panel" hidden={currentView !== 'comparison' && currentView !== 'patch'}>
          <article className="comparison-panel panel" hidden={currentView !== 'comparison'}>
            <div className="panel-heading">
              <div><p>攻击效果</p><h2>{reportData || playback.cve === 'CVE-2022-46169' ? '三种流量，同屏看结果' : '同一请求，修补前后'}</h2></div>
              <div className="panel-heading-actions">
                <PageDemoButton view="comparison" status={trafficRuns ? 'idle' : playback.status} activeChapter={trafficRuns ? null : playback.activeChapter} onToggle={handlePageDemo} />
              </div>
            </div>
            {reportData ? (
              <TrafficComparison
                key={`${playback.cve}-${comparisonRevision}`}
                phase={comparisonPhase}
                runs={trafficRuns}
                playing={playback.status === 'playing' && playback.activeChapter === 'comparison'}
                onToggle={toggleTraffic}
                onInspect={pauseTraffic}
              />
            ) : playback.cve === 'CVE-2022-46169' ? (
              <CactiLab comparison mode={cactiMode} phase={cactiPhase} onMode={setCactiMode} onStep={seekCacti} />
            ) : (<>
            <div className="effect-grid">
              <section className={`effect-card effect-before ${beforeVisible ? 'has-result' : ''}`}>
                <div className="effect-label"><span>修补前</span><em>BEFORE</em></div>
                <div className="browser-frame">
                  <div className="browser-top"><i /><i /><i /><code>{profile.port}</code></div>
                  <div className="request-row"><span>REQUEST</span><code>{profile.endpoint}</code></div>
                  {beforeVisible ? (
                    <div className="verdict verdict-danger">
                      <span className="verdict-mark">×</span>
                      <div><small>演示结果</small><strong>攻击成功</strong><p>{profile.evidence}</p></div>
                    </div>
                  ) : (
                    <div className="verdict verdict-empty"><span>—</span><div><small>尚无证据</small><strong>等待首次攻击</strong><p>播放到漏洞定位后在此保留修补前结果。</p></div></div>
                  )}
                </div>
                <div className="evidence-line"><span>危险行为</span><strong>{beforeVisible ? profile.dangerCall : '等待验证'}</strong></div>
                <div className="effect-facts">
                  <div><span>攻击证据</span><p>{beforeVisible ? '命令路径被触发，目标是创建 /tmp/got_rce。' : '先播放漏洞定位片段，保留修补前结果。'}</p></div>
                  <div><span>风险含义</span><p>{beforeVisible ? '上传接口没有直接执行命令，但解析器被恶意内容带到了系统调用边界。' : '等待基线样本进入解析链路。'}</p></div>
                </div>
              </section>

              <section className={`effect-card effect-after ${afterBlocked ? 'has-result' : ''}`}>
                <div className="effect-label"><span>修补后</span><em>AFTER</em></div>
                <div className="browser-frame">
                  <div className="browser-top"><i /><i /><i /><code>{profile.port}</code></div>
                  <div className="request-row"><span>SAME REQUEST</span><code>{profile.endpoint}</code></div>
                  {afterBlocked ? (
                    <div className="verdict verdict-safe">
                      <span className="verdict-mark">✓</span>
                      <div><small>演示结果</small><strong>攻击已拦截</strong><p>{profile.blockedEvidence}</p></div>
                    </div>
                  ) : afterReady ? (
                    <div className="verdict verdict-ready"><span>✓</span><div><small>策略已生效</small><strong>等待结果对比片段</strong><p>继续播放后展示相同输入的拦截结果。</p></div></div>
                  ) : (
                    <div className="verdict verdict-empty"><span>—</span><div><small>尚无结果</small><strong>等待完成修补</strong><p>修补解析出现后使用完全相同的请求验证。</p></div></div>
                  )}
                </div>
                <div className={`evidence-line ${playbackSnapshot.normalVerified ? 'evidence-safe' : ''}`}>
                  <span>正常业务</span><strong>{playbackSnapshot.normalVerified ? profile.normalEvidence : '等待验证'}</strong>
                </div>
                <div className="effect-facts">
                  <div><span>防护位置</span><p>{afterBlocked ? '检查发生在 Ghostscript 启动前，危险内容没有机会进入解释器。' : '完成修补解析后，再看相同样本的结果。'}</p></div>
                  <div><span>业务影响</span><p>{playbackSnapshot.normalVerified ? '正常业务没有被误伤，正常图片仍然返回有效响应。' : '等待正常图片验证结果。'}</p></div>
                </div>
              </section>
            </div>
            <section className="visual-result-dashboard" aria-label="修补前后视觉结论看板">
              <div className="result-verdict-strip">
                <div>
                  <span>一眼看结论</span>
                  <strong>{afterBlocked ? '危险命令被截断，正常图片照常处理' : beforeVisible ? '修补前已复现危险命令路径' : '等待演示数据进入结果页'}</strong>
                </div>
                <p>
                  {afterBlocked
                    ? '同一个 rce.jpg 复测后没有创建 /tmp/got_rce，execve 归零；normal.jpg 仍返回 HTTP 200。'
                    : beforeVisible
                      ? '恶意样本把 Ghostscript 带到系统命令边界，下一步看修补如何把这条路堵住。'
                      : '播放本页演示后，这里会用图表把攻击面、系统调用和业务结果放在一起。'}
                </p>
                <div className="verdict-tags" aria-label="结果摘要标签">
                  <span>危险命令：从可执行到不可执行</span>
                  <span>业务链路：正常图片继续通过</span>
                </div>
              </div>

              <div className="attack-surface-map" aria-label="攻击路径与阻断点">
                <div className={`surface-node ${beforeVisible ? 'is-danger' : ''}`}>
                  <span>01</span>
                  <strong>上传 rce.jpg</strong>
                  <p>伪装成图片进入业务入口</p>
                </div>
                <i />
                <div className={`surface-node ${beforeVisible ? 'is-danger' : ''}`}>
                  <span>02</span>
                  <strong>进入 Ghostscript</strong>
                  <p>%pipe% 触发危险解释路径</p>
                </div>
                <i />
                <div className={`surface-node ${afterBlocked ? 'is-safe' : beforeVisible ? 'is-danger' : ''}`}>
                  <span>03</span>
                  <strong>{afterBlocked ? '策略提前拦截' : '执行系统命令'}</strong>
                  <p>{afterBlocked ? '解释器启动前拒绝危险内容' : '目标是 touch /tmp/got_rce'}</p>
                </div>
              </div>

              <div className="metric-bar-chart" aria-label="修补前后关键指标柱状图">
                <div className="chart-heading">
                  <span>BEFORE / AFTER</span>
                  <strong>关键指标对比</strong>
                </div>
                {GHOSTSCRIPT_RESULT_METRICS.map((metric) => {
                  const beforeHeight = Math.max(metric.before, 4);
                  const afterHeight = Math.max(metric.after, 4);
                  return (
                    <div className={`comparison-metric metric-${metric.key}`} key={metric.key}>
                      <div className="metric-title">
                        <strong>{metric.label}</strong>
                        <em className="metric-source-badge">{metric.evidenceSource}</em>
                        <span className="metric-primary-line">{metric.headline}</span>
                      </div>
                      <div className="metric-bars">
                        <div className="metric-column is-before">
                          <i style={{ height: `${beforeHeight}%` }} />
                          <em>修补前</em>
                        </div>
                        <div className="metric-column is-after">
                          <i style={{ height: `${afterHeight}%` }} />
                          <em>修补后</em>
                        </div>
                      </div>
                      <p className="metric-evidence-note">{metric.note}</p>
                    </div>
                  );
                })}
              </div>
            </section>
            </>)}
            {reportData ? (
              <div className="comparison-validation-grid">
                <section className="validation-matrix" aria-label="Stage 10 实测结果">
                  <div className="validation-heading">
                    <div><span>STAGE 10 · MEASURED</span><strong>Stage 10 实测结果</strong></div>
                    <em>{reportData.validation.durationSeconds.toFixed(2)} s</em>
                  </div>
                  <div className="validation-row validation-normal">
                    <span>正常图片</span>
                    <strong>HTTP {reportData.validation.normal.status}</strong>
                    <code>{reportData.validation.normal.responseBytes} bytes · normal_ok={String(reportData.validation.normal.ok)}</code>
                  </div>
                  <div className="validation-row validation-malicious">
                    <span>恶意 EPS</span>
                    <strong>HTTP {reportData.validation.malicious.status}</strong>
                    <code>{reportData.validation.malicious.markerPath} · {reportData.validation.malicious.markerPresent ? 'present' : 'absent'}</code>
                  </div>
                  <div className="validation-row validation-success">
                    <span>最终结论</span>
                    <strong>success={String(reportData.validation.success)}</strong>
                    <code>normal_ok=true · malicious_blocked=true</code>
                  </div>
                </section>

                <aside className="result-reading-panel" aria-label="实测结果含义说明">
                  <div className="result-reading-heading">
                    <span>READING</span>
                    <strong>实测结果怎么读</strong>
                  </div>
                  {GHOSTSCRIPT_RESULT_READINGS.map((item) => (
                    <article className="result-reading-item" key={item.title}>
                      <span>{item.label}</span>
                      <strong>{item.title}</strong>
                      <p>{item.text}</p>
                    </article>
                  ))}
                </aside>
              </div>
            ) : null}
          </article>

          <article className="code-panel panel" hidden={currentView !== 'patch'}>
            <div className="panel-heading">
              <div><p>修补解析</p><h2>策略注入示意</h2></div>
              <div className="panel-heading-actions">
                <span className={`patch-state ${showPatch ? 'patch-applied' : ''}`}>
                  {showPatch ? `已加载 ${playbackSnapshot.patchStep}/4` : '等待修补解析'}
                </span>
                <PageDemoButton view="patch" status={playback.status} activeChapter={playback.activeChapter} onToggle={handlePageDemo} />
              </div>
            </div>
            {reportData ? <PatchLab key={`${playback.cve}-${comparisonRevision}`} frame={playbackSnapshot.patchStep} playing={playback.status === 'playing'} onPause={() => setPlayback((state) => transitionPlayback(state, { type: 'PAUSE' }))} /> : <div className={`patch-code-layout ${reportData ? 'has-analysis' : ''}`}>
              <div className="patch-code-column">
                <div className="file-tab">
                  <span>{profile.patch.source}</span>
                  <em>POLICY</em>
                </div>
                <div className="code-editor" aria-live="polite">
                  {patchLines.map((line, index) => {
                    const hidden = line.kind === 'add' && (!line.step || playbackSnapshot.patchStep < line.step);
                    const removed = line.kind === 'remove' && showPatch;
                    return (
                      <div className={`code-line code-${line.kind} ${hidden ? 'line-hidden' : ''} ${removed ? 'line-removed' : ''}`} key={`${line.no}-${index}`}>
                        <span className="change-mark">{line.kind === 'add' ? '+' : line.kind === 'remove' ? '−' : ' '}</span>
                        <span className="line-no">{line.no}</span>
                        <code>{line.code}</code>
                      </div>
                    );
                  })}
                </div>
              </div>
              {reportData ? (
                <aside className="patch-analysis-column" aria-label="Ghostscript 修补代码逐行解析">
                  <div className="analysis-tab">
                    <span>逐行解析</span>
                    <em>WHY IT WORKS</em>
                  </div>
                  <div className="code-analysis-track">
                    {GHOSTSCRIPT_PATCH_EXPLANATIONS.map((item) => {
                      const hidden = item.step > 0 && playbackSnapshot.patchStep < item.step;
                      const active = item.step > 0 && playbackSnapshot.patchStep === item.step;
                      return (
                        <div className={`code-analysis-row ${hidden ? 'line-hidden' : ''} ${active ? 'is-active' : ''}`} key={item.no}>
                          <span>{item.label}</span>
                          <p>{item.detail}</p>
                        </div>
                      );
                    })}
                  </div>
                </aside>
              ) : null}
            </div>
            }
            <div className="code-summary">
              <div><span>定位函数</span><strong>{profile.targetFunction}</strong></div>
              <div><span>当前展示</span><strong>{reportData ? '最终验证逻辑修复' : '运行时白名单策略'}</strong></div>
            </div>
            {reportData ? (
              <details className="policy-whitelist" aria-label="Stage 9 syscall 白名单">
                <summary>查看白名单与实现依据 · Stage 9 / Stage 10</summary>
                <div className="policy-heading">
                  <div><span>STAGE 9 · GENERATED POLICY</span><strong>正常行为白名单</strong></div>
                  <em>{reportData.whitelist.normalSamples} samples · {reportData.whitelist.extractedSyscalls.toLocaleString()} syscalls</em>
                </div>
                <div className="syscall-whitelist" aria-label="10 类 syscall">
                  {reportData.whitelist.syscalls.map((syscall) => <code key={syscall}>{syscall}</code>)}
                </div>
                <div className="execve-policy">
                  <div className="policy-allow">
                    <span>execve 仅允许</span>
                    {reportData.whitelist.execveAllowedPaths.map((path) => <code key={path}>{path}</code>)}
                  </div>
                  <div className="policy-deny">
                    <span>额外命令不允许</span>
                    {reportData.whitelist.deniedExamples.map((command) => <code key={command}>{command}</code>)}
                  </div>
                </div>
                <section className="repair-explainer-grid" aria-label="Ghostscript 修补实现说明与流程图">
                  <article className="repair-implementation-note">
                    <div className="implementation-heading">
                      <span>实现说明</span>
                      <strong>为什么要在 Ghostscript 启动之前阻断</strong>
                    </div>
                    <p>
                      漏洞真正跨越安全边界的时刻，是 Pillow 把 EPS 内容交给 <code>{reportData.generatedRepair.protectedCall}</code>，
                      并通过子进程启动 Ghostscript。修补因此放在调用边界之前：先读取 EPS 原始字节，再判断是否包含能够调用系统命令的 <code>%pipe%</code> 操作符。
                    </p>
                    <div className="implementation-facts">
                      <div>
                        <span>自动生成策略</span>
                        <p>Stage 8–9 从 {reportData.whitelist.normalSamples} 个正常样本、{reportData.whitelist.extractedSyscalls.toLocaleString()} 次 syscall 中生成 10 类白名单，并把 <code>execve</code> 限制到正常 Ghostscript 路径。</p>
                      </div>
                      <div>
                        <span>本机验证实现</span>
                        <p>当前 WSL2 内核缺少可用的 BPF LSM 挂载能力，内核级策略无法稳定加载，因此最终演示采用启动前输入检查，保持验证过程可重复。</p>
                      </div>
                      <div>
                        <span>业务与安全结果</span>
                        <p>正常图片仍进入原有渲染流程；恶意 EPS 在创建 Ghostscript 子进程前返回错误，<code>{reportData.validation.malicious.markerPath}</code> 不会出现。</p>
                      </div>
                    </div>
                    <div className="implementation-guard">
                      <span>最终验证防线</span>
                      <code>{reportData.validatedRepair.guard}</code>
                    </div>
                  </article>

                  <aside className="repair-flowchart" aria-label="EPS 输入检查和 Ghostscript 分支流程图">
                    <div className="flowchart-heading">
                      <span>REPAIR FLOW</span>
                      <strong>输入如何被分流</strong>
                    </div>
                    <div className="flowchart-sequence">
                      <div className="flowchart-node is-reached"><span>01</span><strong>接收上传文件</strong><small>multipart image</small></div>
                      <i aria-hidden="true">→</i>
                      <div className={`flowchart-node ${playbackSnapshot.patchStep >= 1 ? 'is-reached' : ''}`}><span>02</span><strong>读取 EPS 原始字节</strong><small>binary content</small></div>
                      <i aria-hidden="true">→</i>
                      <div className={`flowchart-node node-decision ${playbackSnapshot.patchStep >= 2 ? 'is-reached' : ''}`}><span>03</span><strong>包含 %pipe%？</strong><small>policy decision</small></div>
                    </div>
                    <div className="flowchart-connector"><span>是 / DANGER</span><span>否 / SAFE</span></div>
                    <div className="flowchart-branch">
                      <div className={`flowchart-outcome outcome-danger ${playbackSnapshot.patchStep >= 3 ? 'is-reached' : ''}`}>
                        <span>BLOCK</span>
                        <strong>恶意样本提前拒绝</strong>
                        <p>抛出 IOError · 不创建 gs 子进程</p>
                        <code>/tmp/got_rce · absent</code>
                      </div>
                      <div className={`flowchart-outcome outcome-safe ${playbackSnapshot.patchStep >= 4 ? 'is-reached' : ''}`}>
                        <span>ALLOW</span>
                        <strong>正常图片继续渲染</strong>
                        <p>调用受控 Ghostscript 命令</p>
                        <code>HTTP 200 · {reportData.validation.normal.responseBytes} bytes</code>
                      </div>
                    </div>
                    <div className="flowchart-caption">
                      <span>阻断点</span>
                      <p>危险内容不会到达 <code>subprocess.check_call()</code>，因此系统命令没有执行机会。</p>
                    </div>
                  </aside>
                </section>
              </details>
            ) : null}
          </article>
        </section>

        <section className="console panel playback-terminal">
          <div className="console-heading"><span>{cactiActive ? '步骤说明 · 路径示意' : '同步终端输出'}</span><em>{playbackLabel}</em></div>
          <div className="console-lines">
            {displayLogs.length ? displayLogs.map((line: string, index: number) => (
              <div className="console-line" key={`${line}-${index}`}>
                <time>{manualComparison || cactiActive ? `步骤 ${index + 1}` : `00:${String(index + 1).padStart(2, '0')}`}</time><span>{line}</span>
              </div>
            )) : <p>点击当前页面的“演示本页”后，运行轨迹会随该页片段同步呈现。</p>}
          </div>
          <div className="console-finding">
            <span>关键发现</span><strong>{displayFinding}</strong>
          </div>
        </section>

        <footer className="footnote">
          <p>界面加载案例数据，并按固定时间轴同步展示漏洞位置、代码修改、运行轨迹和前后验证结果。</p>
          <span>KINTSUGI / CASE INTERFACE</span>
        </footer>
      </div>
    </main>
  );
}

function GhostscriptEvidencePanel({
  inspectionFile,
  onSelectSample,
  view,
  reportData,
  uploadVisual,
  uploadDisabled,
  repairStatus,
  onDrop,
  onFileChange,
  onChooseFile,
  inputRef,
}: {
  inspectionFile: File | null;
  onSelectSample: (file: File, repaired?: boolean) => void;
  view: GhostscriptEvidenceView;
  reportData: GhostscriptReportData;
  uploadVisual: UploadVisualState;
  uploadDisabled: boolean;
  repairStatus: string;
  onDrop: (event: DragEvent<HTMLDivElement>) => void;
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onChooseFile: () => void;
  inputRef: RefObject<HTMLInputElement | null>;
}) {
  const repaired = uploadVisual.repaired ?? (repairStatus === 'repaired');
  const activeStep = uploadVisual.status === 'normal' ? 2 : uploadVisual.status === 'breached' ? 3 : repaired ? 4 : 1;
  const statusIcon = uploadVisual.status === 'breached' ? '!' : uploadVisual.status === 'blocked' ? 'shield' : uploadVisual.status === 'normal' ? 'ok' : uploadVisual.status === 'uploading' ? '...' : 'idle';
  const laneKey = uploadVisual.status === 'blocked' ? 'repaired' : uploadVisual.classification === 'malicious' ? 'attack' : 'normal';

  return (
    <div className={`ghostscript-arena evidence-workspace arena-${uploadVisual.status}`} aria-label="CVE-2018-16509 上传即见交互演示">
      <section className="upload-battlefield" onDrop={onDrop} onDragOver={(event) => event.preventDefault()}>
        <div className="battlefield-title">
          <div>
            <p>{view.insight}</p>
            <h3>CVE-2018-16509 · 沙箱绕过 · 交互演示</h3>
          </div>
          {repaired ? <span className="defense-badge">修补后数据已加载</span> : <span className="defense-badge badge-muted">修补前样本</span>}
        </div>

        <div
          className={`drop-zone ${uploadDisabled ? 'is-disabled' : ''}`}
          aria-label="拖拽或选择图片文件"
        >
          <input ref={inputRef} type="file" accept=".jpg,.jpeg,.png,.gif,.bmp,.eps" onChange={onFileChange} hidden />
          <div className="drop-copy">
            <span>DRAG & DROP</span>
            <strong>{uploadVisual.fileName || '上传 normal.jpg 或 rce.jpg'}</strong>
            <p>{uploadVisual.fileName ? `${uploadVisual.fileSize} · ${uploadVisual.classification === 'malicious' ? '攻击流量' : '正常业务流量'}` : '选择样本，查看文件内容如何影响处理路径。'}</p>
          </div>
          <button type="button" onClick={onChooseFile} disabled={uploadDisabled}>
            选择文件
          </button>
        </div>

        <div className={`upload-verdict-card verdict-${uploadVisual.status}`} aria-live="polite">
          <div className={`verdict-symbol symbol-${statusIcon}`}>{statusIcon}</div>
          <div>
            <span>{uploadVisual.status === 'uploading' ? '处理中' : uploadVisual.classification === 'malicious' ? '恶意样本' : uploadVisual.classification === 'normal' ? '正常样本' : '等待样本'}</span>
            <strong>{uploadVisual.message}</strong>
            <p>{uploadVisual.detail}</p>
          </div>
        </div>

        <SampleViewer key={inspectionFile ? `${inspectionFile.name}-${inspectionFile.lastModified}` : 'empty'} file={inspectionFile} onSelect={onSelectSample} onChooseFile={onChooseFile} />
        <details className="process-playbook" aria-label="上传处理四步路径对比">
          <summary>展开四步处理记录与路径说明</summary>
          <div className="playbook-heading">
            <span>处理记录</span>
            <strong>四步拆解：正常路径 / 攻击路径 / 修补后</strong>
          </div>
          <div className="flow-step-grid">
            {GHOSTSCRIPT_FLOW_STEPS.map((step, index) => {
              const stepNo = index + 1;
              const reached = uploadVisual.flowStep >= stepNo;
              const active = uploadVisual.flowStep === stepNo;
              const issueActive = reached && step.issue && laneKey === 'attack';
              const traceLines = step.traces[laneKey];
              return (
                <article
                  className={`flow-step-card ${reached ? 'is-reached' : ''} ${active ? 'is-active' : ''} ${issueActive ? 'is-issue' : ''}`}
                  key={step.id}
                >
                  <div className="step-chip"><span>{String(stepNo).padStart(2, '0')}</span><strong>{step.title}</strong></div>
                  <code>{step.metric}</code>
                  <div className="path-lanes">
                    <div className={`path-lane lane-normal ${laneKey === 'normal' && reached ? 'is-current' : ''}`}>
                      <span>正常路径</span>
                      <p>{step.normal}</p>
                    </div>
                    <div className={`path-lane lane-attack ${laneKey === 'attack' && reached ? 'is-current' : ''}`}>
                      <span>攻击路径</span>
                      <p>{step.attack}</p>
                    </div>
                    <div className={`path-lane lane-repaired ${laneKey === 'repaired' && reached ? 'is-current' : ''}`}>
                      <span>修补后</span>
                      <p>{step.repaired}</p>
                    </div>
                  </div>
                  <div
                    className={`step-backend-terminal trace-${laneKey} ${active ? 'is-running' : reached ? 'is-complete' : 'is-waiting'}`}
                    aria-label={`${step.title}后台运行轨迹`}
                  >
                    <div className="backend-trace-bar">
                      <span aria-hidden="true"><i /><i /><i /></span>
                      <strong>BACKEND TRACE · 运行轨迹</strong>
                      <em>{active ? 'RUNNING' : reached ? 'CAPTURED' : 'WAITING'}</em>
                    </div>
                    <div className="backend-trace-body">
                      {reached ? traceLines.map((line, lineIndex) => (
                        <code
                          className={`backend-trace-line tone-${line.tone}`}
                          style={{ animationDelay: `${lineIndex * 110}ms` }}
                          key={`${step.id}-${laneKey}-${line.text}`}
                        >
                          <b>{String(lineIndex + 1).padStart(2, '0')}</b>
                          <span>{line.text}</span>
                        </code>
                      )) : (
                        <code className="backend-trace-line tone-muted">
                          <b>--</b><span>[worker] waiting for the previous stage...</span>
                        </code>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </details>

        <div className="marker-inventory" aria-label="容器文件状态">
          <div className={`marker-chip ${uploadVisual.markerPresent ? 'is-present' : 'is-absent'}`}>
            <i>{uploadVisual.markerPresent ? '!' : '✓'}</i>
            <div><span>容器文件状态</span><strong>{uploadVisual.markerPath}</strong></div>
            <em>{uploadVisual.markerPresent ? '存在' : '不存在'}</em>
          </div>
          <div className="parser-route">
            {view.processChain.map((process, index) => (
              <span className={index >= 2 && uploadVisual.status === 'breached' ? 'is-danger' : repaired && index >= 2 ? 'is-blocked' : ''} key={process}>
                {process}
              </span>
            ))}
          </div>
        </div>

        <div className="guide-bubbles" aria-label="互动引导">
          {[
            '拖拽一张正常图片到此处，查看正常行为',
            '拖拽恶意图片 rce.jpg，触发攻击',
            '播放修补解析章节，查看代码变化',
            '选择修补后样本结果，观察拦截',
          ].map((step, index) => (
            <div className={activeStep === index + 1 ? 'guide-bubble is-active' : 'guide-bubble'} key={step}>
              <span>{index + 1}</span>
              <strong>{step}</strong>
            </div>
          ))}
        </div>
      </section>

          <aside className="system-call-dashboard" aria-label="容器观察与证据说明">
        <GhostscriptObserver mode={uploadVisual.classification === 'malicious' ? repaired ? 'protected' : 'attack' : 'normal'} phase={uploadVisual.flowStep} eps={uploadVisual.fileFormat === 'EPS / PostScript'} />
        <details className="traffic-causal"><summary>查看完整处理链路说明</summary><ProcessEvidence step={uploadVisual.flowStep} malicious={uploadVisual.classification === 'malicious'} repaired={repaired} eps={uploadVisual.fileFormat === 'EPS / PostScript'} /></details>

        <div className="upload-log-strip" aria-label="辅助运行日志">
          <span>辅助日志</span>
          {(uploadVisual.logs.length ? uploadVisual.logs : ['等待上传文件...']).map((line, index) => (
            <code key={`${line}-${index}`}>{line}</code>
          ))}
        </div>
          </aside>

          <section className="report-evidence-strip" aria-label="实测采集与定位">
            <div className="report-strip-heading">
              <div><span>REPORT EVIDENCE</span><strong>实测采集与定位</strong></div>
              <code>{reportData.detection.targetFunction}</code>
            </div>
            <div className="report-metric-grid">
              <div><span>流量样本</span><strong>{reportData.traffic.normalRequests} / {reportData.traffic.maliciousRequests}</strong><small>正常 / 恶意请求</small></div>
              <div><span>解析事件</span><strong>{reportData.traffic.normalEvents.toLocaleString()}</strong><small>normal · malicious {reportData.traffic.maliciousEvents.toLocaleString()}</small></div>
              <div><span>请求单元</span><strong>{reportData.traffic.requestUnits}</strong><small>全部完成调用栈恢复</small></div>
              <div className="metric-risk"><span>最高风险分</span><strong>{reportData.detection.normalizedScore.toFixed(3)}</strong><small>{reportData.detection.firstPlaceCount}/11 恶意结果排名第一</small></div>
            </div>
          </section>
        </div>
  );
}

function VuFindEvidencePanel({
  view,
  beforeVisible,
  afterReady,
  afterBlocked,
}: {
  view: VuFindEvidenceView;
  beforeVisible: boolean;
  afterReady: boolean;
  afterBlocked: boolean;
}) {
  const afterState = afterBlocked ? '已拦截' : afterReady ? '待复测' : '待修补';
  const beforeState = beforeVisible ? '已观测' : '待观测';

  function beforeValue(row: MatrixEvidenceRow) {
    return beforeVisible ? row.before : '等待首次请求';
  }

  function afterValue(row: MatrixEvidenceRow) {
    if (afterBlocked) return row.after;
    if (afterReady) return row.ready;
    return '等待策略写入';
  }

  return (
    <div className="network-evidence-body">
      <div className="proxy-dossier" aria-label="VuFind 代理请求档案">
        <div className="dossier-title">
          <span>PROXY REQUEST</span>
          <strong>Cover/Show</strong>
        </div>
        <code className="request-line">GET /vufind/Cover/Show?proxy=...</code>
        <div className="network-target-map" aria-label="请求目标解析">
          <span>USER</span>
          <i>→</i>
          <strong>SERVER FETCH</strong>
          <i>→</i>
          <em>PRIVATE</em>
        </div>
        <div className="request-fields">
          {view.proxyFields.map((field) => (
            <div className={`request-field field-${field.tone}`} key={field.label}>
              <span>{field.label}</span>
              <code>{field.value}</code>
            </div>
          ))}
        </div>
      </div>

      <div className="egress-map" aria-label="VuFind 网络出口边界与请求链">
        <div className="boundary-nodes">
          {view.boundaries.map((boundary, index) => (
            <div className="boundary-node network-boundary-node" key={boundary.label}>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <div>
                <small>{boundary.label}</small>
                <strong>{beforeVisible ? boundary.before : '等待内网访问证据'}</strong>
                <em>{afterBlocked ? boundary.after : afterState}</em>
              </div>
            </div>
          ))}
        </div>

        <div className="process-chain network-process-chain" aria-label="服务端请求链">
          {view.processChain.map((process, index) => (
            <span className={index >= 2 && beforeVisible ? 'process-danger is-active' : ''} key={process}>
              {process}
            </span>
          ))}
        </div>
      </div>

      <div className="cacti-insight network-insight">
        <span>{view.insight}</span>
        <p>这个案例的取证重点是目标地址：用户只是提交了参数，真正跨越网络边界的是 VuFind 服务端发出的出站请求。</p>
      </div>

      <div className="evidence-matrix" aria-label="VuFind 修补前后证据矩阵">
        <div className="matrix-head">
          <span>证据项</span>
          <span>修补前 · {beforeState}</span>
          <span>修补后 · {afterState}</span>
        </div>
        {view.evidenceRows.map((row) => (
          <div className={`matrix-row row-${row.key}`} key={row.key}>
            <strong>{row.label}</strong>
            <code className={beforeVisible ? 'is-before-visible' : ''}>{beforeValue(row)}</code>
            <code className={afterBlocked ? 'is-after-blocked' : afterReady ? 'is-after-ready' : ''}>{afterValue(row)}</code>
          </div>
        ))}
      </div>
    </div>
  );
}
