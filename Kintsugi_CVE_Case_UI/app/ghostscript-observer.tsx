'use client';

import { useState } from 'react';
import { getGhostscriptObservation } from './ghostscript-observation.mjs';
import { CVE_2018_16509_REPORT_DATA as report } from './cve-2018-report-data.mjs';
import './ghostscript-observer.css';

export default function GhostscriptObserver({ mode, phase, eps = false, compact = false, onInspect }: {
  mode: 'normal' | 'attack' | 'protected'; phase: number; eps?: boolean; compact?: boolean; onInspect?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const state = getGhostscriptObservation(mode, phase, eps);
  const blocked = mode === 'protected';
  function inspect() { if (onInspect) onInspect(); else setExpanded((value) => !value); }
  return <section className={`gs-observer gs-${mode} ${compact ? 'gs-compact' : ''}`} aria-label="Ghostscript 容器观察窗">
    <header className="gs-observer-heading"><div><span>容器观察窗</span><h3>{compact ? '/tmp · 文件副作用' : '图片之外，容器里发生了什么？'}</h3></div><small>已有资料 · 非实时连接</small></header>
    {!compact && <div className="gs-environment"><span>实验容器</span><code>{report.pipeline.container}</code><em>{blocked ? '修补后恶意样本' : mode === 'attack' ? '修补前恶意样本' : '正常图片场景'}</em></div>}
    <div className="gs-filesystem">
      <div className="gs-folder-toolbar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M3 7V4h7l3 3h8v13H3Z" /></svg><code>/tmp</code><span>仅列出本实验关注的文件</span></div>
      <button type="button" className={`gs-file-row file-${state.marker}`} onClick={inspect} aria-label={`查看 ${mode === 'normal' ? '正常流量' : blocked ? '修补后恶意流量' : '恶意流量'}的 got_rce 证据`} aria-expanded={onInspect ? undefined : expanded}>
        <svg viewBox="0 0 28 34" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M5 2h11l8 8v22H5Z M16 2v9h8 M10 19h9 M10 24h7" /></svg>
        <div><strong>{state.marker === 'pending' ? 'got_rce · 待检查' : state.marker === 'present' ? 'got_rce' : '未出现 got_rce'}</strong><span>{state.marker === 'pending' ? '到第 4 步才展示目录结果' : state.marker === 'present' ? '新增目标文件 · 按攻击机制示意' : blocked ? 'Stage 10 报告：目标文件未创建' : '正常路径示意，不代表实测目录快照'}</span></div>
        <em>{state.marker === 'present' ? '＋ 新增' : state.marker === 'absent' ? '未新增' : '待核对'}<b aria-hidden="true"> ↗</b></em>
      </button>
      <div className="gs-file-footnote"><span>{state.marker === 'pending' ? '尚未展示文件检查' : state.markerSource === 'report' ? '依据：验证报告' : '依据：路径原理'}</span><span>点击查看证据</span></div>
    </div>
    <div className="gs-observation-result" aria-live="polite"><strong>{state.headline}</strong><span>{state.response ? `报告对照：HTTP ${state.response}${state.responseBytes ? ` · ${state.responseBytes} bytes` : ' · 恶意输入处理失败'}` : state.step >= 3 && mode === 'attack' ? '没有修补前响应原始记录，不填造状态码' : `处理进度 ${state.step} / 4`}</span></div>
    <div className="gs-processing" aria-label="处理链路示意">
      <div className={state.step >= 1 ? 'is-reached' : ''}><span>01</span><strong>上传接口</strong><small>Flask / Pillow</small></div>
      <span className="gs-arrow" aria-hidden="true">→</span>
      <div className={state.guard ? 'is-guarded' : state.step >= 2 ? 'is-reached' : ''}><span>02</span><strong>{blocked ? '输入检查' : '内容识别'}</strong><small>{blocked ? state.guard ? '%pipe% · 拒绝' : '检查 EPS 内容' : mode === 'attack' || eps ? 'EPS / PostScript 内容' : '合法图片格式'}</small></div>
      <span className="gs-arrow" aria-hidden="true">{state.guard ? '⊣' : '→'}</span>
      <div className={`parser-${state.parserState}`}><span>03</span><strong>{state.parser}</strong><small>{state.parserState === 'stopped' ? '未启动' : state.parserState === 'reached' ? '进入处理路径' : '等待处理'}</small></div>
    </div>
    <div className={`gs-extra-branch ${state.extraCommand ? 'is-active' : ''} ${state.guard ? 'is-guarded' : ''}`}><span aria-hidden="true">{state.guard ? '⊣' : '↳'}</span><div><strong>{state.extraCommand ? '额外命令：创建标记文件' : state.guard ? '额外命令路径被截断' : '业务之外的命令分支'}</strong><code>{state.extraCommand ? 'shell → touch /tmp/got_rce' : state.guard ? '在调用 Ghostscript 前拒绝危险输入' : '尚无额外命令的展示结果'}</code></div><small>关系示意</small></div>
    {expanded && <div className="gs-source-note"><h4>这个画面如何得出</h4><p>{mode === 'attack' ? '报告记录了包含 %pipe% 的恶意载荷进入漏洞路径。文件出现是按攻击机制呈现，现有资料没有提供修补前的 stat 原始输出。' : blocked ? 'Stage 10 记录恶意 EPS 返回 HTTP 500、未创建 /tmp/got_rce。该实验最终使用 Python 输入检查，不是已验证的内核 eBPF 拦截。' : 'Stage 10 记录正常图片返回 HTTP 200、1653 bytes。当前输入图片可预览，但报告未提供转换后的图片及正常目录原始快照。'}</p><code>CVE-2018-16509-report.md · {mode === 'attack' ? '恶意路径' : 'Stage 10'}</code><p>仅说明本组样本。文件不存在或 HTTP 500，单独一项都不足以证明漏洞已全面修复。</p></div>}
  </section>;
}
