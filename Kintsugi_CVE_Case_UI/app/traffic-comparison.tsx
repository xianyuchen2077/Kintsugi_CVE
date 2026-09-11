'use client';

import { useEffect, useRef, useState } from 'react';
import { CVE_2018_16509_REPORT_DATA as report } from './cve-2018-report-data.mjs';
import ProcessEvidence from './process-evidence';
import GhostscriptObserver from './ghostscript-observer';

export const scenarios = [
  {
    id: 'normal', title: '正常流量', context: '正常图片 · 业务验证', source: 'Stage 10 实测',
    file: '正常图片', format: '合法图片内容',
    steps: ['提交正常图片', '读取并处理图片', '返回转换结果', '查看业务与目录结果'],
    details: ['图片进入同一个上传接口。', '内容符合正常图片处理要求。', `HTTP ${report.validation.normal.status} · ${report.validation.normal.responseBytes} bytes`, '业务结果有实测记录；目录按正常路径示意。'],
    result: '图片处理成功', summary: '正常功能保持可用',
    explanation: '正常图片仍能返回转换内容。这里引用修补后的业务验证，不代表已测量前后性能差异。',
    marker: '正常路径不创建攻击标记',
  },
  {
    id: 'attack', title: '恶意流量', context: '未修补 · 危险路径', source: '攻击路径示意',
    file: 'rce.jpg', format: '扩展名 JPG / 内容 EPS',
    steps: ['提交伪装图片', '进入 Ghostscript 解释器', '触发额外系统命令', '查看新增证据文件'],
    details: ['与右侧使用同一恶意样本。', '真实内容是 EPS，交给 Ghostscript 解释。', '%pipe% 将处理引向 shell 命令。', 'touch 的可见副作用：创建 got_rce 文件。'],
    result: '出现攻击证据文件', summary: '图片解析越过了业务边界',
    explanation: '正常任务只是处理图片，攻击却让服务器创建了额外文件。文件出现在容器 /tmp 中，不是电脑桌面。',
    marker: '攻击路径：新增 1 个目标文件',
  },
  {
    id: 'protected', title: '修补后恶意流量', context: '相同样本 · 修补后复测', source: 'Stage 10 实测',
    file: 'rce.jpg', format: '扩展名 JPG / 内容 EPS',
    steps: ['提交相同伪装图片', '启动解释器前检查内容', '拒绝危险输入', '核对证据文件未出现'],
    details: ['保持恶意样本不变，验证防护效果。', '输入检查发现 %pipe% 操作符。', `抛出 unsafe EPS file · HTTP ${report.validation.malicious.status}`, '报告记录：/tmp/got_rce 未创建。'],
    result: '危险输入已拒绝', summary: '相同攻击未产生文件副作用',
    explanation: 'HTTP 500 表示该样本处理失败；结合证据文件未创建及正常业务通过，才支持本次修补有效的结论。',
    marker: '实测结果：目标文件未出现',
  },
] as const;

export type TrafficRun = { phase: number; running: boolean; started: boolean };

function FileIcon({ folder = false }: { folder?: boolean }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      {folder ? <path d="M3 9V6h10l3 4h13v16H3V9Z" /> : <><path d="M8 3h10l7 7v19H8V3Z" /><path d="M18 3v8h7M12 17h9M12 22h7" /></>}
    </svg>
  );
}

/** Presentation of saved evidence; no request is sent to the vulnerable service. */
export default function TrafficComparison({ phase, runs, playing, onToggle, onInspect }: {
  phase: number;
  runs: TrafficRun[] | null;
  playing: boolean;
  onToggle: (index: number) => void;
  onInspect: () => void;
}) {
  const [detail, setDetail] = useState<{ index: number; step: number | 'evidence' } | null>(null);
  const [recordView, setRecordView] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (detail) dialog.current?.showModal();
  }, [detail]);
  function inspect(index: number, step: number | 'evidence') {
    onInspect();
    setRecordView(false);
    setDetail({ index, step });
  }
  const selected = detail ? scenarios[detail.index] : null;
  const selectedPhase = detail ? runs?.[detail.index].phase ?? phase : 0;

  return (
    <section className="traffic-comparison" aria-label="正常、恶意与修补后恶意流量对比">
      <div className="traffic-intro">
        <p>看同一个上传入口，最后改变了什么。</p>
        <span>容器目录仅展示相关证据 · 点击按钮按步骤呈现已有资料</span>
      </div>
      <div className="traffic-columns">
        {scenarios.map((scenario, index) => {
          const run = runs?.[index];
          const running = run?.running ?? playing;
          const step = run?.phase ?? phase;
          const complete = step >= 4;
          return (
            <article className={`traffic-lane traffic-${scenario.id} ${complete ? 'is-complete' : ''}`} key={scenario.id}>
              <header className="traffic-lane-heading">
                <div><span className="traffic-number">0{index + 1}</span><h3>{scenario.title}</h3></div>
                <p>{scenario.context}</p>
                <div className="traffic-lane-controls">
                  <span className="traffic-source">{scenario.source}</span>
                  <button className="traffic-play" type="button" onClick={() => onToggle(index)} aria-label={`${running ? '暂停' : '演示'}${scenario.title}`}>
                    <span aria-hidden="true">{running ? 'Ⅱ' : '▶'}</span>{running ? '暂停' : complete ? '重新展示' : step > 0 ? '继续展示' : '逐步展示'}<small>{Math.min(step, 4)} / 4</small>
                  </button>
                </div>
              </header>
              <div className={`traffic-input ${step >= 1 ? 'is-revealed' : ''}`}>
                <FileIcon />
                <div><strong>{scenario.file}</strong><span>{scenario.format}</span></div>
                <small>POST /</small>
              </div>
              <GhostscriptObserver compact mode={scenario.id} phase={step} onInspect={() => inspect(index, 'evidence')} />
              <details className="traffic-full-steps"><summary>四步处理记录 · 点击展开</summary>
              <ol className="traffic-steps" aria-label={`${scenario.title}处理步骤`}>
                {scenario.steps.map((title, stepIndex) => (
                  <li className={step > stepIndex ? 'is-done' : ''} key={title}>
                    <button type="button" className="traffic-step-inspect" onClick={() => inspect(index, stepIndex)} aria-label={`${scenario.title}：${title}，查看详情`}>
                    <span className="traffic-step-number">{step > stepIndex ? '✓' : stepIndex + 1}</span>
                    <span className="traffic-step-copy"><strong>{title}<em aria-hidden="true"> ↗</em></strong><span>{step > stepIndex ? scenario.details[stepIndex] : '等待展示 · 可查看步骤说明'}</span></span>
                    </button>
                  </li>
                ))}
              </ol>
              </details>
              <div className="traffic-output" aria-live="polite" aria-atomic="true">
                {scenario.id === 'normal' ? <details className="business-preview"><summary>查看输入图片与响应依据</summary><figure><img src="/case-samples/CVE-2018-16509/normal.jpg" alt="预置的正常输入图片，非服务器返回图像" /><figcaption>预置输入样本 · 非服务器返回图片</figcaption></figure><dl><div><dt>报告中的业务响应</dt><dd>HTTP {report.validation.normal.status} · {report.validation.normal.responseBytes} bytes</dd></div><div><dt>转换后图像</dt><dd>当前资料未提供，暂不显示预览</dd></div></dl></details> : <details className="traffic-causal"><summary>查看进程与文件关系</summary><ProcessEvidence step={step} malicious repaired={scenario.id === 'protected'} eps /></details>}
                <p className="traffic-takeaway"><strong>{complete ? scenario.summary : '观察处理过程与文件变化'}</strong><span>{complete ? scenario.explanation : '每列可单独播放，也可用“演示本页”同步对照。'}</span></p>
              </div>
            </article>
          );
        })}
      </div>
      <div className="traffic-reading-note"><strong>对比要点</strong><p>正常图片能处理；恶意 EPS 的风险是让图片解析触发额外命令；修补将危险输入挡在解释器之前。正常 EPS 渲染本身也可能创建子进程，不能把所有 execve 都视为攻击。</p></div>
      <dialog ref={dialog} className="traffic-detail-dialog" aria-labelledby="traffic-detail-title" onClose={() => setDetail(null)} onClick={(event) => { if (event.target === dialog.current) dialog.current?.close(); }}>
        {selected && detail ? <div className="traffic-detail-content">
          <header><span>{selected.title} · {selected.source}</span><button type="button" autoFocus onClick={() => dialog.current?.close()} aria-label="关闭详情">关闭 ×</button></header>
          <h3 id="traffic-detail-title">{detail.step === 'evidence' ? '容器文件证据' : selected.steps[detail.step]}</h3>
          <div className="sample-tabs" role="tablist" aria-label="证据详情查看方式"><button role="tab" aria-selected={!recordView} onClick={() => setRecordView(false)}>解释说明</button><button role="tab" aria-selected={recordView} onClick={() => setRecordView(true)}>原始记录</button></div>
          <p className="traffic-detail-status">{selectedPhase >= (detail.step === 'evidence' ? 4 : detail.step + 1) ? '该环节已展示' : '步骤说明 · 演示尚未到达此处'} · 查看期间不推进演示</p>
          {recordView ? <section className="evidence-record" role="tabpanel"><p>来源：CVE-2018-16509-report.md<br />{selected.id === 'attack' ? '恶意请求路径记录' : 'Stage 10 · 验证修复'}</p><pre>{selected.id === 'normal' ? '正常图片上传: HTTP 200，返回 1653 bytes，通过' : selected.id === 'protected' ? '恶意 EPS 上传: HTTP 500，未创建 /tmp/got_rce，通过\n\nnormal_ok: true\nmalicious_blocked: true\nsuccess: true' : '恶意请求中包含 Ghostscript `%pipe%touch /tmp/got_rce` payload，说明恶意流量确实进入了漏洞路径。'}</pre><aside>{selected.id === 'attack' ? '此摘录证明载荷进入漏洞路径，未提供修补前文件的 stat 原始输出；目录中的新增文件按攻击机制示意。' : '以上为已有报告摘录，并非此次点击运行终端产生的日志。'}</aside></section> : <>
          {detail.step === 'evidence' ? <>
            <dl><div><dt>目标位置</dt><dd><code>/tmp/got_rce</code></dd></div><div><dt>所在环境</dt><dd>{report.pipeline.container} 容器</dd></div><div><dt>当前画面</dt><dd>{selectedPhase < 4 ? '尚未展示文件检查结果' : selected.marker}</dd></div></dl>
            <p>{selected.explanation}</p>
            <p>这个文件用来标记命令执行的副作用，判断重点是“是否被创建”，而不是文件里写了什么。现有资料未提供文件内容、权限和创建时间。</p>
            <aside>{selected.id === 'attack' ? '此处按攻击路径演示文件出现，不是本次点击实时读取的目录。' : selected.id === 'protected' ? '依据 Stage 10：恶意输入返回 HTTP 500，/tmp/got_rce 未创建；正常图片验证通过。' : 'HTTP 200 与 1653 bytes 来自 Stage 10；正常路径未创建攻击文件的画面是逻辑示意。'}</aside>
          </> : <>
            <p>{selected.details[detail.step]}</p>
            <dl><div><dt>输入内容</dt><dd>{selected.file} · {selected.format}</dd></div><div><dt>处理位置</dt><dd>{detail.step === 0 ? 'HTTP 上传接口：POST /' : selected.id === 'normal' ? 'Pillow 图片处理链路' : 'PIL.EpsImagePlugin.Ghostscript'}</dd></div></dl>
            <pre>{detail.step === 0 ? '上传文件 → 按文件内容识别格式' : detail.step === 1 ? (selected.id === 'protected' ? "if b'%pipe%' in eps_file.read():\n    raise IOError('unsafe EPS file')" : selected.id === 'attack' ? 'EPS 内容 → Ghostscript → %pipe% 危险路径' : '合法图片 → 解码 / 转换 → 图片响应') : detail.step === 2 ? (selected.id === 'normal' ? 'HTTP 200 · 1653 bytes · normal_ok=true' : selected.id === 'protected' ? 'unsafe EPS file → 拒绝处理 → HTTP 500' : '图片解释 → 额外 shell 命令 → 创建目标文件') : selected.marker}</pre>
            <aside>{detail.step < 3 ? '处理逻辑说明；查看步骤不会提前推进演示或触发后台执行。' : selected.explanation}</aside>
          </>}
          </>}
          <footer>{selectedPhase >= 4 ? '关闭后可重新展示，或查看其他流量的证据。' : '关闭后可继续播放，从暂停的位置接着讲。'}</footer>
        </div> : null}
      </dialog>
    </section>
  );
}
