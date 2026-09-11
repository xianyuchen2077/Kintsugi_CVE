'use client';

import { CACTI_SCENARIOS, CACTI_STEPS, cactiSnapshot } from './cacti-scenario.mjs';
import './cacti-lab.css';

type Props = {
  mode: string;
  phase: number;
  comparison?: boolean;
  onMode: (mode: string) => void;
  onStep: (step: number) => void;
};

function MarkerFolder({ mode, phase }: { mode: string; phase: number }) {
  const state = cactiSnapshot(mode, phase);
  return <div className={`cacti-folder marker-${state.marker}`}>
    <div className="cacti-folder-bar"><span aria-hidden="true">▱</span><code>/tmp</code><span>仅展示攻击标记</span></div>
    <div className="cacti-folder-content" aria-live="polite">
      {state.marker === 'present' ? <><span className="cacti-file-icon" aria-hidden="true">＋</span><div><strong>kintsugi_marker</strong><p>预期新增 · 命令执行的副作用</p></div></>
        : <><span className="cacti-file-icon" aria-hidden="true">{state.marker === 'pending' ? '…' : '—'}</span><div><strong>{state.marker === 'pending' ? '等待文件检查' : '未发现攻击标记'}</strong><p>{state.marker === 'pending' ? '流程尚未到达证据检查步骤' : '预期状态 · 不代表目录为空'}</p></div></>}
    </div>
  </div>;
}

export default function CactiLab({ mode, phase, comparison = false, onMode, onStep }: Props) {
  const state = cactiSnapshot(mode, phase);
  return <div className="cacti-lab">
    <div className="cacti-lab-intro"><p>{comparison ? '对照同一条链路，看额外行为在哪里出现、在哪里停止。' : '数据本应只用于轮询，问题出在它被当成了命令的一部分。'}</p><span>路径示意 · 非本次实测</span></div>
    <div className="cacti-mode-switch" role="group" aria-label="选择 Cacti 请求场景">
      {CACTI_SCENARIOS.map((scenario, index) => <button key={scenario.id} type="button" aria-pressed={mode === scenario.id} onClick={() => onMode(scenario.id)}><span>0{index + 1}</span><div><strong>{scenario.title}</strong><small>{scenario.subtitle}</small></div></button>)}
    </div>
    <div className="cacti-step-controls" role="group" aria-label="Cacti 流程步骤">
      {CACTI_STEPS.map((step, index) => <button type="button" key={step} aria-pressed={phase === index + 1} className={phase >= index + 1 ? 'is-reached' : ''} onClick={() => onStep(index + 1)}><span>{index + 1}</span>{step}<small>{phase === index + 1 ? '当前步骤' : '点击查看'}</small></button>)}
    </div>
    {comparison ? <div className="cacti-three-paths">
      {CACTI_SCENARIOS.map((scenario) => {
        const item = cactiSnapshot(scenario.id, phase);
        return <section key={scenario.id} className={`cacti-compare-column mode-${scenario.id} ${mode === scenario.id ? 'is-selected' : ''}`}>
          <h3>{scenario.title}</h3><p>{scenario.subtitle}</p>
          <ol>{CACTI_STEPS.map((step, index) => <li key={step} className={phase >= index + 1 ? 'is-reached' : ''}><span>{index + 1}</span><div><strong>{step}</strong><p>{phase >= index + 1 ? scenario.details[index] : '等待此步骤'}</p></div></li>)}</ol>
          <MarkerFolder mode={scenario.id} phase={phase} />
          <strong className="cacti-result">{phase === 4 ? `预期：${item.result}` : `${phase} / 4 步`}</strong>
        </section>;
      })}
    </div> : <div className={`cacti-route-layout mode-${mode}`}>
      <section className="cacti-request-sheet" aria-label="Cacti 请求内容">
        <h3>请求中的两处关键输入</h3><code className="cacti-endpoint">GET /remote_agent.php?action=polldata</code>
        <dl><dt>来源声明</dt><dd><code>X-Forwarded-For: 127.0.0.1</code><p>{mode === 'normal' ? '本地测试 poller 使用的请求头。' : '外部请求声称自己来自本地。'}</p></dd><dt>轮询参数</dt><dd><code>poller_id=1{mode !== 'normal' && <mark>; touch /tmp/kintsugi_marker</mark>}</code><p>{mode === 'normal' ? '参数只表示轮询器编号。' : '分号之后是额外命令，不再是编号。'}</p></dd><dt>测试采集项</dt><dd><code>{state.branch}</code><p>这里是数据库采集项的 action，不是 URL 的 action=polldata。</p></dd></dl>
      </section>
      <section className="cacti-boundary-route" aria-label="Cacti 信任边界示意">
        <h3>请求走到哪里了</h3>
        <div className={`cacti-boundary ${phase >= 2 ? 'is-reached' : ''}`}><small>边界一 · 谁可以调用</small><strong>{phase < 2 ? '等待来源判断' : mode === 'normal' ? '本地测试请求进入轮询' : '来源声明被误信任'}</strong><p>声明一个地址，不等于证明自己的身份。</p></div>
        <div className="cacti-route-connector" aria-hidden="true">↓</div>
        <div className={`cacti-boundary ${phase >= 3 ? 'is-reached' : ''} ${state.blocked ? 'is-blocked' : ''}`}><small>边界二 · 数据能否变成命令</small><strong>{phase < 3 ? '等待业务分支' : mode === 'normal' ? '执行正常采集任务' : state.blocked ? '危险调用前限制执行' : '参数进入危险命令分支'}</strong><p>{mode === 'normal' ? '正常测试走 action=1，不应把所有命令执行都判为攻击。' : state.blocked ? '示意防护位置；不代表来源校验也已修复。' : '需要关注的是多执行了什么，而不是仅统计进程数量。'}</p></div>
        <div className="cacti-route-connector" aria-hidden="true">↓</div>
        <MarkerFolder mode={mode} phase={phase} />
      </section>
    </div>}
    <div className="cacti-current-step" aria-live="polite"><span>{phase ? `步骤 ${phase} / 4` : '操作提示'}</span><p>{state.finding}</p></div>
    <details className="cacti-evidence-notes"><summary>查看判定依据与测试覆盖范围</summary><div>
      <section><h3>正常业务：不只看 HTTP 200</h3><p>validate.py 同时检查响应状态、采集数据内容和攻击标记。只有响应含预期 local_data_id 或数值 123，且标记未出现，才满足脚本的正常请求判据。</p><code>validate_normal_request() · BENIGN_CASES</code></section>
      <section><h3>攻击效果：看新增副作用</h3><p>每次测试先清理旧标记，再检查 /tmp/kintsugi_marker 及其变体。文件不存在不能单独证明拦截有效；超时、连接错误也不能代替完整的执行证据。</p><code>validate_malicious_request() · _marker_exists()</code></section>
      <section><h3>还缺什么，才能称为实测</h3><p>本页尚未加载 Cacti 的运行产物。需要修补前后同一输入的请求与响应、标记清理和检测记录、实际修补代码及调用轨迹。正常测试走 action=1，仍需补充 action=2 的合法输入回归。</p><code>依据：cves/php/CVE-2022-46169/validate.py</code></section>
    </div></details>
  </div>;
}
