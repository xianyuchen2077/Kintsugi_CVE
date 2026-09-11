import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  CVE_PROFILES,
  createInitialState,
  isBusy,
  transitionDemo,
} from '../app/case-state.mjs';

const pagePath = fileURLToPath(new URL('../app/page.tsx', import.meta.url));
const stylesPath = fileURLToPath(new URL('../app/globals.css', import.meta.url));

test('creates a vulnerable default session for CVE-2022-46169', () => {
  const state = createInitialState();

  assert.equal(state.cve, 'CVE-2022-46169');
  assert.equal(state.repairStatus, 'vulnerable');
  assert.equal(state.phase, 'ready');
  assert.equal(state.progress, 0);
  assert.deepEqual(state.logs, []);
});

test('records an exposed result when a vulnerable target is attacked', () => {
  const attacking = transitionDemo(createInitialState(), { type: 'ATTACK_START' });
  const completed = transitionDemo(attacking, { type: 'ATTACK_COMPLETE' });

  assert.equal(attacking.repairStatus, 'attacking');
  assert.equal(completed.repairStatus, 'vulnerable');
  assert.equal(completed.phase, 'exposed');
  assert.equal(completed.result, 'breached');
  assert.equal(completed.baselineObserved, true);
});

test('moves through repair and finishes in the repaired state', () => {
  const exposed = transitionDemo(
    transitionDemo(createInitialState(), { type: 'ATTACK_START' }),
    { type: 'ATTACK_COMPLETE' },
  );
  const started = transitionDemo(exposed, { type: 'REPAIR_START' });
  const staged = transitionDemo(started, { type: 'REPAIR_PROGRESS', progress: 72, stage: 2 });
  const completed = transitionDemo(staged, { type: 'REPAIR_COMPLETE' });

  assert.equal(started.repairStatus, 'repairing');
  assert.equal(staged.progress, 72);
  assert.equal(staged.pipelineStage, 2);
  assert.equal(completed.repairStatus, 'repaired');
  assert.equal(completed.phase, 'repaired');
  assert.equal(completed.progress, 100);
});

test('records a blocked result and normal verification after repaired attack', () => {
  const exposed = transitionDemo(
    transitionDemo(createInitialState(), { type: 'ATTACK_START' }),
    { type: 'ATTACK_COMPLETE' },
  );
  const repaired = transitionDemo(
    transitionDemo(exposed, { type: 'REPAIR_START' }),
    { type: 'REPAIR_COMPLETE' },
  );
  const attacking = transitionDemo(repaired, { type: 'ATTACK_START' });
  const completed = transitionDemo(attacking, { type: 'ATTACK_COMPLETE' });

  assert.equal(completed.repairStatus, 'repaired');
  assert.equal(completed.phase, 'verified');
  assert.equal(completed.result, 'blocked');
  assert.equal(completed.normalVerified, true);
  assert.equal(completed.baselineObserved, true);
});

test('reset clears transient evidence but keeps the selected CVE', () => {
  const initial = createInitialState('CVE-2018-16509');
  const withLog = transitionDemo(initial, { type: 'LOG_APPEND', line: 'demo line' });
  const attacking = transitionDemo(withLog, { type: 'ATTACK_START' });
  const reset = transitionDemo(attacking, { type: 'RESET' });

  assert.equal(reset.cve, 'CVE-2018-16509');
  assert.equal(reset.repairStatus, 'vulnerable');
  assert.deepEqual(reset.logs, []);
  assert.equal(reset.result, null);
});

test('switching CVE starts a clean session with a known profile', () => {
  const switched = transitionDemo(createInitialState(), {
    type: 'SELECT_CVE',
    cve: 'CVE-2024-25737',
  });

  assert.equal(switched.cve, 'CVE-2024-25737');
  assert.equal(switched.phase, 'ready');
  assert.equal(CVE_PROFILES[switched.cve].product, 'VuFind');
});

test('busy states are reported while attacking or repairing', () => {
  const initial = createInitialState();
  const attacking = transitionDemo(initial, { type: 'ATTACK_START' });
  const exposed = transitionDemo(attacking, { type: 'ATTACK_COMPLETE' });
  const repairing = transitionDemo(exposed, { type: 'REPAIR_START' });

  assert.equal(isBusy(initial), false);
  assert.equal(isBusy(attacking), true);
  assert.equal(isBusy(repairing), true);
});

test('tracks live patch progress only while the repair pipeline is running', () => {
  const initial = createInitialState();
  const ignored = transitionDemo(initial, { type: 'PATCH_PROGRESS', step: 2 });
  const exposed = transitionDemo(
    transitionDemo(initial, { type: 'ATTACK_START' }),
    { type: 'ATTACK_COMPLETE' },
  );
  const repairing = transitionDemo(exposed, { type: 'REPAIR_START' });
  const patched = transitionDemo(repairing, { type: 'PATCH_PROGRESS', step: 3 });
  const completed = transitionDemo(patched, { type: 'REPAIR_COMPLETE' });

  assert.equal(ignored.patchStep, 0);
  assert.equal(patched.patchStep, 3);
  assert.equal(completed.patchStep, 4);
});

test('does not start repair before the baseline attack has been observed', () => {
  const initial = createInitialState();
  const unchanged = transitionDemo(initial, { type: 'REPAIR_START' });

  assert.deepEqual(unchanged, initial);
});

test('provides language-appropriate live patch fixtures', () => {
  const pythonPatch = CVE_PROFILES['CVE-2018-16509'].patch.lines;
  const phpPatch = CVE_PROFILES['CVE-2022-46169'].patch.lines;

  assert.equal(pythonPatch.some((line) => line.code.includes("b'%pipe%'")), true);
  assert.equal(pythonPatch.some((line) => line.code.includes('$input')), false);
  assert.equal(phpPatch.some((line) => line.code.includes('$input')), true);
});

test('uses report-backed Ghostscript detection and validation evidence', () => {
  const profile = CVE_PROFILES['CVE-2018-16509'];

  assert.equal(profile.targetFunction, 'PIL.EpsImagePlugin.Ghostscript');
  assert.equal(profile.repairLocation, 'PIL/EpsImagePlugin.py · Ghostscript()');
  assert.equal(profile.dangerCall, 'subprocess.check_call → gs / unexpected command');
  assert.equal(profile.reportData.detection.normalizedScore, 1);
  assert.deepEqual(profile.reportData.whitelist.execveAllowedPaths, [
    '/usr/local/bin/gs',
    '/usr/local/sbin/gs',
  ]);
  assert.equal(profile.reportData.validation.malicious.markerPresent, false);
  assert.match(profile.blockedEvidence, /HTTP 500/);
  assert.match(profile.normalEvidence, /HTTP 200/);
});

test('plays report-backed Ghostscript terminal evidence', () => {
  const profile = CVE_PROFILES['CVE-2018-16509'];
  const logs = [...profile.attackLogs, ...profile.repairLogs, ...profile.blockedLogs].join('\n');

  assert.match(logs, /29 个正常请求/);
  assert.match(logs, /PIL\.EpsImagePlugin\.Ghostscript · score=1\.000/);
  assert.match(logs, /10 类 syscall/);
  assert.match(logs, /HTTP 500 · \/tmp\/got_rce absent/);
});

test('provides a distinct evidence view for every case', () => {
  const command = CVE_PROFILES['CVE-2022-46169'].evidenceView;
  const file = CVE_PROFILES['CVE-2018-16509'].evidenceView;
  const network = CVE_PROFILES['CVE-2024-25737'].evidenceView;

  assert.deepEqual([command.kind, file.kind, network.kind], ['command', 'file', 'network']);
  assert.match(command.specimen.value, /poller_id/);
  assert.match(file.specimen.value, /rce\.jpg/);
  assert.match(network.specimen.value, /3306/);
});

test('keeps case evidence concise and structurally comparable', () => {
  for (const profile of Object.values(CVE_PROFILES)) {
    assert.equal(profile.evidenceView.steps.length, 3);
    assert.equal(profile.evidenceView.facts.length, 3);
    assert.ok(profile.evidenceView.title.length > 0);
    assert.ok(profile.evidenceView.beforeSignal.length > 0);
    assert.ok(profile.evidenceView.afterSignal.length > 0);
  }
});

test('describes the Cacti case with request fields, boundaries, and evidence rows', () => {
  const view = CVE_PROFILES['CVE-2022-46169'].evidenceView;

  assert.deepEqual(view.requestFields.map((field) => field.label), [
    '伪造来源头',
    '动作入口',
    '危险参数',
  ]);
  assert.deepEqual(view.boundaries.map((boundary) => boundary.label), [
    '可信来源边界',
    '命令执行边界',
  ]);
  assert.equal(view.processChain.join(' -> '), 'apache2 -> php-fpm -> /bin/sh -> touch');
  assert.equal(view.insight, 'HTTP 200 不等于安全');
  assert.deepEqual(view.evidenceRows.map((row) => row.key), ['http', 'marker', 'normal']);
  assert.deepEqual(view.markerFile, {
    directory: '/tmp',
    name: 'kintsugi_marker',
    path: '/tmp/kintsugi_marker',
    size: '0B',
    createdBy: 'touch',
  });
});

test('describes the Ghostscript case with upload identity, parser boundaries, and evidence rows', () => {
  const view = CVE_PROFILES['CVE-2018-16509'].evidenceView;

  assert.deepEqual(view.uploadFields.map((field) => field.label), [
    '表面文件名',
    '声明类型',
    '真实载荷',
  ]);
  assert.deepEqual(view.boundaries.map((boundary) => boundary.label), [
    '文件身份边界',
    '子进程行为边界',
  ]);
  assert.equal(view.processChain.join(' -> '), 'flask -> pillow -> gs -> execve');
  assert.equal(view.insight, '文件扩展名不等于解析内容');
  assert.deepEqual(view.evidenceRows.map((row) => row.key), ['upload', 'process', 'normal']);
});

test('renders the Ghostscript case as an upload-first visual battlefield', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /upload-battlefield/);
  assert.match(source, /onDrop=\{handleGhostscriptDrop\}/);
  assert.match(source, /GhostscriptObserver/);
  assert.match(source, /\/tmp\/got_rce/);
  assert.match(source, /修补后数据已加载/);
  assert.match(source, /Blocked by %pipe% input guard/);
  assert.match(styles, /\.ghostscript-arena \{[\s\S]*?grid-template-columns: minmax\(0, 3fr\) minmax\(320px, 2fr\);/);
  assert.match(styles, /\.upload-verdict-card\.verdict-breached/);
  assert.match(styles, /\.syscall-bar-fill/);
  assert.match(styles, /@media \(max-width: 980px\)[\s\S]*?\.ghostscript-arena \{ grid-template-columns: 1fr;/);
});

test('renders Ghostscript uploads as a step-by-step process comparison', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /GHOSTSCRIPT_FLOW_STEPS/);
  assert.match(source, /flowStep/);
  assert.match(source, /process-playbook/);
  assert.match(source, /正常路径/);
  assert.match(source, /攻击路径/);
  assert.match(source, /修补后/);
  assert.match(source, /上传入口/);
  assert.match(source, /文件身份/);
  assert.match(source, /解析边界/);
  assert.match(source, /系统调用/);
  assert.match(styles, /\.process-playbook/);
  assert.match(styles, /\.flow-step-card\.is-active/);
  assert.match(styles, /\.path-lane\.lane-attack/);
});

test('keeps Ghostscript upload playback alive when switching to the location view', () => {
  const source = readFileSync(pagePath, 'utf8');
  const match = /async function runGhostscriptUpload\(file: File, scenarioRepaired\?: boolean\) \{([\s\S]*?)\n  \}/.exec(source);

  assert.ok(match, 'runGhostscriptUpload should be present');

  const body = match[1];
  const selectIndex = body.indexOf("selectWorkspaceView('location')");
  const captureIndex = body.indexOf('const currentSequence = sequence.current');

  assert.ok(selectIndex >= 0, 'upload should enter the location view');
  assert.ok(captureIndex >= 0, 'upload should capture the active sequence token');
  assert.ok(
    selectIndex < captureIndex,
    'switching to the location view must happen before capturing the upload sequence token',
  );
});

test('uses the bundled normal jpg sample name in Ghostscript upload hints', () => {
  const source = readFileSync(pagePath, 'utf8');

  assert.match(source, /normal\.jpg/);
  assert.doesNotMatch(source, /normal\.png/);
});

test('renders a backend runtime trace inside every Ghostscript process step', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /traces:\s*\{/);
  assert.match(source, /BACKEND TRACE/);
  assert.match(source, /运行轨迹/);
  assert.match(source, /step-backend-terminal/);
  assert.match(source, /backend-trace-line/);
  assert.match(source, /EpsImagePlugin\.Ghostscript\(\)/);
  assert.match(source, /execve\('\/bin\/sh'/);
  assert.match(source, /\/tmp\/got_rce -> PRESENT/);
  assert.match(styles, /\.flow-step-grid \{[\s\S]*?grid-template-columns: repeat\(2, minmax\(0, 1fr\)\);/);
  assert.match(styles, /\.step-backend-terminal/);
  assert.match(styles, /\.step-backend-terminal\.is-running/);
  assert.match(styles, /@keyframes traceLineIn/);
});

test('renders report-backed Ghostscript evidence, policy, and validation sections', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /report-evidence-strip/);
  assert.match(source, /实测采集与定位/);
  assert.match(source, /policy-whitelist/);
  assert.match(source, /execve 仅允许/);
  assert.match(source, /validation-matrix/);
  assert.match(source, /Stage 10 实测结果/);
  assert.match(source, /ProcessEvidence/);
  assert.doesNotMatch(source, /异常指数 86/);
  assert.match(styles, /\.report-evidence-strip/);
  assert.match(styles, /\.policy-whitelist/);
  assert.match(styles, /\.validation-matrix/);
});

test('explains Ghostscript before-after validation results on the comparison page', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /comparison-validation-grid/);
  assert.match(source, /实测结果怎么读/);
  assert.match(source, /HTTP 200 说明正常图片仍然能处理/);
  assert.match(source, /HTTP 500 不是服务崩溃/);
  assert.match(source, /marker 文件没有出现/);
  assert.match(source, /关注额外命令，而非所有子进程/);
  assert.match(source, /没有提供修补前后的 execve 实测计数/);
  assert.match(source, /正常业务没有被误伤/);
  assert.match(styles, /\.comparison-validation-grid/);
  assert.match(styles, /\.result-reading-panel/);
  assert.match(styles, /\.result-reading-item/);
});

test('renders Ghostscript comparison as a visual result dashboard', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /GHOSTSCRIPT_RESULT_METRICS/);
  assert.match(source, /visual-result-dashboard/);
  assert.match(source, /一眼看结论/);
  assert.match(source, /危险命令：从可执行到不可执行/);
  assert.match(source, /业务链路：正常图片继续通过/);
  assert.match(source, /attack-surface-map/);
  assert.match(source, /metric-bar-chart/);
  assert.match(source, /result-verdict-strip/);
  assert.match(styles, /\.visual-result-dashboard/);
  assert.match(styles, /\.attack-surface-map/);
  assert.match(styles, /\.metric-bar-chart/);
  assert.match(styles, /\.result-verdict-strip/);
});

test('labels Ghostscript comparison metrics by evidence source instead of subjective percentages', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /evidenceSource/);
  assert.match(source, /实测证据/);
  assert.match(source, /演示指数/);
  assert.match(source, /Stage 10 实测/);
  assert.match(source, /normal_ok=true · HTTP 200 · 1653 bytes/);
  assert.match(source, /不做前后百分比/);
  assert.doesNotMatch(source, /before: 100, after: 100/);
  assert.match(styles, /\.metric-source-badge/);
  assert.match(styles, /\.metric-evidence-note/);
});

test('keeps Ghostscript metric cards readable and professionally explained', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /headline/);
  assert.match(source, /metric-primary-line/);
  assert.match(source, /看的是是否出现额外 shell 子进程/);
  assert.match(source, /文件出现说明命令执行过/);
  assert.match(source, /正常图片还能处理并返回内容/);
  assert.match(source, /最终结论仍以 Stage 10 表格为准/);
  assert.doesNotMatch(source, /归一化片段/);
  assert.match(styles, /\.metric-title strong \{[^}]*font-size: 18px/);
  assert.match(styles, /\.metric-primary-line \{[^}]*font-size: 14px/);
  assert.match(styles, /\.metric-evidence-note \{[^}]*font-size: var\(--font-body\)/);
});

test('describes the VuFind case with proxy target, network boundaries, and evidence rows', () => {
  const view = CVE_PROFILES['CVE-2024-25737'].evidenceView;

  assert.deepEqual(view.proxyFields.map((field) => field.label), [
    '用户参数',
    '解析目标',
    '内部服务',
  ]);
  assert.deepEqual(view.boundaries.map((boundary) => boundary.label), [
    'URL 信任边界',
    '网络出口边界',
  ]);
  assert.equal(view.processChain.join(' -> '), 'browser -> vufind -> curl -> internal-api');
  assert.equal(view.insight, '服务端可达不等于用户可达');
  assert.deepEqual(view.evidenceRows.map((row) => row.key), ['response', 'destination', 'normal']);
});

test('returns to the exposed state when a local repair run fails', () => {
  const initial = createInitialState();
  const exposed = transitionDemo(
    transitionDemo(initial, { type: 'ATTACK_START' }),
    { type: 'ATTACK_COMPLETE' },
  );
  const repairing = transitionDemo(exposed, { type: 'REPAIR_START' });
  const failed = transitionDemo(repairing, { type: 'REPAIR_FAILED' });

  assert.equal(failed.repairStatus, 'vulnerable');
  assert.equal(failed.phase, 'exposed');
  assert.equal(failed.result, 'breached');
  assert.equal(failed.progress, 0);
  assert.equal(failed.patchStep, 0);
});

test('keeps only shared status reset and speed controls in the case header', () => {
  const source = readFileSync(pagePath, 'utf8');

  assert.match(source, /演示数据已加载/);
  assert.match(source, /当前页状态/);
  assert.match(source, /重置状态/);
  assert.match(source, /PLAYBACK_SPEEDS/);
  assert.match(source, /transitionPlayback/);
  assert.doesNotMatch(source, /按演示流程推进/);
});

test('uses Cacti-specific paths and does not invent container output', () => {
  const source = readFileSync(pagePath, 'utf8');
  assert.match(source, /<CactiLab comparison/);
  assert.match(source, /cactiActive \? cactiState.logs/);
  assert.doesNotMatch(source, /Modify: just now/);
  assert.doesNotMatch(source, /Up · web target ready/);
});

test('removes live Bridge repair controls from the presentation surface', () => {
  const source = readFileSync(pagePath, 'utf8');

  assert.equal(source.includes('bridge-password'), false);
  assert.equal(source.includes('本机 sudo'), false);
  assert.equal(source.includes('运行 KINTSUGI'), false);
  assert.equal(source.includes('Stage 0—10'), false);
  assert.equal(source.includes('本地 Bridge 连接'), false);
  assert.equal(source.includes('subscribeToBridgeRun'), false);
});

test('reflows the console before browser zoom compresses it into three narrow columns', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(
    styles,
    /\.console \{ display: grid; grid-template-columns: minmax\(96px, \.22fr\) minmax\(0, 1\.45fr\) minmax\(220px, \.7fr\);/,
  );
  assert.match(styles, /@media \(max-width: 900px\)[\s\S]*?\.console \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\) minmax\(220px, \.55fr\);[\s\S]*?grid-template-rows: auto minmax\(0, 1fr\);/);
  assert.match(styles, /@media \(max-width: 900px\)[\s\S]*?\.console-heading \{[\s\S]*?grid-column: 1 \/ -1;/);
  assert.match(styles, /\.console-heading, \.console-lines, \.console-finding \{ min-width: 0; \}/);
  assert.match(styles, /\.console-line > span \{ min-width: 0; overflow-wrap: anywhere; \}/);
});

test('fully stacks the console at the existing narrow-screen breakpoint', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.console \{ grid-template-columns: 1fr; grid-template-rows: auto; \}/);
});

test('uses a case header and tabbed single-workspace layout', () => {
  const source = readFileSync(pagePath, 'utf8');

  assert.match(source, /className="workspace-header"/);
  assert.match(source, /className="case-switcher"/);
  assert.match(source, /className="workspace-tabs"/);
  assert.match(source, /aria-label="案例工作区导航"/);
  assert.match(source, /id: 'flow', label: '演示流程'/);
  assert.match(source, /id: 'location', label: '漏洞定位'/);
  assert.match(source, /id: 'patch', label: '修补解析'/);
  assert.match(source, /id: 'comparison', label: '结果对比'/);
  assert.equal(source.includes("id: 'logs'"), false);
});

test('uses a fullscreen presentation workspace without prerecorded replay wording', () => {
  const source = readFileSync(pagePath, 'utf8');
  const presentationSource = readFileSync(new URL('../app/presentation-state.mjs', import.meta.url), 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.doesNotMatch(source, /预制|预先准备|回放/);
  assert.doesNotMatch(presentationSource, /预制|预先准备|回放/);
  assert.match(source, /运行轨迹/);
  assert.match(styles, /@media \(min-width: 1440px\) and \(min-height: 800px\)/);
  assert.match(styles, /height: calc\(100dvh - 232px\)/);
  assert.match(styles, /grid-template-rows: minmax\(0, 1fr\) 132px 24px/);
  assert.match(styles, /\.workspace-panel:not\(\[hidden\]\)/);
});

test('adds a clear Ghostscript principle primer to the flow page', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /ghostscript-primer/);
  assert.match(source, /漏洞原理速读/);
  assert.match(source, /文件扩展名不等于文件内容/);
  assert.match(source, /Pillow 把 EPS 交给 Ghostscript/);
  assert.match(source, /%pipe%/);
  assert.match(source, /\/tmp\/got_rce/);
  assert.match(source, /解释器启动前检查输入/);
  assert.match(styles, /\.ghostscript-primer/);
  assert.match(styles, /\.primer-flow-map/);
  assert.match(styles, /\.primer-point/);
});

test('reserves enough fullscreen header space to keep endpoint metadata above the tabs', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(styles, /\.workspace-header \{ height: 232px;/);
  assert.match(styles, /\.workspace-hero \{ min-height: 138px; height: 138px;/);
  assert.match(styles, /height: calc\(100dvh - 232px\)/);
});

test('places an independent demo control on every workspace page', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /function PageDemoButton/);
  assert.match(source, /view="flow"/);
  assert.match(source, /view="location"/);
  assert.match(source, /view="patch"/);
  assert.match(source, /view="comparison"/);
  assert.match(source, /演示本页/);
  assert.doesNotMatch(source, /开始演示/);
  assert.doesNotMatch(source, /handlePlaybackToggle/);
  assert.doesNotMatch(source, /action-playback/);
  assert.match(styles, /\.page-demo-button/);
});

test('aligns Ghostscript patch code with a right-side line explanation track', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /GHOSTSCRIPT_PATCH_EXPLANATIONS/);
  assert.match(source, /patch-code-layout/);
  assert.match(source, /code-analysis-track/);
  assert.match(source, /code-analysis-row/);
  assert.match(source, /%pipe% 是触发系统命令的危险操作符/);
  assert.match(styles, /\.patch-code-layout\.has-analysis/);
  assert.match(styles, /grid-template-columns: minmax\(0, 1\.08fr\) minmax\(360px, \.92fr\)/);
  assert.match(styles, /\.code-analysis-row \{ min-height: 34px;/);
});

test('expands the Ghostscript implementation note with a right-side repair flowchart', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /repair-explainer-grid/);
  assert.match(source, /repair-flowchart/);
  assert.match(source, /读取 EPS 原始字节/);
  assert.match(source, /启动 Ghostscript 前/);
  assert.match(source, /BPF LSM/);
  assert.match(source, /正常图片继续渲染/);
  assert.match(source, /恶意样本提前拒绝/);
  assert.match(styles, /\.repair-explainer-grid \{ display: grid; grid-template-columns: minmax\(0, \.9fr\) minmax\(520px, 1\.1fr\);/);
  assert.match(styles, /\.repair-flowchart/);
  assert.match(styles, /\.flowchart-branch/);
});

test('renders synchronized playback logs as a dock instead of a separate workspace page', () => {
  const source = readFileSync(pagePath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(source, /同步终端输出/);
  assert.match(source, /playback-terminal/);
  assert.match(source, /playbackSnapshot\.logs/);
  assert.match(styles, /\.playback-terminal/);
  assert.match(styles, /\.playback-progress/);
});

test('never changes the page scroll position automatically', () => {
  const source = readFileSync(pagePath, 'utf8');

  assert.doesNotMatch(source, /scrollIntoView/);
  assert.doesNotMatch(source, /scrollTo/);
  assert.doesNotMatch(source, /scrollBy/);
  assert.doesNotMatch(source, /logEnd/);
});

test('keeps the case controls and workspace navigation visible on desktop', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(styles, /\.workspace-header \{[\s\S]*?position: sticky;[\s\S]*?top: 0;/);
  assert.match(styles, /\.workspace-tabs \{[\s\S]*?position: sticky;/);
  assert.match(styles, /\.workspace-panel\[hidden\] \{ display: none; \}/);
  assert.match(styles, /\.workspace-stage \{[\s\S]*?min-height: calc\(100vh -/);
});

test('turns the case switcher and workspace tabs into horizontal scrollers on narrow screens', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.case-switcher,[\s\S]*?\.workspace-tabs \{[\s\S]*?overflow-x: auto;/);
  assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.workspace-hero \{[\s\S]*?grid-template-columns: 1fr;/);
});

test('uses a readable type scale for captions, body copy, controls, code, and logs', () => {
  const styles = readFileSync(stylesPath, 'utf8');

  assert.match(styles, /--font-caption: 11px;/);
  assert.match(styles, /--font-body: 13px;/);
  assert.match(styles, /--font-control: 13px;/);
  assert.match(styles, /--font-code: 11\.5px;/);
  assert.match(styles, /\.workspace-tabs button span \{[\s\S]*?font-size: var\(--font-control\);/);
  assert.match(styles, /\.path-lane p \{[\s\S]*?font-size: var\(--font-body\);/);
  assert.match(styles, /\.code-line code \{[\s\S]*?font: 500 var\(--font-code\)/);
  assert.match(styles, /\.console-line \{[\s\S]*?font: 500 var\(--font-code\)/);
  assert.match(styles, /\.wordmark small \{[\s\S]*?font-size: var\(--font-caption\);/);
  assert.match(styles, /\.footnote p \{[\s\S]*?font-size: var\(--font-caption\);/);
  assert.match(styles, /\.footnote span \{[\s\S]*?font: 500 var\(--font-caption\)/);
  assert.doesNotMatch(styles, /font-size:\s*[789]px/);
  assert.doesNotMatch(styles, /font:\s*[^;]*\s[789]px(?:\s|\/)/);
  assert.doesNotMatch(styles, /font-size:\s*10px/);
  assert.doesNotMatch(styles, /font:\s*[^;]*\s10px(?:\s|\/)/);
});
