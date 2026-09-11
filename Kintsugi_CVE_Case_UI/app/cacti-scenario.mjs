// Teaching scenarios derived from cves/php/CVE-2022-46169/{normal,validate}.py.
// These are expected paths, not captured execution results.
export const CACTI_STEPS = ['接收请求', '判断来源', '进入业务分支', '检查副作用'];
export const CACTI_SCENARIOS = [
  { id: 'normal', title: '正常轮询', subtitle: '合法参数 · 原有业务', branch: 'action=1',
    details: ['轮询请求携带合法 poller_id，读取指定采集项。', '测试使用本地 poller 的来源头；来源声明本身不等于可信身份。', '正常测试数据走 action=1 的采集分支，不覆盖含 proc_open 的 action=2 分支。', '预期返回采集数据，且没有攻击标记。是否通过仍需检查真实响应和容器记录。'],
    result: '采集结果正常返回', marker: 'absent' },
  { id: 'attack', title: '恶意请求', subtitle: '未修补 · 参数越界', branch: 'action=2',
    details: ['同一 polldata 接口收到伪造来源头与带命令片段的 poller_id。', '在漏洞条件下，外部来源声明被误信任，请求进入本应受限的轮询处理。', '测试项进入 action=2 分支；不安全的参数拼接让 poller_id 越过数据与命令的边界。', '若附加命令执行成功，/tmp 中会新增 kintsugi_marker。HTTP 200 不能代替这项检查。'],
    result: '出现额外文件', marker: 'present' },
  { id: 'protected', title: '修补后恶意请求', subtitle: '相同输入 · 危险调用受限', branch: 'action=2',
    details: ['复用恶意请求，保持来源头、采集项和 poller_id 不变。', '来源判断仍按原请求展示；运行时限制不代表来源认证本身已被修好。', '防护方案在危险调用前约束参数或执行行为。此处仅示意拦截位置，具体实现需以修补产物为准。', '预期不再新增攻击标记。还要结合调用轨迹、清理记录和正常业务复测，才能确认防护有效。'],
    result: '未新增攻击标记', marker: 'absent' },
];

export function cactiSnapshot(mode, phase) {
  const scenario = CACTI_SCENARIOS.find((item) => item.id === mode) ?? CACTI_SCENARIOS[0];
  const step = Number.isFinite(phase) ? Math.max(0, Math.min(4, Math.floor(phase))) : 0;
  return { ...scenario, phase: step, measured: false,
    marker: step === 4 ? scenario.marker : 'pending',
    blocked: scenario.id === 'protected' && step >= 3,
    logs: scenario.details.slice(0, step).map((detail, index) => `[路径示意 · ${index + 1}/4] ${detail}`),
    finding: step ? scenario.details[step - 1] : '选择一种请求，点击“演示本页”或下方步骤查看路径。',
  };
}
