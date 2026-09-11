import { CVE_2018_16509_REPORT_DATA } from './cve-2018-report-data.mjs';

export const CVE_PROFILES = {
  'CVE-2022-46169': {
    product: 'Cacti 1.2.22',
    language: 'PHP 7.4',
    severity: 'CRITICAL 9.8',
    category: '命令注入',
    port: 'localhost:8080',
    headline: '伪造可信来源，越过认证边界执行系统命令',
    summary: '攻击者构造 poller_id 参数并伪造来源地址，让 Cacti 将外部输入带入命令执行链。',
    endpoint: 'GET /remote_agent.php?action=polldata',
    evidence: '容器内出现 /tmp/kintsugi_marker',
    blockedEvidence: '命令参数偏离运行时白名单，请求在危险调用前终止',
    normalEvidence: '授权轮询请求返回 200，数据采集链路可用',
    targetFunction: 'poll_for_data()',
    repairLocation: 'remote_agent.php · poller command branch',
    dangerCall: 'proc_open → /bin/sh',
    evidenceView: {
      kind: 'command',
      eyebrow: 'COMMAND PATH',
      title: '一条参数如何抵达系统命令',
      specimen: {
        label: '恶意参数',
        value: 'poller_id=1; touch /tmp/kintsugi_marker',
        meta: '外部输入被拼接到 poller 命令',
      },
      steps: [
        { label: '来源边界', value: '伪造可信请求来源' },
        { label: '参数拼接', value: 'poller_id → command' },
        { label: '危险调用', value: 'proc_open → /bin/sh' },
      ],
      facts: [
        { label: '入口', value: 'remote_agent.php' },
        { label: '执行证据', value: '/tmp/kintsugi_marker' },
        { label: '正常基线', value: 'poller data · 200' },
      ],
      requestFields: [
        { label: '伪造来源头', value: 'X-Forwarded-For: 127.0.0.1', tone: 'identity' },
        { label: '动作入口', value: 'action=polldata&host_id=1', tone: 'route' },
        { label: '危险参数', value: 'poller_id=1; touch /tmp/kintsugi_marker', tone: 'danger' },
      ],
      boundaries: [
        {
          label: '可信来源边界',
          before: '代理头被当作可信 poller 身份',
          after: '来源校验回到服务端信任配置',
        },
        {
          label: '命令执行边界',
          before: 'poller_id 字符串进入命令拼接',
          after: '偏离白名单的命令参数被拒绝',
        },
      ],
      processChain: ['apache2', 'php-fpm', '/bin/sh', 'touch'],
      insight: 'HTTP 200 不等于安全',
      markerFile: {
        directory: '/tmp',
        name: 'kintsugi_marker',
        path: '/tmp/kintsugi_marker',
        size: '0B',
        createdBy: 'touch',
      },
      evidenceRows: [
        {
          key: 'http',
          label: 'HTTP 响应',
          before: '200 OK · 但命令已执行',
          ready: '等待相同请求复测',
          after: '请求完成 · 危险调用未发生',
        },
        {
          key: 'marker',
          label: '副作用文件',
          before: '/tmp/kintsugi_marker present',
          ready: '待验证',
          after: '/tmp/kintsugi_marker absent',
        },
        {
          key: 'normal',
          label: '正常轮询',
          before: '未纳入修补前判断',
          ready: '策略已写入，等待验证',
          after: 'poller data · 200 OK',
        },
      ],
      beforeSignal: 'marker · present',
      afterSignal: 'marker · absent',
    },
    patch: {
      source: 'remote_agent.php · poller command branch',
      lines: [
        { no: '342', kind: 'plain', code: 'function poll_for_data($input) {' },
        { no: '343', kind: 'remove', code: '  $command = build_command($input);' },
        { no: '343', kind: 'add', step: 1, code: "  $policy = Kintsugi::guard('poll_for_data');" },
        { no: '344', kind: 'add', step: 2, code: '  $policy->assertAllowed($input);' },
        { no: '345', kind: 'add', step: 3, code: '  $command = build_command($policy->sanitize($input));' },
        { no: '346', kind: 'add', step: 4, code: '  return $policy->execute($command);' },
        { no: '347', kind: 'plain', code: '}' },
      ],
    },
    attackLogs: [
      '[lab] 目标 cve-2022-46169-web · 127.0.0.1:8080',
      '[poc] 注入 poller_id="1; touch /tmp/kintsugi_marker"',
      '[http] GET /remote_agent.php?action=polldata → 200 OK',
      '[verify] docker exec · marker file detected',
    ],
    blockedLogs: [
      '[lab] 复用完全相同的请求与注入参数',
      '[policy] poll_for_data() 命中运行时参数约束',
      '[block] proc_open 调用被拒绝 · policy=kintsugi-7f2a',
      '[verify] marker file absent · normal poll request 200 OK',
    ],
    repairLogs: [
      '[stage 2] 采集正常与恶意流量的运行时轨迹',
      '[stage 7] 差分定位 poll_for_data() 的危险命令分支',
      '[stage 8] 生成参数约束与系统调用过滤策略',
      '[stage 10] 恶意用例被阻断，正常轮询保持可用',
    ],
    syscalls: { before: [32, 20, 18, 9, 4, 2], after: [30, 20, 18, 0, 3, 2] },
  },
  'CVE-2018-16509': {
    product: 'Ghostscript 9.23',
    language: 'Python',
    severity: 'CRITICAL 9.8',
    category: '恶意文件 RCE',
    port: 'localhost:8000',
    headline: '伪装成图片的 EPS 载荷突破安全模式执行命令',
    summary: '伪装成 JPG 的 EPS 内容进入 Pillow 的 Ghostscript 路径，%pipe% 载荷进一步触发 touch /tmp/got_rce。',
    endpoint: 'POST / · multipart image upload',
    evidence: '容器内出现 /tmp/got_rce，证明 payload 命令已执行',
    blockedEvidence: '恶意 EPS 返回 HTTP 500，/tmp/got_rce 未创建',
    normalEvidence: '正常图片返回 HTTP 200 · 1653 bytes',
    targetFunction: 'PIL.EpsImagePlugin.Ghostscript',
    repairLocation: 'PIL/EpsImagePlugin.py · Ghostscript()',
    dangerCall: 'subprocess.check_call → gs / unexpected command',
    reportData: CVE_2018_16509_REPORT_DATA,
    evidenceView: {
      kind: 'file',
      eyebrow: 'FILE PATH',
      title: '伪装图片如何越过解析边界',
      specimen: {
        label: '上传样本',
        value: 'rce.jpg · JPEG MIME / EPS payload',
        meta: '扩展名与实际解析内容不一致',
      },
      steps: [
        { label: '文件入口', value: 'multipart image upload' },
        { label: '解释边界', value: 'Ghostscript 9.23' },
        { label: '危险行为', value: 'EPS payload → execve' },
      ],
      facts: [
        { label: '表面类型', value: 'image/jpeg' },
        { label: '真实载荷', value: 'PostScript 指令' },
        { label: '正常基线', value: 'normal.jpg · converted' },
      ],
      uploadFields: [
        { label: '表面文件名', value: 'rce.jpg', tone: 'identity' },
        { label: '声明类型', value: 'Content-Type: image/jpeg', tone: 'route' },
        { label: '真实载荷', value: 'EPS / PostScript operators', tone: 'danger' },
      ],
      boundaries: [
        {
          label: '文件身份边界',
          before: '扩展名与 MIME 让样本进入图片处理链',
          after: '文件内容与解析器选择被策略约束',
        },
        {
          label: '子进程行为边界',
          before: 'Ghostscript 解析后出现非预期 execve',
          after: '输入包含 %pipe% 时在启动 Ghostscript 前拒绝',
        },
      ],
      processChain: ['flask', 'pillow', 'gs', 'execve'],
      insight: '文件扩展名不等于解析内容',
      evidenceRows: [
        {
          key: 'upload',
          label: '上传结果',
          before: 'rce.jpg accepted · enters converter',
          ready: '等待相同文件复测',
          after: 'same file rejected at policy boundary',
        },
        {
          key: 'process',
          label: '子进程行为',
          before: 'touch /tmp/got_rce · marker present',
          ready: '待验证',
          after: 'HTTP 500 · marker absent',
        },
        {
          key: 'normal',
          label: '正常转换',
          before: 'normal.jpg baseline available',
          ready: '策略已写入，等待验证',
          after: 'normal.jpg converted successfully',
        },
      ],
      beforeSignal: '/tmp/got_rce · present',
      afterSignal: '/tmp/got_rce · absent',
    },
    patch: {
      source: 'PIL/EpsImagePlugin.py · Ghostscript()',
      lines: [
        { no: '143', kind: 'plain', code: 'def Ghostscript(tile, size, fp, scale=1):' },
        { no: '144', kind: 'add', step: 1, code: "    with open(infile, 'rb') as eps_file:" },
        { no: '145', kind: 'add', step: 2, code: "        if b'%pipe%' in eps_file.read():" },
        { no: '146', kind: 'add', step: 3, code: "            raise IOError('unsafe EPS file')" },
        { no: '147', kind: 'plain', code: '    # normal Ghostscript rendering remains available' },
        { no: '148', kind: 'add', step: 4, code: '    subprocess.check_call(command, stdin=devnull, stdout=devnull)' },
      ],
    },
    attackLogs: [
      '[lab] 目标 cve-2018-16509-env · 127.0.0.1:8000',
      '[stage 2] 29 个正常请求 / 11 个恶意请求 · 0 failed',
      '[stage 3] normal 29,588 events / malicious 9,119 events',
      '[poc] %pipe%touch /tmp/got_rce · marker present',
    ],
    blockedLogs: [
      '[policy] execve 仅允许 /usr/local/bin/gs 与 /usr/local/sbin/gs',
      '[stage 10] WSL2 限制 · 使用 %pipe% 输入检查完成最终验证',
      '[verify] normal HTTP 200 · 1653 bytes / malicious HTTP 500 · /tmp/got_rce absent',
      '[result] normal_ok=true · malicious_blocked=true · success=true · 76.11 s',
    ],
    repairLogs: [
      '[stage 4] 请求单元切分完成 · 40 units',
      '[stage 5] 调用栈恢复完成 · 40 JSONL',
      '[stage 7] PIL.EpsImagePlugin.Ghostscript · score=1.000 · 11/11 排名第一',
      '[stage 9] 14 normal samples · 6,844 syscalls · 10 类 syscall',
    ],
    syscalls: { before: [44, 36, 26, 7, 5, 3], after: [42, 34, 25, 0, 4, 3] },
  },
  'CVE-2024-25737': {
    product: 'VuFind',
    language: 'PHP 8.1',
    severity: 'HIGH 8.2',
    category: '服务端请求伪造',
    port: 'localhost:8081',
    headline: '借助封面代理参数跨越网络边界读取内网服务',
    summary: '攻击者控制 Cover/Show 的 proxy 参数，诱导服务器请求仅容器网络可见的内部 API。',
    endpoint: 'GET /vufind/Cover/Show?proxy=…',
    evidence: '响应泄露 Internal API 与敏感配置标记',
    blockedEvidence: '目标地址不在网络白名单，内部连接建立前被拒绝',
    normalEvidence: '合法外部封面请求仍可访问并返回图像',
    targetFunction: 'getImageFromProxy()',
    repairLocation: 'CoverController.php · proxy fetch path',
    dangerCall: 'curl_exec → internal network',
    evidenceView: {
      kind: 'network',
      eyebrow: 'NETWORK PATH',
      title: '一个代理参数如何跨越网络边界',
      specimen: {
        label: '目标参数',
        value: 'proxy=http://127.0.0.1:3306',
        meta: '服务端代替攻击者访问本机端口',
      },
      steps: [
        { label: '用户输入', value: 'Cover/Show?proxy=…' },
        { label: '服务端解析', value: 'URL → loopback address' },
        { label: '内部连接', value: '127.0.0.1:3306' },
      ],
      facts: [
        { label: '目标网段', value: 'loopback / private' },
        { label: '暴露服务', value: 'MySQL · 3306' },
        { label: '正常基线', value: 'public cover · available' },
      ],
      proxyFields: [
        { label: '用户参数', value: 'proxy=http://cve-2024-25737-internal/secret.json', tone: 'identity' },
        { label: '解析目标', value: 'container network · private host', tone: 'route' },
        { label: '内部服务', value: 'internal-api · sensitive marker', tone: 'danger' },
      ],
      boundaries: [
        {
          label: 'URL 信任边界',
          before: '用户提供的 proxy URL 被服务端直接采信',
          after: '协议、主机与解析后地址进入策略检查',
        },
        {
          label: '网络出口边界',
          before: 'curl 从服务端网络连接内部资源',
          after: 'private-network destination 在 connect 前拒绝',
        },
      ],
      processChain: ['browser', 'vufind', 'curl', 'internal-api'],
      insight: '服务端可达不等于用户可达',
      evidenceRows: [
        {
          key: 'response',
          label: '响应内容',
          before: '200 OK · contains ssrf_confirmed / API_KEY',
          ready: '等待相同 proxy 复测',
          after: 'sensitive marker absent',
        },
        {
          key: 'destination',
          label: '网络目标',
          before: 'internal container host reached',
          ready: '待验证',
          after: 'private destination denied before connect',
        },
        {
          key: 'normal',
          label: '公开封面',
          before: 'public cover baseline available',
          ready: '策略已写入，等待验证',
          after: 'public cover request still available',
        },
      ],
      beforeSignal: 'internal response · exposed',
      afterSignal: 'connect · denied',
    },
    patch: {
      source: 'CoverController.php · proxy fetch path',
      lines: [
        { no: '118', kind: 'plain', code: 'function getImageFromProxy($url) {' },
        { no: '119', kind: 'remove', code: '  return curl_exec($url);' },
        { no: '119', kind: 'add', step: 1, code: "  $policy = Kintsugi::guard('cover_proxy');" },
        { no: '120', kind: 'add', step: 2, code: '  $policy->assertNetworkTarget($url);' },
        { no: '121', kind: 'add', step: 3, code: '  $safeUrl = $policy->sanitizeUrl($url);' },
        { no: '122', kind: 'add', step: 4, code: '  return $policy->fetch($safeUrl);' },
        { no: '123', kind: 'plain', code: '}' },
      ],
    },
    attackLogs: [
      '[lab] 目标 cve-2024-25737-env · 127.0.0.1:8081',
      '[poc] proxy=http://cve-2024-25737-internal/secret.json',
      '[http] 服务端连接容器内网目标 → 200 OK',
      '[verify] response contains ssrf_confirmed / API_KEY',
    ],
    blockedLogs: [
      '[lab] 复用完全相同的内部服务 URL',
      '[policy] getImageFromProxy() 命中网络目标约束',
      '[block] private-network destination denied before connect',
      '[verify] sensitive marker absent · public cover request available',
    ],
    repairLogs: [
      '[stage 2] 采集公开封面与内网目标的连接轨迹',
      '[stage 7] 定位 getImageFromProxy() 的目标差异',
      '[stage 8] 生成协议、主机与网段访问策略',
      '[stage 10] 内网请求被拒绝，公开封面仍可获取',
    ],
    syscalls: { before: [24, 18, 20, 1, 12, 2], after: [23, 18, 20, 1, 3, 2] },
  },
};

export function createInitialState(cve = 'CVE-2022-46169') {
  if (!CVE_PROFILES[cve]) {
    throw new Error(`Unknown CVE profile: ${cve}`);
  }

  return {
    cve,
    repairStatus: 'vulnerable',
    phase: 'ready',
    progress: 0,
    pipelineStage: -1,
    result: null,
    normalVerified: false,
    logs: [],
    attackBaseStatus: null,
    patchStep: 0,
    baselineObserved: false,
  };
}

export function isBusy(state) {
  return state.repairStatus === 'attacking' || state.repairStatus === 'repairing';
}

export function transitionDemo(state, event) {
  switch (event.type) {
    case 'SELECT_CVE':
      return createInitialState(event.cve);
    case 'RESET':
      return createInitialState(state.cve);
    case 'LOG_APPEND':
      return { ...state, logs: [...state.logs, event.line] };
    case 'ATTACK_START':
      if (isBusy(state)) return state;
      return {
        ...state,
        repairStatus: 'attacking',
        phase: 'attacking',
        result: null,
        normalVerified: false,
        attackBaseStatus: state.repairStatus,
      };
    case 'ATTACK_COMPLETE': {
      const wasRepaired = state.attackBaseStatus === 'repaired';
      return {
        ...state,
        repairStatus: wasRepaired ? 'repaired' : 'vulnerable',
        phase: wasRepaired ? 'verified' : 'exposed',
        result: wasRepaired ? 'blocked' : 'breached',
        normalVerified: wasRepaired,
        attackBaseStatus: null,
        baselineObserved: wasRepaired ? state.baselineObserved : true,
      };
    }
    case 'REPAIR_START':
      if (isBusy(state) || !state.baselineObserved) return state;
      return {
        ...state,
        repairStatus: 'repairing',
        phase: 'repairing',
        progress: 4,
        pipelineStage: 0,
        result: null,
        normalVerified: false,
        logs: [],
        patchStep: 0,
      };
    case 'REPAIR_PROGRESS':
      if (state.repairStatus !== 'repairing') return state;
      return {
        ...state,
        progress: Math.max(0, Math.min(100, event.progress)),
        pipelineStage: Math.max(0, Math.min(3, event.stage)),
      };
    case 'REPAIR_COMPLETE':
      return {
        ...state,
        repairStatus: 'repaired',
        phase: 'repaired',
        progress: 100,
        pipelineStage: 3,
        result: null,
        attackBaseStatus: null,
        patchStep: 4,
      };
    case 'REPAIR_FAILED':
      return {
        ...state,
        repairStatus: 'vulnerable',
        phase: 'exposed',
        progress: 0,
        pipelineStage: -1,
        result: 'breached',
        normalVerified: false,
        attackBaseStatus: null,
        patchStep: 0,
      };
    case 'PATCH_PROGRESS':
      if (state.repairStatus !== 'repairing') return state;
      return {
        ...state,
        patchStep: Math.max(0, Math.min(4, event.step)),
      };
    default:
      return state;
  }
}
