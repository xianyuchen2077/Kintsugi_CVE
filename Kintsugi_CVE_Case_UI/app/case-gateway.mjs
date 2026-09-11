// Backend boundary for the Case UI. Frontend replays and the local HTTP/SSE
// Bridge use the same operation and event vocabulary.

export const CASE_API_CONTRACT = Object.freeze({
  version: 1,
  actions: Object.freeze({
    attack: Object.freeze({ method: 'POST', path: '/api/cases/:cve/attack' }),
    repair: Object.freeze({ method: 'POST', path: '/api/cases/:cve/repair' }),
    reset: Object.freeze({ method: 'POST', path: '/api/cases/:cve/reset' }),
    validate: Object.freeze({ method: 'POST', path: '/api/cases/:cve/validate' }),
    evidence: Object.freeze({ method: 'POST', path: '/api/cases/:cve/evidence' }),
    upload: Object.freeze({ method: 'POST', path: '/api/cases/:cve/upload', body: 'multipart/form-data' }),
    events: Object.freeze({ method: 'GET', path: '/api/cases/:cve/events', transport: 'sse' }),
  }),
  events: Object.freeze(['log', 'progress', 'patch', 'complete', 'error']),
});

const MOCK_TIMING = Object.freeze({
  attackLog: 520,
  attackComplete: 380,
  repairStep: 820,
  repairComplete: 620,
});

const REPAIR_PROGRESS = Object.freeze([18, 44, 72, 96]);
const LOCAL_CASES = new Set([
  'CVE-2022-46169',
  'CVE-2018-16509',
  'CVE-2024-25737',
]);
const BRIDGE_STAGE_MAP = Object.freeze({
  2: Object.freeze({ progress: 18, stage: 0, patchStep: 1 }),
  7: Object.freeze({ progress: 44, stage: 1, patchStep: 2 }),
  8: Object.freeze({ progress: 72, stage: 2, patchStep: 3 }),
  10: Object.freeze({ progress: 96, stage: 3, patchStep: 4 }),
});

export function supportsLocalBridge(cve) {
  return LOCAL_CASES.has(cve);
}

export function supportsSecureSudoBridge(health) {
  return health?.capabilities?.secure_sudo_stdin === true;
}

export function buildBridgeRunRequest(cve, sudoPassword = '') {
  const request = {
    cve,
    start_stage: 0,
    end_stage: 10,
    collector: 'auto',
    model: 'deepseek-chat',
    max_repairs: 1,
    threshold: 0.5,
    repair_mode: 'filter',
    validate_mode: 'all',
    normal_time: 60,
    malicious_time: 20,
    wait_time: 60,
    min_files: 10,
    whitelist_mode: 'static',
    algo: ['all'],
    log_mode: 'append',
  };

  return sudoPassword ? { ...request, sudo_password: sudoPassword } : request;
}

export function mapBridgeLogToRepairEvent(line) {
  const match = /Stage\s+(2|7|8|10)\b/i.exec(line);
  return match ? BRIDGE_STAGE_MAP[Number(match[1])] : null;
}

async function readBridgeResponse(response, action) {
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.detail || `${action} failed with HTTP ${response.status || 'error'}`);
  }
  return data;
}

export function createLocalBridgeClient({
  baseUrl = 'http://127.0.0.1:8765',
  fetchImpl = globalThis.fetch,
} = {}) {
  const base = baseUrl.replace(/\/$/, '');

  async function request(path, init) {
    const response = await fetchImpl(`${base}${path}`, init);
    return readBridgeResponse(response, path);
  }

  function postCaseProgram(cve, program, body = {}) {
    const caseId = encodeURIComponent(cve);
    return request(`/cases/${caseId}/${program}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  return Object.freeze({
    baseUrl: base,
    health: () => request('/health'),
    attack: (cve, options = {}) => postCaseProgram(cve, 'attack', options),
    validate: (cve, options = {}) => postCaseProgram(cve, 'validate', options),
    inspectEvidence: (cve, options = {}) => postCaseProgram(cve, 'evidence', options),
    reset: (cve, options = {}) => postCaseProgram(cve, 'reset', options),
    uploadFile(cve, file, options = {}) {
      const caseId = encodeURIComponent(cve);
      const form = new FormData();
      form.append('file', file, file.name || 'upload.bin');
      form.append('repaired', String(options.repaired === true));
      return request(`/cases/${caseId}/upload`, { method: 'POST', body: form });
    },
    async submitRepair(cve, sudoPassword = '') {
      const body = buildBridgeRunRequest(cve, sudoPassword);
      const init = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      };
      const preflight = await request('/preflight', init);
      if (!preflight.ready) throw new Error('Local Bridge preflight did not pass');
      return request('/runs', init);
    },
  });
}

export function subscribeToBridgeRun({
  baseUrl,
  eventsUrl,
  onEvent,
  signal,
  EventSourceImpl = globalThis.EventSource,
}) {
  return new Promise((resolve, reject) => {
    const url = new URL(eventsUrl, `${baseUrl.replace(/\/$/, '')}/`).toString();
    const source = new EventSourceImpl(url);
    let settled = false;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      source.close();
      signal?.removeEventListener('abort', abort);
      if (error) reject(error);
      else resolve();
    };

    const parse = (message) => JSON.parse(message.data || '{}');
    const abort = () => finish(new Error('Local Bridge run cancelled'));

    source.addEventListener('log', (message) => {
      const { line = '' } = parse(message);
      onEvent({ type: 'log', line });
      const stageEvent = mapBridgeLogToRepairEvent(line);
      if (stageEvent) onEvent({ type: 'repair-step', line, ...stageEvent });
    });

    source.addEventListener('error', (message) => {
      const data = parse(message);
      const error = new Error(data.message || 'Local Bridge run failed');
      finish(error);
    });

    source.addEventListener('status', (message) => {
      const data = parse(message);
      if (data.status === 'succeeded') {
        onEvent({ type: 'complete', result: 'repaired' });
        finish();
      } else if (data.status === 'failed' || data.status === 'cancelled') {
        const error = new Error(`Local Bridge run ${data.status}`);
        finish(error);
      }
    });

    source.onerror = () => finish(new Error('Local Bridge event stream disconnected'));
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
  });
}

export function getCaseEndpoints(cve) {
  const caseId = encodeURIComponent(cve);
  const base = `/api/cases/${caseId}`;

  return {
    attack: `${base}/attack`,
    repair: `${base}/repair`,
    reset: `${base}/reset`,
    validate: `${base}/validate`,
    evidence: `${base}/evidence`,
    upload: `${base}/upload`,
    events: `${base}/events`,
  };
}

export function createAttackRun(profile, repaired) {
  const lines = repaired ? profile.blockedLogs : profile.attackLogs;

  return {
    operation: 'attack',
    events: [
      ...lines.map((line) => ({ type: 'log', line, delay: MOCK_TIMING.attackLog })),
      { type: 'complete', result: repaired ? 'blocked' : 'breached', delay: MOCK_TIMING.attackComplete },
    ],
  };
}

export function createRepairRun(profile) {
  return {
    operation: 'repair',
    events: [
      ...profile.repairLogs.map((line, index) => ({
        type: 'repair-step',
        line,
        progress: REPAIR_PROGRESS[index] ?? 96,
        stage: index,
        patchStep: index + 1,
        delay: MOCK_TIMING.repairStep,
      })),
      { type: 'complete', result: 'repaired', delay: MOCK_TIMING.repairComplete },
    ],
  };
}

export function createResetRun() {
  return {
    operation: 'reset',
    events: [{ type: 'complete', result: 'reset', delay: 0 }],
  };
}

export const caseGateway = Object.freeze({
  mode: 'mock',
  attack: createAttackRun,
  repair: createRepairRun,
  reset: createResetRun,
  endpoints: getCaseEndpoints,
});
