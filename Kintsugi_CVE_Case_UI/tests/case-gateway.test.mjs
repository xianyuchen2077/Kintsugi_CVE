import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const gatewayPath = fileURLToPath(new URL('../app/case-gateway.mjs', import.meta.url));

test('keeps the backend gateway in a dedicated module', () => {
  assert.equal(existsSync(gatewayPath), true);
});

test('defines stable backend endpoints for every case action', async () => {
  const { CASE_API_CONTRACT, getCaseEndpoints } = await import('../app/case-gateway.mjs');
  const endpoints = getCaseEndpoints('CVE-2022-46169');

  assert.deepEqual(CASE_API_CONTRACT.events, ['log', 'progress', 'patch', 'complete', 'error']);
  assert.deepEqual(Object.keys(CASE_API_CONTRACT.actions), ['attack', 'repair', 'reset', 'validate', 'evidence', 'upload', 'events']);
  assert.deepEqual(endpoints, {
    attack: '/api/cases/CVE-2022-46169/attack',
    repair: '/api/cases/CVE-2022-46169/repair',
    reset: '/api/cases/CVE-2022-46169/reset',
    validate: '/api/cases/CVE-2022-46169/validate',
    evidence: '/api/cases/CVE-2022-46169/evidence',
    upload: '/api/cases/CVE-2022-46169/upload',
    events: '/api/cases/CVE-2022-46169/events',
  });
});

test('creates transport-neutral attack events', async () => {
  const { createAttackRun } = await import('../app/case-gateway.mjs');
  const profile = {
    attackLogs: ['attack-1', 'attack-2'],
    blockedLogs: ['blocked-1'],
  };

  const exposed = createAttackRun(profile, false);
  const blocked = createAttackRun(profile, true);

  assert.deepEqual(exposed.events.map((event) => event.type), ['log', 'log', 'complete']);
  assert.equal(exposed.events.at(-1).result, 'breached');
  assert.equal(blocked.events.at(-1).result, 'blocked');
});

test('creates repair events with progress and patch updates', async () => {
  const { createRepairRun } = await import('../app/case-gateway.mjs');
  const run = createRepairRun({ repairLogs: ['collect', 'detect', 'generate', 'verify'] });

  assert.equal(run.events.length, 5);
  assert.deepEqual(run.events[2], {
    type: 'repair-step',
    line: 'generate',
    progress: 72,
    stage: 2,
    patchStep: 3,
    delay: 820,
  });
  assert.deepEqual(run.events.at(-1), { type: 'complete', result: 'repaired', delay: 620 });
});

test('keeps reset behind the same transport boundary', async () => {
  const { createResetRun } = await import('../app/case-gateway.mjs');

  assert.deepEqual(createResetRun(), {
    operation: 'reset',
    events: [{ type: 'complete', result: 'reset', delay: 0 }],
  });
});

test('exposes one swappable gateway object to the page', async () => {
  const { caseGateway } = await import('../app/case-gateway.mjs');

  assert.equal(caseGateway.mode, 'mock');
  assert.deepEqual(
    ['attack', 'repair', 'reset', 'endpoints'].map((method) => typeof caseGateway[method]),
    ['function', 'function', 'function', 'function'],
  );
});

test('enables the local bridge for all three cases', async () => {
  const { supportsLocalBridge } = await import('../app/case-gateway.mjs');

  assert.equal(supportsLocalBridge('CVE-2022-46169'), true);
  assert.equal(supportsLocalBridge('CVE-2018-16509'), true);
  assert.equal(supportsLocalBridge('CVE-2024-25737'), true);
});

test('builds the existing bridge run payload without persisting credentials', async () => {
  const { buildBridgeRunRequest } = await import('../app/case-gateway.mjs');

  assert.deepEqual(buildBridgeRunRequest('CVE-2022-46169', ''), {
    cve: 'CVE-2022-46169',
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
  });
  assert.equal(buildBridgeRunRequest('CVE-2022-46169', 'secret').sudo_password, 'secret');
});

test('preserves each case identifier in bridge repair requests', async () => {
  const { buildBridgeRunRequest } = await import('../app/case-gateway.mjs');

  for (const cve of ['CVE-2022-46169', 'CVE-2018-16509', 'CVE-2024-25737']) {
    assert.equal(buildBridgeRunRequest(cve).cve, cve);
  }
});

test('maps bridge stage logs onto the four UI repair stages', async () => {
  const { mapBridgeLogToRepairEvent } = await import('../app/case-gateway.mjs');

  assert.deepEqual(mapBridgeLogToRepairEvent('Stage 2: collect runtime trace'), {
    progress: 18,
    stage: 0,
    patchStep: 1,
  });
  assert.deepEqual(mapBridgeLogToRepairEvent('Stage 8: repair policy generated'), {
    progress: 72,
    stage: 2,
    patchStep: 3,
  });
  assert.equal(mapBridgeLogToRepairEvent('ordinary stdout line'), null);
});

test('checks the bridge, preflights, and submits a repair run', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.endsWith('/health')) return { ok: true, json: async () => ({ status: 'ok', docker: true }) };
    if (url.endsWith('/preflight')) return { ok: true, json: async () => ({ ready: true, warnings: 2 }) };
    return { ok: true, json: async () => ({ run_id: 'RUN-1', events_url: '/runs/RUN-1/events' }) };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765/', fetchImpl });

  const health = await client.health();
  const run = await client.submitRepair('CVE-2022-46169', 'secret');

  assert.equal(health.status, 'ok');
  assert.equal(run.run_id, 'RUN-1');
  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/health',
    'http://127.0.0.1:8765/preflight',
    'http://127.0.0.1:8765/runs',
  ]);
  assert.equal(JSON.parse(calls[2].init.body).sudo_password, 'secret');
});

test('accepts only bridge runtimes that advertise secure sudo stdin', async () => {
  const { supportsSecureSudoBridge } = await import('../app/case-gateway.mjs');

  assert.equal(supportsSecureSudoBridge({ capabilities: { secure_sudo_stdin: true } }), true);
  assert.equal(supportsSecureSudoBridge({ capabilities: { secure_sudo_stdin: false } }), false);
  assert.equal(supportsSecureSudoBridge({ status: 'ok', version: '0.1.0' }), false);
});

test('calls optional bridge case programs through explicit attack, reset, and validate methods', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    return { ok: true, json: async () => ({ ok: true, events: [{ type: 'complete', result: 'ok' }] }) };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765/', fetchImpl });

  await client.attack('CVE-2022-46169', { repaired: false });
  await client.validate('CVE-2022-46169');
  await client.reset('CVE-2022-46169');

  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/cases/CVE-2022-46169/attack',
    'http://127.0.0.1:8765/cases/CVE-2022-46169/validate',
    'http://127.0.0.1:8765/cases/CVE-2022-46169/reset',
  ]);
  assert.equal(JSON.parse(calls[0].init.body).repaired, false);
  assert.equal(calls[2].init.method, 'POST');
});

test('calls the optional bridge evidence inspection program for Cacti marker checks', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    return {
      ok: true,
      json: async () => ({
        present: true,
        path: '/tmp/kintsugi_marker',
        command: 'test -f /tmp/kintsugi_marker && stat /tmp/kintsugi_marker',
      }),
    };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765/', fetchImpl });

  const result = await client.inspectEvidence('CVE-2022-46169', { path: '/tmp/kintsugi_marker' });

  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/cases/CVE-2022-46169/evidence',
  ]);
  assert.equal(JSON.parse(calls[0].init.body).path, '/tmp/kintsugi_marker');
  assert.equal(result.present, true);
});

test('uploads Ghostscript demo files through multipart bridge form data', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    return {
      ok: true,
      json: async () => ({
        result: 'breached',
        classification: 'malicious',
        marker_present: true,
      }),
    };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765/', fetchImpl });
  const sample = new Blob(['%!PS-Adobe-3.0'], { type: 'image/jpeg' });
  sample.name = 'rce.jpg';

  const result = await client.uploadFile('CVE-2018-16509', sample, { repaired: false });

  assert.equal(result.result, 'breached');
  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/cases/CVE-2018-16509/upload',
  ]);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.body.get('repaired'), 'false');
  assert.equal(calls[0].init.body.get('file').name, 'rce.jpg');
});

test('uses the same optional bridge program contract for the Ghostscript case', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    return { ok: true, json: async () => ({ result: 'ok' }) };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765', fetchImpl });

  await client.attack('CVE-2018-16509', { repaired: true });
  await client.validate('CVE-2018-16509', { after_attack: true });
  await client.reset('CVE-2018-16509');

  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/cases/CVE-2018-16509/attack',
    'http://127.0.0.1:8765/cases/CVE-2018-16509/validate',
    'http://127.0.0.1:8765/cases/CVE-2018-16509/reset',
  ]);
  assert.equal(JSON.parse(calls[0].init.body).repaired, true);
  assert.equal(JSON.parse(calls[1].init.body).after_attack, true);
});

test('uses the same optional bridge program contract for the VuFind case', async () => {
  const { createLocalBridgeClient } = await import('../app/case-gateway.mjs');
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    return { ok: true, json: async () => ({ result: 'ok' }) };
  };
  const client = createLocalBridgeClient({ baseUrl: 'http://127.0.0.1:8765', fetchImpl });

  await client.attack('CVE-2024-25737', { repaired: false });
  await client.validate('CVE-2024-25737', { after_attack: true });
  await client.reset('CVE-2024-25737');

  assert.deepEqual(calls.map((call) => call.url), [
    'http://127.0.0.1:8765/cases/CVE-2024-25737/attack',
    'http://127.0.0.1:8765/cases/CVE-2024-25737/validate',
    'http://127.0.0.1:8765/cases/CVE-2024-25737/reset',
  ]);
  assert.equal(JSON.parse(calls[0].init.body).repaired, false);
  assert.equal(JSON.parse(calls[1].init.body).after_attack, true);
});

test('normalizes bridge SSE logs and completion events', async () => {
  const { subscribeToBridgeRun } = await import('../app/case-gateway.mjs');
  const received = [];

  class FakeEventSource {
    static latest;
    listeners = new Map();
    constructor(url) { this.url = url; FakeEventSource.latest = this; }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    emit(type, data) { this.listeners.get(type)?.({ data: JSON.stringify(data) }); }
    close() { this.closed = true; }
  }

  const completion = subscribeToBridgeRun({
    baseUrl: 'http://127.0.0.1:8765',
    eventsUrl: '/runs/RUN-1/events',
    EventSourceImpl: FakeEventSource,
    onEvent: (event) => received.push(event),
  });

  FakeEventSource.latest.emit('log', { line: 'Stage 8: repair policy generated' });
  FakeEventSource.latest.emit('status', { status: 'succeeded', return_code: 0 });
  await completion;

  assert.deepEqual(received.map((event) => event.type), ['log', 'repair-step', 'complete']);
  assert.equal(received[1].patchStep, 3);
  assert.equal(FakeEventSource.latest.closed, true);
});

test('rejects bridge SSE failures without duplicating the outer error log', async () => {
  const { subscribeToBridgeRun } = await import('../app/case-gateway.mjs');
  const received = [];

  class FakeEventSource {
    static latest;
    listeners = new Map();
    constructor() { FakeEventSource.latest = this; }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    emit(type, data) { this.listeners.get(type)?.({ data: JSON.stringify(data) }); }
    close() { this.closed = true; }
  }

  const completion = subscribeToBridgeRun({
    baseUrl: 'http://127.0.0.1:8765',
    eventsUrl: '/runs/RUN-1/events',
    EventSourceImpl: FakeEventSource,
    onEvent: (event) => received.push(event),
  });

  FakeEventSource.latest.emit('error', { message: 'sudo authentication failed' });

  await assert.rejects(completion, /sudo authentication failed/);
  assert.deepEqual(received, []);
  assert.equal(FakeEventSource.latest.closed, true);
});
