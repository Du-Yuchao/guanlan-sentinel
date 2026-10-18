import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifySources, observationExitCode, publicationLatency, readEvidence, runObservation, summarizeRecords, validateBaseUrl } from '../scripts/monitor-observation.mjs';

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-observation-test-'));
  const state = { posts: 0, polls: 0, complete: true, rejectPost: false, items: [{ id: 'snapshot', dataMode: 'snapshot' }, { id: 'old-live', dataMode: 'live' }], ...options };
  const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'POST') { for await (const _ of req) {} }
    if (req.url === '/api/intel') {
      if (state.badJson) { res.end('not json'); return; }
      res.end(JSON.stringify({ items: state.items })); return;
    }
    if (req.url === '/api/runs' && req.method === 'POST') {
      state.posts++;
      if (state.rejectPost) { res.statusCode = 409; res.end(JSON.stringify({ error: '已有任务执行中' })); return; }
      const at = new Date().toISOString();
      state.run = { id: `RUN-${state.posts}`, mode: 'live', status: 'running', startedAt: at, summary: 'fake API fixture', sourceResults: [{ id: 'one', name: '主站', status: 'healthy', transport: { mode: 'primary', url: 'https://example.test' } }, { id: 'two', name: '备用', status: 'degraded', transport: { mode: 'official-mirror', url: 'https://mirror.test', primaryError: 'ETIMEDOUT' } }, { id: 'three', name: '失败', status: 'error', error: 'timeout' }] };
      res.statusCode = 202; res.end(JSON.stringify({ runId: state.run.id })); return;
    }
    if (req.url === '/api/runs') { res.end(JSON.stringify({ items: state.run ? [state.run] : [] })); return; }
    if (req.url.startsWith('/api/runs/')) {
      state.polls++;
      if (!state.run) { res.statusCode = 404; res.end('{}'); return; }
      if (state.complete) {
        state.run.status = state.terminalStatus ?? 'partial'; state.run.finishedAt = new Date().toISOString();
        if (!state.items.some(item => item.id === 'fresh')) state.items.push({ id: 'fresh', dataMode: 'live', firstSeenMode: 'live', discoveryRunId: state.run.id, firstSeenAt: state.run.finishedAt, published: new Date(Date.now() - 60000).toISOString(), url: 'https://example.test/fresh' });
        state.items[0] = { ...state.items[0], dataMode: 'live', firstSeenMode: 'snapshot', discoveryRunId: null, firstLiveAt: state.run.finishedAt, published: '2026-01-01' };
      }
      res.end(JSON.stringify({ run: state.run })); return;
    }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  return { state, file: join(directory, 'evidence.jsonl'), baseUrl: `http://127.0.0.1:${server.address().port}`, once: true, pollMs: 5, requestTimeoutMs: 1000, runTimeoutMs: 1000 };
}

test('only literal loopback HTTP endpoints are accepted and localhost avoids DNS', () => {
  assert.equal(validateBaseUrl('http://localhost:8787'), 'http://127.0.0.1:8787');
  assert.equal(validateBaseUrl('http://[::1]:8787'), 'http://[::1]:8787');
  for (const url of ['https://127.0.0.1', 'http://example.test', 'http://127.0.0.1.evil.test', 'http://user:pass@127.0.0.1', 'http://127.0.0.1/api', 'http://127.0.0.1?token=secret', 'http://192.168.1.1']) assert.throws(() => validateBaseUrl(url));
});

test('latency excludes old snapshots, repeated observations, unrelated runs and invalid dates', () => {
  const run = { id: 'RUN-test', startedAt: '2026-10-18T10:00:00Z' };
  const valid = { id: 'fresh', dataMode: 'live', firstSeenMode: 'live', discoveryRunId: run.id, firstSeenAt: '2026-10-18T10:00:01Z', published: '2026-10-18T09:59:00Z' };
  const result = publicationLatency(['old'], [{ ...valid, id: 'old' }, valid, { ...valid, id: 'snapshot', firstSeenMode: 'snapshot' }, { ...valid, id: 'unrelated', discoveryRunId: 'RUN-other' }, { ...valid, id: 'date', published: '2026-10-18' }, { ...valid, id: 'invalid', published: '2026-02-30' }, { ...valid, id: 'future', published: '2026-10-18T11:00:00Z' }, { ...valid, id: 'missing', published: '' }, { ...valid, id: 'early', firstSeenAt: '2026-10-18T08:00:00Z' }], run, '2026-10-18T10:01:00Z');
  assert.equal(result.newItems, 8); assert.equal(result.eligibleItems, 2);
  assert.equal(result.samples[0].latencyMs, 61000); assert.equal(result.samples[1].publicationPrecision, 'date');
  assert.deepEqual(result.excluded, { not_discovered_by_this_live_run: 2, invalid_or_missing_published: 2, published_after_first_seen: 1, invalid_first_seen: 1 });
});

test('mirror availability never counts as primary recovery', () => {
  const transport = { mode: 'official-mirror', url: 'https://mirror.test', primaryUrl: 'https://primary.test', primaryError: 'timeout', primaryErrorCode: 'TIMEOUT', mirrorStatus: 'succeeded', mirrorErrorCode: null, attempts: 4, redirects: 1, retries: 2, notPublic: 'must not be copied' };
  const sources = classifySources([{ id: 'a', status: 'degraded', transport }, { id: 'b', status: 'healthy', transport: { mode: 'primary' } }, { id: 'c', status: 'error', transport: { ...transport, mirrorStatus: 'failed', mirrorErrorCode: 'HTTP_503' } }, { id: 'd', status: 'snapshot' }]);
  assert.deepEqual(sources.counts, { total: 4, primary: 1, mirrored: 1, failed: 1, unknown: 1 });
  const { notPublic, ...publicFields } = transport;
  assert.deepEqual(sources.items[0].transport, publicFields);
  assert.equal(sources.items[2].transport.mirrorErrorCode, 'HTTP_503');
  const records = ['failed', 'mirrored', 'mirrored', 'primary'].map((availability, index) => ({ type: 'cycle.completed', at: `2026-10-18T0${index}:00:01Z`, cycleStartedAt: `2026-10-18T0${index}:00:00Z`, outcome: 'terminal', run: { status: 'partial' }, sources: { items: [{ id: 'a', availability }] }, latency: { samples: [] } }));
  assert.equal(summarizeRecords(records.slice(0, 3)).sources[0].primaryRecoveries, 0);
  assert.equal(summarizeRecords(records).sources[0].primaryRecoveries, 1);
});

test('once appends auditable terminal evidence and incremental summary does not double count freshness', async t => {
  const options = await fixture(t);
  const first = await runObservation(options);
  assert.equal(first.totals.terminalRuns, 1); assert.equal(first.totals.partial, 1);
  assert.equal(first.totals.primary, 1); assert.equal(first.totals.mirrored, 1); assert.equal(first.totals.sourceFailures, 1);
  assert.equal(first.publicationLatency.count, 1); assert.ok(first.coverage.observationSpanHours < 1);
  const bytes = await readFile(options.file, 'utf8');
  const second = await runObservation(options);
  assert.equal(second.totals.terminalRuns, 2); assert.equal(second.publicationLatency.count, 1);
  assert.ok((await readFile(options.file, 'utf8')).startsWith(bytes), 'existing bytes must not be rewritten');
  const records = await readEvidence(options.file);
  assert.equal(records.filter(record => record.type === 'cycle.completed').at(-1).latency.eligibleItems, 0);
  assert.deepEqual(summarizeRecords(records).totals, second.totals);
});

test('timeouts retain pending run and a second invocation recovers without another POST', async t => {
  const options = await fixture(t, { complete: false });
  const first = await runObservation({ ...options, runTimeoutMs: 10 });
  assert.ok(first.coverage.pendingCycleId); assert.equal(first.totals.terminalRuns, 0);
  options.state.complete = true;
  const second = await runObservation(options);
  assert.equal(options.state.posts, 1); assert.equal(second.coverage.pendingCycleId, null); assert.equal(second.totals.terminalRuns, 1);
});

test('recovery after a crash between POST and saved run ID uniquely adopts the existing run', async t => {
  const options = await fixture(t); await runObservation(options);
  const records = await readEvidence(options.file);
  const intentIndex = records.findIndex(record => record.type === 'cycle.submitting');
  // Simulate only the bytes that had reached disk when that process crashed.
  await writeFile(options.file, records.slice(0, intentIndex + 1).map(record => JSON.stringify(record)).join('\n') + '\n');
  const resumed = await runObservation(options);
  assert.equal(options.state.posts, 1); assert.equal(resumed.totals.terminalRuns, 1); assert.equal(resumed.coverage.pendingCycleId, null);
});

test('duration boundary ends a short observation even when the interval is longer', async t => {
  const options = await fixture(t);
  const started = Date.now();
  const result = await runObservation({ ...options, once: false, intervalMinutes: 30, durationHours: 0.00002 });
  assert.equal(result.sessions[0].reason, 'duration');
  assert.ok(result.sessions[0].recordedHours >= 0.00002);
  assert.ok(Date.now() - started < 3000, 'must not wait the 30-minute interval past the deadline');
});

test('Ctrl+C signal leaves durable pending run for recovery', async t => {
  const options = await fixture(t, { complete: false });
  const controller = new AbortController();
  const summary = await runObservation({ ...options, signal: controller.signal, onEvent: event => { if (event.type === 'cycle.run') controller.abort(); } });
  assert.ok(summary.coverage.pendingCycleId); assert.equal(summary.sessions[0].reason, 'interrupted');
  options.state.complete = true;
  await runObservation(options); assert.equal(options.state.posts, 1);
});

test('active evidence lock prevents a second writer', async t => {
  const options = await fixture(t, { complete: false });
  let competingError;
  const controller = new AbortController();
  await runObservation({ ...options, signal: controller.signal, onEvent: async event => {
    if (event.type === 'cycle.run') {
      try { await runObservation(options); } catch (error) { competingError = error; }
      controller.abort();
    }
  } });
  assert.match(competingError?.message ?? '', /已有监测进程占用/);
  assert.equal(options.state.posts, 1);
});

test('HTTP conflicts and invalid baseline JSON are logged as failures, without inventing successful observations', async t => {
  const options = await fixture(t, { rejectPost: true });
  const first = await runObservation(options);
  assert.equal(first.totals.requestFailures, 1); assert.equal(first.coverage.pendingCycleId, null);
  options.state.badJson = true;
  const second = await runObservation(options);
  assert.equal(second.totals.requestFailures, 2); assert.equal(second.totals.terminalRuns, 0); assert.equal(second.publicationLatency.minimumMs, null);
});

for (const status of ['interrupted', 'cancelled']) {
  test(`terminal ${status} is recorded and produces a failing CLI exit code`, async t => {
    const options = await fixture(t, { terminalStatus: status });
    const summary = await runObservation(options);
    assert.equal(summary.totals.terminalRuns, 1);
    assert.equal(summary.totals[status], 1);
    assert.equal(summary.coverage.pendingCycleId, null);
    assert.equal((await readEvidence(options.file)).find(record => record.type === 'cycle.completed').run.status, status);
    assert.equal(observationExitCode(summary), 1);
    assert.equal(observationExitCode(summary, true), 130, 'Ctrl+C exit code takes priority');
  });
}

test('CLI exit decision distinguishes successful, failed, empty and pending observations', () => {
  const good = { coverage: { pendingCycleId: null }, totals: { terminalRuns: 1, failed: 0, interrupted: 0, cancelled: 0, requestFailures: 0 } };
  assert.equal(observationExitCode(good), 0);
  for (const field of ['failed', 'interrupted', 'cancelled', 'requestFailures']) assert.equal(observationExitCode({ ...good, totals: { ...good.totals, [field]: 1 } }), 1);
  assert.equal(observationExitCode({ ...good, totals: { ...good.totals, terminalRuns: 0 } }), 1);
  assert.equal(observationExitCode({ ...good, coverage: { pendingCycleId: 'pending' } }), 1);
  assert.equal(observationExitCode(good, true), 130);
});

test('log corruption or torn tails are rejected without modifying existing evidence', async t => {
  const options = await fixture(t); await runObservation(options);
  const bytes = await readFile(options.file, 'utf8');
  await writeFile(options.file, bytes.replace('session.started', 'session.altered'));
  await assert.rejects(() => runObservation(options), /哈希链校验失败/);
  assert.equal(await readFile(options.file, 'utf8'), bytes.replace('session.started', 'session.altered'));
  await writeFile(options.file, bytes.slice(0, -1));
  await assert.rejects(() => readEvidence(options.file), /尾行不完整/);
});
