import { open, readFile, mkdir, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const running = new Set(['pending', 'queued', 'running']);
const timestamp = () => new Date().toISOString();

export function validateBaseUrl(input = 'http://127.0.0.1:8787') {
  const url = new URL(input);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('base-url 必须为无凭据、无路径的回环 HTTP 地址，例如 http://127.0.0.1:8787');
  }
  // Resolve localhost locally without consulting DNS. Redirects are rejected too.
  if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
  return url.origin;
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value)) return null;
  const datePart = value.slice(0, 10), dateOnly = Date.parse(`${datePart}T00:00:00Z`), ms = Date.parse(value);
  if (!Number.isFinite(ms) || !Number.isFinite(dateOnly) || new Date(dateOnly).toISOString().slice(0, 10) !== datePart) return null;
  return ms;
}

export function publicationLatency(beforeIds, afterItems, run, observedAt) {
  const before = new Set(beforeIds), samples = [], excluded = {};
  const reject = reason => { excluded[reason] = (excluded[reason] ?? 0) + 1; };
  let newItems = 0;
  for (const item of afterItems) {
    if (before.has(item.id)) continue;
    newItems++;
    if (item.dataMode !== 'live' || item.firstSeenMode !== 'live' || item.discoveryRunId !== run.id) { reject('not_discovered_by_this_live_run'); continue; }
    const firstSeen = validDate(item.firstSeenAt), started = validDate(run.startedAt), end = validDate(observedAt);
    if (firstSeen === null || started === null || end === null || firstSeen < started || firstSeen > end) { reject('invalid_first_seen'); continue; }
    const published = validDate(item.published);
    if (published === null) { reject('invalid_or_missing_published'); continue; }
    if (published > firstSeen) { reject('published_after_first_seen'); continue; }
    samples.push({ id: item.id, sourceId: item.sourceId ?? null, url: item.url ?? null, published: item.published, publicationPrecision: item.published.length === 10 ? 'date' : 'timestamp', firstSeenAt: item.firstSeenAt, discoveryRunId: item.discoveryRunId, latencyMs: firstSeen - published });
  }
  return { newItems, eligibleItems: samples.length, excluded, samples, definition: '仅本轮运行中新入库的 live 条目；published 至 immutable firstSeenAt。日期精度发布时间按 UTC 当日 00:00 估算。' };
}

export function classifySources(sourceResults = []) {
  const counts = { total: sourceResults.length, primary: 0, mirrored: 0, failed: 0, unknown: 0 };
  const items = sourceResults.map(source => {
    let availability = 'unknown';
    if (source.status === 'error') availability = 'failed';
    else if (source.transport?.mode === 'official-mirror') availability = 'mirrored';
    else if (source.status === 'healthy' && source.transport?.mode === 'primary') availability = 'primary';
    counts[availability]++;
    const transportFields = ['url', 'mode', 'primaryUrl', 'primaryError', 'primaryErrorCode', 'mirrorStatus', 'mirrorErrorCode', 'attempts', 'redirects', 'retries'];
    const transport = source.transport ? Object.fromEntries(transportFields.filter(field => Object.hasOwn(source.transport, field)).map(field => [field, source.transport[field]])) : null;
    return { id: source.id, name: source.name, status: source.status, availability, lastSync: source.lastSync ?? null, lastSuccess: source.lastSuccess ?? null, lastPrimarySuccess: source.lastPrimarySuccess ?? null, count: source.count ?? null, changed: source.changed ?? null, contentHash: source.contentHash ?? null, error: source.error ?? null, errorCode: source.errorCode ?? null, detail: source.detail ?? null, transport };
  });
  return { counts, items, evidenceAvailable: sourceResults.length > 0 };
}

export async function readEvidence(file) {
  let bytes;
  try { bytes = await readFile(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  if (!bytes) return [];
  if (!bytes.endsWith('\n')) throw new Error('证据文件尾行不完整；保留原文件并改用新文件，禁止覆盖修补旧记录');
  const records = []; let previousHash = null;
  for (const [index, line] of bytes.slice(0, -1).split('\n').entries()) {
    let record;
    try { record = JSON.parse(line); } catch { throw new Error(`证据第 ${index + 1} 行不是有效 JSON`); }
    const { hash, ...body } = record;
    if (body.schema !== 1 || body.previousHash !== previousHash || hash !== digest(body)) throw new Error(`证据第 ${index + 1} 行哈希链校验失败`);
    records.push(record); previousHash = hash;
  }
  return records;
}

async function lockEvidence(file) {
  const lockPath = `${file}.lock`, token = randomUUID();
  await mkdir(dirname(file), { recursive: true });
  let handle;
  try { handle = await open(lockPath, 'wx'); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    // Serialize stale-lock recovery: two resumptions must never delete a new owner's lock.
    const recoveryPath = `${lockPath}.recovery`;
    let recovery;
    try { recovery = await open(recoveryPath, 'wx'); }
    catch (err) { if (err.code === 'EEXIST') throw new Error('证据锁正在恢复；若 .lock.recovery 持续存在，确认没有监测进程后再处理'); throw err; }
    try {
      let owner;
      try { owner = JSON.parse(await readFile(lockPath, 'utf8')); if (!Number.isInteger(owner.pid) || owner.pid <= 0) throw new Error(); } catch { throw new Error('证据锁不可读取；确认没有监测进程后再删除 .lock 文件'); }
      let alive = true;
      try { process.kill(owner.pid, 0); } catch (err) { if (err.code === 'ESRCH') alive = false; }
      if (alive) throw new Error(`已有监测进程占用证据文件（PID ${owner.pid}）`);
      await unlink(lockPath);
      handle = await open(lockPath, 'wx');
    } finally { await recovery.close(); await unlink(recoveryPath); }
  }
  await handle.writeFile(JSON.stringify({ pid: process.pid, token, at: timestamp() }));
  await handle.close();
  return async () => {
    try { const owner = JSON.parse(await readFile(lockPath, 'utf8')); if (owner.token === token) await unlink(lockPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
}

function unfinishedCycle(records) {
  const cycles = new Map();
  for (const record of records) {
    if (record.type === 'cycle.started') cycles.set(record.cycleId, { ...record });
    if (record.type === 'cycle.run' && cycles.has(record.cycleId)) cycles.get(record.cycleId).runId = record.runId;
    if (record.type === 'cycle.completed') cycles.delete(record.cycleId);
  }
  return [...cycles.values()].at(-1) ?? null;
}

export function summarizeRecords(records) {
  const completed = records.filter(record => record.type === 'cycle.completed');
  const observations = completed.filter(record => record.outcome === 'terminal');
  const totals = { attempts: completed.length, terminalRuns: observations.length, completed: 0, partial: 0, failed: 0, interrupted: 0, cancelled: 0, requestFailures: completed.filter(record => record.outcome !== 'terminal').length, primary: 0, mirrored: 0, sourceFailures: 0, sourceUnknown: 0 };
  const perSource = {}, latencyById = new Map(), intervals = [];
  let previousStart = null;
  for (const record of observations) {
    if (Object.hasOwn(totals, record.run.status)) totals[record.run.status]++;
    const start = Date.parse(record.cycleStartedAt);
    if (previousStart !== null) intervals.push(start - previousStart);
    previousStart = start;
    for (const source of record.sources.items) {
      const row = perSource[source.id] ??= { id: source.id, name: source.name, primary: 0, mirrored: 0, failed: 0, unknown: 0, primaryRecoveries: 0, lastAvailability: null, lastError: null };
      if (source.availability === 'primary' && ['mirrored', 'failed'].includes(row.lastAvailability)) row.primaryRecoveries++;
      row[source.availability]++; row.lastAvailability = source.availability;
      row.lastError = source.error ?? source.transport?.primaryError ?? null;
      if (source.availability === 'failed') totals.sourceFailures++;
      else if (source.availability === 'unknown') totals.sourceUnknown++;
      else totals[source.availability]++;
    }
    for (const sample of record.latency.samples) if (!latencyById.has(sample.id)) latencyById.set(sample.id, sample);
  }
  const samples = [...latencyById.values()], values = samples.map(sample => sample.latencyMs).sort((a, b) => a - b);
  const sessions = records.filter(record => record.type === 'session.started').map(start => {
    const end = records.find(record => record.type === 'session.ended' && record.sessionId === start.sessionId);
    const last = records.filter(record => record.sessionId === start.sessionId).at(-1);
    return { sessionId: start.sessionId, startedAt: start.at, endedAt: end?.at ?? null, recordedThrough: end?.at ?? last.at, reason: end?.reason ?? 'unclosed', targetHours: start.durationHours, intervalMinutes: start.intervalMinutes, recordedHours: Math.max(0, Date.parse(end?.at ?? last.at) - Date.parse(start.at)) / 3600000 };
  });
  const first = observations[0], last = observations.at(-1);
  const maxGapMs = intervals.length ? Math.max(...intervals) : 0;
  const typicalIntervalMs = sessions.length ? Math.min(...sessions.map(session => session.intervalMinutes * 60000)) : null;
  const observationSpanHours = first && last ? Math.max(0, Date.parse(last.at) - Date.parse(first.cycleStartedAt)) / 3600000 : 0;
  return { schema: 1, generatedAt: timestamp(), integrity: { hashChain: 'verified', records: records.length, lastHash: records.at(-1)?.hash ?? null, note: '本机追加日志哈希链能发现意外修改，不是第三方时间戳或数字签名。' }, totals, sources: Object.values(perSource), sessions, coverage: { observationSpanHours, recordedSessionHours: sessions.reduce((sum, session) => sum + session.recordedHours, 0), maximumSampleGapHours: maxGapMs / 3600000, gapExceedsSchedule: typicalIntervalMs !== null && maxGapMs > typicalIntervalMs * 1.5, pendingCycleId: unfinishedCycle(records)?.cycleId ?? null, note: '跨度不等于连续覆盖；暂停、断网、主站失败和备用成功分别保留。仅有一次样本不能证明 72 小时运行。' }, publicationLatency: { count: values.length, timestampPrecisionCount: samples.filter(sample => sample.publicationPrecision === 'timestamp').length, datePrecisionCount: samples.filter(sample => sample.publicationPrecision === 'date').length, minimumMs: values[0] ?? null, medianMs: values.length ? (values[Math.floor((values.length - 1) / 2)] + values[Math.ceil((values.length - 1) / 2)]) / 2 : null, p95Ms: values.length ? values[Math.ceil(values.length * 0.95) - 1] : null, maximumMs: values.at(-1) ?? null, samples, note: '无合格新入库条目时为 null，不以旧快照、重复采集或缺失发布时间填充。' } };
}

export async function runObservation({ baseUrl = 'http://127.0.0.1:8787', file = 'artifacts/monitoring/observations.jsonl', once = false, intervalMinutes = 30, durationHours = 72, pollMs = 1000, requestTimeoutMs = 15000, runTimeoutMs = 180000, signal, onEvent = () => {} } = {}) {
  baseUrl = validateBaseUrl(baseUrl); file = resolve(file);
  for (const [name, value] of Object.entries({ intervalMinutes, durationHours, pollMs, requestTimeoutMs, runTimeoutMs })) if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} 必须为正数`);
  const release = await lockEvidence(file); let log;
  try {
    const records = await readEvidence(file);
    if (records.some(record => record.type === 'session.started' && record.baseUrl !== baseUrl)) throw new Error('同一证据文件不能混入不同 HTTP 目标');
    log = await open(file, 'a'); const sessionId = randomUUID();
    async function append(type, fields = {}) {
      const body = { schema: 1, type, at: timestamp(), sessionId, ...fields, previousHash: records.at(-1)?.hash ?? null };
      const record = { ...body, hash: digest(body) };
      await log.write(`${JSON.stringify(record)}\n`); await log.sync(); records.push(record); await onEvent(record); return record;
    }
    async function api(path, body) {
      const response = await fetch(`${baseUrl}${path}`, { method: body ? 'POST' : 'GET', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(requestTimeoutMs)]) : AbortSignal.timeout(requestTimeoutMs) });
      const text = await response.text();
      if (text.length > 16 * 1024 * 1024) throw new Error('API 响应超过 16 MB');
      let data; try { data = JSON.parse(text); } catch { throw new Error(`HTTP ${response.status} 返回无效 JSON`); }
      if (!response.ok) { const error = new Error(`HTTP ${response.status}: ${String(data.error ?? '请求失败').slice(0, 1000)}`); error.httpStatus = response.status; throw error; }
      return data;
    }
    const sessionStarted = await append('session.started', { baseUrl, once, intervalMinutes, durationHours, resumedCycleId: unfinishedCycle(records)?.cycleId ?? null });
    const deadline = Date.parse(sessionStarted.at) + durationHours * 3600000;
    let reason = once ? 'once' : 'duration';
    try {
      for (;;) {
        if (signal?.aborted) { reason = 'interrupted'; break; }
        const attemptStarted = Date.now();
        let cycle = unfinishedCycle(records), runId = cycle?.runId;
        const resumed = Boolean(cycle);
        try {
          if (!cycle) {
            const baseline = await api('/api/intel');
            if (!Array.isArray(baseline.items) || baseline.items.some(item => typeof item.id !== 'string')) throw new Error('情报基线 API 缺少 items/id');
            cycle = await append('cycle.started', { cycleId: randomUUID(), beforeIds: [...new Set(baseline.items.map(item => item.id))], baselineObservedAt: timestamp() });
          } else await append('cycle.resumed', { cycleId: cycle.cycleId, runId: runId ?? null });
          if (!runId) {
            // A process can stop after POST succeeds but before its response is saved.
            const uncertain = resumed && records.some(record => record.type === 'cycle.submitting' && record.cycleId === cycle.cycleId);
            if (uncertain) {
              const recent = await api('/api/runs');
              const candidates = (recent.items ?? []).filter(run => run.mode === 'live' && Date.parse(run.startedAt) >= Date.parse(cycle.at));
              if (candidates.length !== 1) throw new Error('提交结果不确定且无法唯一恢复 live 运行；保留待恢复周期，请人工核对 /api/runs');
              runId = candidates[0].id;
            } else {
              // Durable intent prevents a second POST after an uncertain interruption.
              await append('cycle.submitting', { cycleId: cycle.cycleId });
              const created = await api('/api/runs', { mode: 'live' });
              runId = created.runId ?? created.run?.id;
              if (typeof runId !== 'string' || !runId) throw new Error('运行创建响应缺少 runId');
            }
            await append('cycle.run', { cycleId: cycle.cycleId, runId });
          }
          const pollingDeadline = Date.now() + runTimeoutMs; let run;
          for (;;) {
            ({ run } = await api(`/api/runs/${encodeURIComponent(runId)}`));
            if (!run || run.id !== runId || run.mode !== 'live' || typeof run.status !== 'string') throw new Error('运行 API 的 id/mode/status 无效');
            if (['completed', 'success', 'partial', 'failed', 'interrupted', 'cancelled'].includes(run.status)) break;
            if (!running.has(run.status)) throw new Error(`未知运行状态：${run.status}`);
            if (Date.now() >= pollingDeadline) throw new Error(`运行 ${runId} 在 ${runTimeoutMs} ms 内未达终态`);
            await delay(pollMs, undefined, { signal });
          }
          const after = await api('/api/intel');
          if (!Array.isArray(after.items) || after.items.some(item => typeof item?.id !== 'string')) throw new Error('情报 API 缺少 items/id');
          const observedAt = timestamp();
          await append('cycle.completed', { cycleId: cycle.cycleId, cycleStartedAt: cycle.at, outcome: 'terminal', run: { id: run.id, mode: run.mode, status: run.status, startedAt: run.startedAt, finishedAt: run.finishedAt ?? null, summary: run.summary ?? null, sourceStats: run.sourceStats ?? null, steps: run.steps ?? [] }, sources: classifySources(run.sourceResults), latency: publicationLatency(cycle.beforeIds, after.items, run, observedAt), afterCount: after.items.length });
        } catch (error) {
          const message = String(error.message).slice(0, 2000);
          const submitted = cycle && records.some(record => record.cycleId === cycle.cycleId && record.type === 'cycle.submitting');
          if (cycle && (runId || (submitted && !error.httpStatus))) await append('cycle.deferred', { cycleId: cycle.cycleId, runId: runId ?? null, submissionUncertain: !runId, error: message, interrupted: signal?.aborted ?? false });
          else await append('cycle.completed', { cycleId: cycle?.cycleId ?? randomUUID(), cycleStartedAt: cycle?.at ?? timestamp(), outcome: signal?.aborted ? 'interrupted' : 'api_error', error: message });
          if (signal?.aborted) { reason = 'interrupted'; break; }
        }
        if (once || Date.now() >= deadline) break;
        const waitMs = Math.max(0, Math.min(attemptStarted + intervalMinutes * 60000, deadline) - Date.now());
        try { if (waitMs) await delay(waitMs, undefined, { signal }); } catch { reason = 'interrupted'; break; }
      }
    } finally { await append('session.ended', { reason }); }
    return summarizeRecords(records);
  } finally { if (log) await log.close(); await release(); }
}

const help = `用法：node scripts/monitor-observation.mjs [--once] [--base-url http://127.0.0.1:8787]\n  [--file artifacts/monitoring/observations.jsonl] [--interval-minutes 30] [--duration-hours 72]\n  [--poll-ms 1000] [--request-timeout-ms 15000] [--run-timeout-ms 180000]\nCtrl+C 保存中止记录；再次运行同一文件会恢复未终态运行。只访问回环 HTTP API。`;

export function observationExitCode(summary, interrupted = false) {
  if (interrupted) return 130;
  const { totals, coverage } = summary;
  return coverage.pendingCycleId || !totals.terminalRuns || totals.failed || totals.interrupted || totals.cancelled || totals.requestFailures ? 1 : 0;
}

export async function main(args = process.argv.slice(2)) {
  const options = {}, mapping = { '--base-url': 'baseUrl', '--file': 'file', '--interval-minutes': 'intervalMinutes', '--duration-hours': 'durationHours', '--poll-ms': 'pollMs', '--request-timeout-ms': 'requestTimeoutMs', '--run-timeout-ms': 'runTimeoutMs' };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') { console.log(help); return; }
    if (args[i] === '--once') { options.once = true; continue; }
    const key = mapping[args[i]];
    if (!key || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`未知参数或缺少值：${args[i]}`);
    options[key] = ['baseUrl', 'file'].includes(key) ? args[++i] : Number(args[++i]);
  }
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    const summary = await runObservation({ ...options, signal: controller.signal, onEvent: event => { if (['cycle.completed', 'cycle.deferred'].includes(event.type)) console.error(`${event.at} ${event.type} ${event.run?.id ?? event.runId ?? ''} ${event.run?.status ?? event.error ?? ''}`); } });
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = observationExitCode(summary, controller.signal.aborted);
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
