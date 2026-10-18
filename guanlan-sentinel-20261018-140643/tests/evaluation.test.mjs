import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import {
  validateBaseUrl, validateDataset, citationMetrics, percentile, checkStructure, parseReviews,
  makeResult, summarize, runRequests, parseArgs, main, sha256, markdownReport
} from '../scripts/evaluate-heldout.mjs';

// Synthetic fixtures exercise the evaluator, never constitute a real held-out set.
const frozen = samples => ({ schemaVersion: 1, dataset: { id: 'synthetic-unit-fixture', status: 'frozen',
  frozenAt: '2026-01-01T00:00:00Z', annotationSource: 'synthetic test only', sourceSnapshot: 'synthetic snapshot', notUsedForDevelopment: true }, samples });
const sample = (id, gold = { citationIds: ['DOC-A'], abstained: false, answerRubric: ['Synthetic expected assertion.'] }) => ({ id, category: 'synthetic', question: `Synthetic question ${id}?`, gold });
const payload = (overrides = {}) => ({ answer: 'Synthetic answer [1]', mode: 'retrieval', abstained: false,
  citations: [{ id: 'DOC-A', index: 1, title: 'Synthetic evidence', url: 'https://example.invalid/a' }], ...overrides });
const result = (s, p = payload(), capture = {}) => makeResult(s, { httpStatus: 200, responseRaw: JSON.stringify(p), error: null, latencyMs: 12, ...capture });
const validReview = (r, datasetSha256, factualCorrect = true) => ({ sampleId: r.id, datasetSha256, responseSha256: r.responseSha256,
  reviewer: 'Synthetic human reviewer fixture', reviewedAt: '2026-01-02T00:00:00Z', factualCorrect });

async function fakeApi(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { baseUrl: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

test('network target is pinned to HTTP loopback and rejects remote URLs and extra components', () => {
  assert.equal(validateBaseUrl('http://localhost:8787'), 'http://127.0.0.1:8787');
  assert.equal(validateBaseUrl('http://[::1]:8787'), 'http://[::1]:8787');
  assert.equal(validateBaseUrl('http://127.0.0.2:8787'), 'http://127.0.0.2:8787');
  for (const url of ['https://127.0.0.1', 'http://example.com', 'http://192.168.1.1', 'http://127.0.0.1.example.com',
    'http://u:p@127.0.0.1', 'http://127.0.0.1/api', 'http://127.0.0.1/?x=1', 'http://127.0.0.1/#x', 'file:///tmp/x']) {
    assert.throws(() => validateBaseUrl(url), /base-url/);
  }
});

test('dataset validation requires a freeze declaration and unique sample IDs', () => {
  assert.equal(validateDataset(frozen([sample('a')])).samples.length, 1);
  const missing = frozen([sample('a')]); delete missing.dataset.annotationSource;
  assert.throws(() => validateDataset(missing), /frozen/);
  assert.throws(() => validateDataset(frozen([sample('a'), sample('a')])), /唯一/);
  assert.throws(() => validateDataset(frozen([sample('a', { citationIds: ['D', 'D'] })])), /无重复/);
  assert.doesNotThrow(() => validateDataset(frozen([sample('missing-gold', null)])));
});

test('citation ID scoring is exact, case sensitive, and deduplicates; empty denominators stay null', () => {
  const score = citationMetrics(['DOC-A', 'DOC-B'], ['DOC-A', 'DOC-A', 'DOC-B-extra', 'doc-b']);
  assert.deepEqual(score.precision, { numerator: 1, denominator: 3, value: 1 / 3 });
  assert.deepEqual(score.recall, { numerator: 1, denominator: 2, value: 0.5 });
  assert.deepEqual(score.missingIds, ['DOC-B']);
  assert.equal(citationMetrics([], []).precision.value, null);
  assert.equal(citationMetrics([], ['DOC-A']).recall.value, null);
});

test('nearest-rank latency percentiles do not mutate observations', () => {
  const values = [100, 1, 2, 3, 4];
  assert.equal(percentile(values, 50), 3);
  assert.equal(percentile(values, 95), 100);
  assert.equal(percentile([], 95), null);
  assert.deepEqual(values, [100, 1, 2, 3, 4]);
});

test('structure checks reject dangling answer references, invalid IDs and uncited non-abstentions', () => {
  assert.equal(checkStructure(payload()).passed, true);
  assert.equal(checkStructure(payload({ answer: 'Claim [9]' })).passed, false);
  assert.equal(checkStructure(payload({ citations: [{ id: '', index: 1 }] })).checks.citationIds, false);
  assert.equal(checkStructure(payload({ answer: 'No reference' })).checks.answerCitesEvidence, false);
  assert.equal(checkStructure(payload({ abstained: true, answer: 'Insufficient evidence', citations: [] })).passed, true);
  assert.equal(checkStructure(null).passed, false);
});

test('review JSONL accepts explicit null but rejects duplicates and incomplete attribution', () => {
  const r = result(sample('a')), hash = sha256('dataset');
  const review = validReview(r, hash, null), line = JSON.stringify(review);
  assert.equal(parseReviews(`${line}\n\n`).get('a').factualCorrect, null);
  assert.throws(() => parseReviews(`${line}\n${line}`), /重复/);
  assert.throws(() => parseReviews(JSON.stringify({ ...review, reviewer: '' })), /字段/);
  assert.throws(() => parseReviews('{bad json'), /第 1 行/);
});

test('missing gold and missing human scores remain in the formal count and prevent full-set accuracy', () => {
  const samples = [sample('reviewed'), sample('unreviewed'), sample('no-gold', null)];
  const results = samples.map(s => result(s)), hash = sha256('dataset');
  const reviews = new Map([['reviewed', validReview(results[0], hash)]]);
  const summary = summarize(frozen(samples), results, reviews, hash);
  assert.equal(summary.eligibleSamples, 3);
  assert.deepEqual(summary.human.coverage, { numerator: 1, denominator: 3, value: 1 / 3 });
  assert.equal(summary.human.unscoredCount, 2);
  assert.deepEqual(summary.human.reasons, { missingReview: 1, missingGoldRubric: 1 });
  assert.equal(summary.human.fullSetFactualAccuracy.value, null);
  assert.deepEqual(summary.human.reviewedSubsetCorrectness, { numerator: 1, denominator: 1, value: 1 });
  assert.equal(summary.citationIdMatching.missingGoldSamples, 1);
});

test('full-set factual accuracy appears only with valid human reviews for every eligible answer', () => {
  const samples = [sample('correct'), sample('incorrect')], results = samples.map(s => result(s)), hash = sha256('dataset');
  const reviews = new Map(results.map((r, i) => [r.id, validReview(r, hash, i === 0)]));
  const summary = summarize(frozen(samples), results, reviews, hash);
  assert.deepEqual(summary.human.fullSetFactualAccuracy, { numerator: 1, denominator: 2, value: 0.5, status: 'available', reason: null });
  assert.equal(summary.human.incorrectCount, 1);
  reviews.set('correct', { ...reviews.get('correct'), responseSha256: sha256('different answer') });
  const changed = summarize(frozen(samples), results, reviews, hash);
  assert.equal(changed.human.fullSetFactualAccuracy.value, null);
  assert.equal(changed.human.reasons.responseHashMismatch, 1);
  reviews.set('correct', { ...reviews.get('correct'), datasetSha256: sha256('different dataset') });
  assert.equal(summarize(frozen(samples), results, reviews, hash).human.reasons.datasetHashMismatch, 1);
});

test('examples and draft sets are excluded and cannot inflate formal metrics', async () => {
  const template = JSON.parse(await readFile(new URL('../data/evaluation/template.json', import.meta.url), 'utf8'));
  validateDataset(template);
  assert.ok(template.samples.every(s => s.example === true && s.excludeFromMetrics === true));
  const results = template.samples.map(s => result(s));
  const summary = summarize(template, results, new Map(), sha256('template'));
  assert.equal(summary.eligibleSamples, 0);
  assert.equal(summary.excludedSamples, template.samples.length);
  assert.equal(summary.human.fullSetFactualAccuracy.value, null);
  const declaredFrozen = { ...template, dataset: frozen([]).dataset };
  assert.equal(summarize(declaredFrozen, results, new Map(), sha256('template')).eligibleSamples, 0);
});

test('HTTP failures count against reference recall and abstention match; missing predictions do not create precision', () => {
  const s = sample('bad'), r = result(s, payload(), { httpStatus: 500, error: 'HTTP 500' });
  const summary = summarize(frozen([s]), [r], new Map(), sha256('dataset'));
  assert.deepEqual(summary.citationIdMatching.recall, { numerator: 0, denominator: 1, value: 0 });
  assert.equal(summary.citationIdMatching.precision.value, null);
  assert.equal(summary.abstention.expectationMatch.value, 0);
  assert.equal(summary.successfulRequests.value, 0);
  assert.equal(summary.latencyMs.count, 1);
  assert.equal(summary.human.reasons.requestFailed, 1);
});

test('local fake API receives only question and report captures raw output, mode, citations and hashes', async () => {
  const received = [];
  const api = await fakeApi(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    received.push({ path: req.url, method: req.method, body: JSON.parse(body) });
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(payload()));
  });
  try {
    const data = frozen([sample('a')]), results = await runRequests(data, { baseUrl: api.baseUrl });
    assert.deepEqual(received, [{ path: '/api/ask', method: 'POST', body: { question: data.samples[0].question } }]);
    assert.equal(results[0].mode, 'retrieval');
    assert.equal(results[0].responseSha256, sha256(results[0].responseRaw));
    assert.deepEqual(results[0].citationIds, ['DOC-A']);
    assert.equal(results[0].automatic.structure.passed, true);
    assert.ok(results[0].latencyMs >= 0);
  } finally { await api.close(); }
});

test('redirects are never followed and malformed JSON remains a captured failed result', async () => {
  let targetRequests = 0;
  const target = await fakeApi((req, res) => { targetRequests++; res.end('{}'); });
  const redirect = await fakeApi((req, res) => { res.writeHead(302, { Location: target.baseUrl + '/outside' }); res.end(); });
  const invalid = await fakeApi((req, res) => res.end('{broken'));
  try {
    const data = frozen([sample('a')]);
    const [redirected] = await runRequests(data, { baseUrl: redirect.baseUrl });
    assert.ok(redirected.error); assert.equal(targetRequests, 0);
    const [broken] = await runRequests(data, { baseUrl: invalid.baseUrl });
    assert.match(broken.error, /有效 JSON/);
    assert.equal(broken.responseRaw, '{broken');
    assert.equal(broken.automatic.structure.passed, false);
  } finally { await redirect.close(); await target.close(); await invalid.close(); }
});

test('timeout captures a failed sample and continues the run', async () => {
  let requests = 0;
  const api = await fakeApi((req, res) => { requests++; if (requests > 1) res.end(JSON.stringify(payload())); });
  try {
    const results = await runRequests(frozen([sample('timeout'), sample('next')]), { baseUrl: api.baseUrl, timeoutMs: 250 });
    assert.ok(results[0].error);
    assert.equal(results[1].httpStatus, 200);
    assert.equal(results.length, 2);
  } finally { await api.close(); }
});

test('CLI captures a run, imports hash-bound human scores without another request, and protects source files', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'sentinel-heldout-test-'));
  let requests = 0;
  const api = await fakeApi((req, res) => { requests++; res.end(JSON.stringify(payload())); });
  try {
    const input = join(temporary, 'samples.json'), output = join(temporary, 'run.json'), reviews = join(temporary, 'reviews.jsonl');
    const raw = JSON.stringify(frozen([sample('a')])); await writeFile(input, raw);
    const initial = await main(['--input', input, '--base-url', api.baseUrl, '--output', output]);
    assert.equal(initial.input.sha256, sha256(raw));
    assert.equal(initial.summary.human.fullSetFactualAccuracy.value, null);
    await writeFile(reviews, JSON.stringify(validReview(initial.results[0], sha256(raw))) + '\n');
    const rescored = await main(['--input', input, '--from-report', output, '--reviews', reviews, '--output', join(temporary, 'reviewed.json')]);
    assert.equal(requests, 1);
    assert.equal(rescored.runId, initial.runId);
    assert.equal(rescored.summary.human.fullSetFactualAccuracy.value, 1);
    assert.match(await readFile(join(temporary, 'reviewed.md'), 'utf8'), /1\/1 \(100\.0%\)/);
    await assert.rejects(() => main(['--input', input, '--output', input]), /不能覆盖/);
    assert.equal(requests, 1);
    await writeFile(input, raw + '\n');
    await assert.rejects(() => main(['--input', input, '--from-report', output, '--output', join(temporary, 'stale.json')]), /SHA-256/);
  } finally {
    await api.close();
    assert.equal(dirname(resolve(temporary)).toLowerCase(), resolve(tmpdir()).toLowerCase());
    assert.ok(basename(temporary).startsWith('sentinel-heldout-test-'));
    await rm(temporary, { recursive: true, force: true });
  }
});

test('CLI rejects invalid arguments before running and markdown never equates auto checks with correctness', () => {
  assert.throws(() => parseArgs([]), /--input/);
  assert.throws(() => parseArgs(['--input', 'x', '--timeout-ms', '0']), /timeout-ms/);
  assert.throws(() => parseArgs(['--input', 'x', '--unknown', 'x']), /无效参数/);
  const samples = [sample('a')], results = samples.map(s => result(s));
  const summary = summarize(frozen(samples), results, new Map(), sha256('dataset'));
  const markdown = markdownReport({ generatedAt: 'test', summarizedAt: 'test', scope: 'test', input: { sha256: sha256('dataset') }, summary, results });
  assert.match(markdown, /全样本事实准确率：不提供/);
  assert.match(markdown, /自动引用命中和结构检查均不代表语义正确性/);
});
