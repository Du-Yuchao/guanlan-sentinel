import { createHash, randomUUID } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

export const sha256 = value => createHash('sha256').update(value).digest('hex');
const has = (value, key) => Object.hasOwn(value, key);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const ratio = (numerator, denominator) => ({ numerator, denominator, value: denominator ? numerator / denominator : null });

export function validateBaseUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('base-url 必须是本机 HTTP URL'); }
  if (url.protocol !== 'http:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('base-url 只允许 HTTP 回环地址与可选端口，不允许凭据、路径、查询或片段');
  }
  // Pin localhost to a literal address; do not trust host-file or DNS resolution.
  if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
  if (url.hostname !== '[::1]' && !/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) {
    throw new Error('base-url 只能使用 localhost、127.0.0.0/8 或 [::1] 回环地址');
  }
  return url.origin;
}

export function validateDataset(dataset) {
  if (!isObject(dataset) || dataset.schemaVersion !== 1 || !isObject(dataset.dataset) || !Array.isArray(dataset.samples)) {
    throw new Error('样本集需包含 schemaVersion: 1、dataset 对象和 samples 数组');
  }
  const meta = dataset.dataset;
  if (!nonempty(meta.id) || !['example', 'draft', 'frozen'].includes(meta.status)) throw new Error('dataset.id 与 status (example/draft/frozen) 必填');
  if (meta.status === 'frozen' && (!nonempty(meta.frozenAt) || !Number.isFinite(Date.parse(meta.frozenAt)) ||
    !nonempty(meta.annotationSource) || !nonempty(meta.sourceSnapshot) || meta.notUsedForDevelopment !== true)) {
    throw new Error('frozen 集需 frozenAt、annotationSource、sourceSnapshot 和 notUsedForDevelopment: true 声明');
  }
  const ids = new Set();
  for (const sample of dataset.samples) {
    if (!isObject(sample) || !nonempty(sample.id) || ids.has(sample.id)) throw new Error('每题 id 必须是唯一非空字符串');
    ids.add(sample.id);
    if (!nonempty(sample.question) || sample.question.length > 4000 || !nonempty(sample.category)) throw new Error(`${sample.id}: question 需 1–4000 字符，category 必填`);
    for (const flag of ['example', 'excludeFromMetrics']) {
      if (has(sample, flag) && typeof sample[flag] !== 'boolean') throw new Error(`${sample.id}: ${flag} 需为布尔值`);
    }
    if (sample.gold !== undefined && sample.gold !== null) {
      if (!isObject(sample.gold)) throw new Error(`${sample.id}: gold 需为对象或 null`);
      const gold = sample.gold;
      if (has(gold, 'citationIds') && (!Array.isArray(gold.citationIds) || gold.citationIds.some(id => !nonempty(id)) || new Set(gold.citationIds).size !== gold.citationIds.length)) {
        throw new Error(`${sample.id}: gold.citationIds 需为无重复的非空 ID 数组，空数组表示预期无引用`);
      }
      if (has(gold, 'abstained') && typeof gold.abstained !== 'boolean') throw new Error(`${sample.id}: gold.abstained 需为布尔值`);
      if (has(gold, 'answerRubric') && (!Array.isArray(gold.answerRubric) || gold.answerRubric.some(line => !nonempty(line)))) {
        throw new Error(`${sample.id}: gold.answerRubric 需为非空字符串数组`);
      }
    }
  }
  return dataset;
}

export function citationMetrics(expectedIds, actualIds) {
  const expected = new Set(expectedIds), actual = new Set(actualIds);
  const matches = [...actual].filter(id => expected.has(id));
  return { matchedIds: matches, missingIds: [...expected].filter(id => !actual.has(id)), extraIds: [...actual].filter(id => !expected.has(id)),
    precision: ratio(matches.length, actual.size), recall: ratio(matches.length, expected.size) };
}

export function percentile(values, percent) {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(percent / 100 * ordered.length) - 1)];
}

export function checkStructure(payload) {
  const checks = {
    object: isObject(payload), answer: nonempty(payload?.answer), citationsArray: Array.isArray(payload?.citations),
    abstainedBoolean: typeof payload?.abstained === 'boolean', mode: nonempty(payload?.mode)
  };
  const citations = Array.isArray(payload?.citations) ? payload.citations : [];
  checks.citationIds = citations.every(c => isObject(c) && nonempty(c.id));
  checks.citationIndices = citations.every(c => Number.isInteger(c?.index) && c.index > 0) && new Set(citations.map(c => c?.index)).size === citations.length;
  const referenceIndices = typeof payload?.answer === 'string' ? [...payload.answer.matchAll(/\[(\d+)\]/g)].map(m => Number(m[1])) : [];
  const indices = new Set(citations.map(c => c?.index));
  checks.referenceIndicesValid = referenceIndices.every(index => indices.has(index));
  checks.answerCitesEvidence = payload?.abstained === true || (citations.length > 0 && referenceIndices.length > 0);
  return { passed: Object.values(checks).every(Boolean), checks, referenceIndices };
}

export function parseReviews(raw) {
  const reviews = new Map();
  for (const [index, line] of raw.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    let review;
    try { review = JSON.parse(line); } catch { throw new Error(`人工评分 JSONL 第 ${index + 1} 行不是有效 JSON`); }
    if (!isObject(review) || !nonempty(review.sampleId) || reviews.has(review.sampleId) ||
      !/^[a-f0-9]{64}$/.test(review.datasetSha256 ?? '') || !/^[a-f0-9]{64}$/.test(review.responseSha256 ?? '') ||
      !nonempty(review.reviewer) || !nonempty(review.reviewedAt) || !Number.isFinite(Date.parse(review.reviewedAt)) ||
      !(review.factualCorrect === true || review.factualCorrect === false || review.factualCorrect === null)) {
      throw new Error(`人工评分 JSONL 第 ${index + 1} 行字段不完整、重复 sampleId 或字段类型错误`);
    }
    reviews.set(review.sampleId, review);
  }
  return reviews;
}

export function makeResult(sample, capture) {
  let payload = null, parseError = null;
  if (typeof capture.responseRaw === 'string') {
    try { payload = JSON.parse(capture.responseRaw); } catch { parseError = 'API 响应不是有效 JSON'; }
  }
  const citations = Array.isArray(payload?.citations) ? payload.citations : [];
  const citationIds = [...new Set(citations.map(c => c?.id).filter(nonempty))];
  const gold = sample.gold ?? {};
  return {
    id: sample.id, category: sample.category, input: { question: sample.question }, gold: sample.gold ?? null,
    example: sample.example === true, excludeFromMetrics: sample.excludeFromMetrics === true,
    ...capture, response: payload, error: capture.error || parseError,
    responseSha256: typeof capture.responseRaw === 'string' ? sha256(capture.responseRaw) : null,
    mode: typeof payload?.mode === 'string' ? payload.mode : null, abstained: typeof payload?.abstained === 'boolean' ? payload.abstained : null,
    citationIds, citations,
    automatic: {
      structure: checkStructure(payload),
      citationIds: has(gold, 'citationIds') ? citationMetrics(gold.citationIds, capture.httpStatus >= 200 && capture.httpStatus < 300 && !capture.error && !parseError ? citationIds : []) : null,
      abstention: typeof gold.abstained === 'boolean' ? { expected: gold.abstained, actual: typeof payload?.abstained === 'boolean' ? payload.abstained : null,
        matched: capture.httpStatus >= 200 && capture.httpStatus < 300 && payload?.abstained === gold.abstained } : null
    }
  };
}

export function summarize(dataset, results, reviews, datasetSha256) {
  const eligible = dataset.dataset.status === 'frozen' ? results.filter(r => !r.example && !r.excludeFromMetrics) : [];
  const eligibleIds = new Set(eligible.map(r => r.id));
  const allIds = new Set(results.map(r => r.id));
  for (const id of reviews.keys()) if (!allIds.has(id)) throw new Error(`人工评分引用不存在的 sampleId: ${id}`);
  const scoredCitations = eligible.filter(r => r.automatic.citationIds !== null);
  const matched = scoredCitations.reduce((sum, r) => sum + r.automatic.citationIds.precision.numerator, 0);
  const predicted = scoredCitations.reduce((sum, r) => sum + r.automatic.citationIds.precision.denominator, 0);
  const expected = scoredCitations.reduce((sum, r) => sum + r.automatic.citationIds.recall.denominator, 0);
  const abstentionCases = eligible.filter(r => r.automatic.abstention !== null);
  const human = { eligibleCount: eligible.length, withRubricCount: 0, reviewedCount: 0, correctCount: 0, incorrectCount: 0, unscoredCount: 0, reasons: {} };
  for (const result of results) {
    let reason = null;
    const review = reviews.get(result.id);
    if (!eligibleIds.has(result.id)) reason = 'excluded';
    else {
      const hasRubric = Array.isArray(result.gold?.answerRubric) && result.gold.answerRubric.length > 0;
      if (hasRubric) human.withRubricCount++;
      if (!hasRubric) reason = 'missingGoldRubric';
      else if (result.error || !(result.httpStatus >= 200 && result.httpStatus < 300)) reason = 'requestFailed';
      else if (!review) reason = 'missingReview';
      else if (review.datasetSha256 !== datasetSha256) reason = 'datasetHashMismatch';
      else if (review.responseSha256 !== result.responseSha256) reason = 'responseHashMismatch';
      else if (review.factualCorrect === null) reason = 'reviewUnscored';
      if (reason) {
        human.unscoredCount++;
        human.reasons[reason] = (human.reasons[reason] || 0) + 1;
      } else {
        human.reviewedCount++;
        human[review.factualCorrect ? 'correctCount' : 'incorrectCount']++;
      }
    }
    result.humanReview = { status: reason ?? 'scored', ...(review ? { record: review } : {}) };
  }
  human.coverage = ratio(human.reviewedCount, eligible.length);
  human.reviewedSubsetCorrectness = ratio(human.correctCount, human.reviewedCount);
  human.fullSetFactualAccuracy = {
    numerator: human.correctCount, denominator: eligible.length,
    value: eligible.length && human.unscoredCount === 0 ? human.correctCount / eligible.length : null,
    status: eligible.length && human.unscoredCount === 0 ? 'available' : 'unavailable',
    reason: !eligible.length ? '没有可纳入统计的冻结正式样本' : human.unscoredCount ? '存在缺失金标准、请求失败或未经有效人工复核的样本，不能报告全样本事实准确率' : null
  };
  const latencies = eligible.map(r => r.latencyMs).filter(n => Number.isFinite(n) && n >= 0);
  return {
    totalSamples: results.length, eligibleSamples: eligible.length, excludedSamples: results.length - eligible.length,
    successfulRequests: ratio(eligible.filter(r => r.httpStatus >= 200 && r.httpStatus < 300 && !r.error).length, eligible.length),
    structureChecks: ratio(eligible.filter(r => r.httpStatus >= 200 && r.httpStatus < 300 && r.automatic.structure.passed).length, eligible.length),
    citationIdMatching: { evaluatedSamples: scoredCitations.length, missingGoldSamples: eligible.length - scoredCitations.length,
      precision: ratio(matched, predicted), recall: ratio(matched, expected),
      scope: '仅对提供 gold.citationIds 的题做区分大小写的精确 ID 集合匹配；去重；不检查事实、证据相关性或引用是否支持陈述；无分母为 null' },
    abstention: { evaluatedSamples: abstentionCases.length, missingGoldSamples: eligible.length - abstentionCases.length,
      observedAbstentions: eligible.filter(r => r.abstained === true).length,
      expectedTrue: abstentionCases.filter(r => r.automatic.abstention.expected).length,
      expectationMatch: ratio(abstentionCases.filter(r => r.automatic.abstention.matched).length, abstentionCases.length) },
    latencyMs: { count: latencies.length, includesFailures: true, method: 'nearest-rank', p50: percentile(latencies, 50), p95: percentile(latencies, 95) }, human
  };
}

export async function runRequests(dataset, { baseUrl, timeoutMs = 60000 }) {
  const base = validateBaseUrl(baseUrl), results = [];
  for (const sample of dataset.samples) {
    const start = performance.now();
    let httpStatus = null, responseRaw = null, error = null;
    try {
      const response = await fetch(`${base}/api/ask`, { method: 'POST', redirect: 'error',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: sample.question }), signal: AbortSignal.timeout(timeoutMs) });
      httpStatus = response.status;
      responseRaw = await response.text();
      if (!response.ok) error = `HTTP ${response.status}`;
    } catch (cause) { error = cause.message; }
    results.push(makeResult(sample, { httpStatus, responseRaw, error, latencyMs: Math.round((performance.now() - start) * 100) / 100 }));
  }
  return results;
}

export function parseArgs(args) {
  const options = { baseUrl: process.env.EVAL_BASE_URL || 'http://127.0.0.1:8787', output: 'artifacts/heldout-evaluation.json', timeoutMs: 60000 };
  const names = { '--input': 'input', '--output': 'output', '--base-url': 'baseUrl', '--reviews': 'reviews', '--from-report': 'fromReport', '--timeout-ms': 'timeoutMs' };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') { options.help = true; continue; }
    const key = names[args[i]];
    if (!key || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`无效参数或缺少值: ${args[i]}`);
    options[key] = args[++i];
  }
  options.timeoutMs = Number(options.timeoutMs);
  if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 300000) throw new Error('timeout-ms 需为 1–300000 整数');
  options.baseUrl = validateBaseUrl(options.baseUrl);
  if (!options.help && !options.input) throw new Error('必须使用 --input 指定人工标注样本文件');
  return options;
}

const formatRatio = metric => metric.value === null ? `未定义 (${metric.numerator}/${metric.denominator})` : `${metric.numerator}/${metric.denominator} (${(metric.value * 100).toFixed(1)}%)`;
const cell = value => String(value ?? '—').replaceAll('|', '\\|').replace(/\r?\n/g, ' ');
export function markdownReport(report) {
  const s = report.summary;
  return `# 冻结人工标注集评测\n\n生成时间：${report.generatedAt}；汇总时间：${report.summarizedAt}\n\n${report.scope}\n\n样本文件 SHA-256：${report.input.sha256}\n\n样本 ${s.totalSamples}；正式统计 ${s.eligibleSamples}；排除 ${s.excludedSamples}。样本独立性由导入者声明，工具不能证明其未参与开发。\n\n自动检查：\n\n- 请求成功：${formatRatio(s.successfulRequests)}\n- 响应结构及引用编号检查：${formatRatio(s.structureChecks)}\n- 引用 ID 精确匹配 precision：${formatRatio(s.citationIdMatching.precision)}；recall：${formatRatio(s.citationIdMatching.recall)}。有引用金标准题 ${s.citationIdMatching.evaluatedSamples}，缺失 ${s.citationIdMatching.missingGoldSamples}。\n- 拒答预期匹配：${formatRatio(s.abstention.expectationMatch)}；实际拒答 ${s.abstention.observedAbstentions}；缺少拒答金标准 ${s.abstention.missingGoldSamples}。\n- 延迟 P50：${s.latencyMs.p50 ?? '—'} ms；P95：${s.latencyMs.p95 ?? '—'} ms（nearest-rank，含失败请求）。\n\n人工事实评判：\n\n- 有事实评分准则：${s.human.withRubricCount}/${s.eligibleSamples}；有效人工评分覆盖：${formatRatio(s.human.coverage)}。\n- 已复核子集事实正确计数：${formatRatio(s.human.reviewedSubsetCorrectness)}；此为已复核子集，不代表全样本准确率。\n- 未评分样本：${s.human.unscoredCount}（${JSON.stringify(s.human.reasons)}）。缺失评分仍在正式样本和覆盖率分母中。\n- 全样本事实准确率：${s.human.fullSetFactualAccuracy.value === null ? `不提供。${s.human.fullSetFactualAccuracy.reason}` : formatRatio(s.human.fullSetFactualAccuracy)}\n\n|ID|问题|模式|HTTP|耗时 ms|引用 ID|实际拒答|结构通过|人工状态|\n|---|---|---|---:|---:|---|---|---|---|\n${report.results.map(r => `|${cell(r.id)}|${cell(r.input.question)}|${cell(r.mode)}|${cell(r.httpStatus)}|${r.latencyMs}|${cell(r.citationIds.join(', '))}|${cell(r.abstained)}|${r.automatic.structure.passed}|${cell(r.humanReview.status)}|`).join('\n')}\n\n完整逐题输入、原始响应、答案、引用、错误、金标准及评分记录见同名 JSON。自动引用命中和结构检查均不代表语义正确性，工具不会生成或代替人工评分。\n`;
}

export async function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  if (options.help) {
    console.log('node scripts/evaluate-heldout.mjs --input DATASET.json [--base-url http://127.0.0.1:8787] [--output artifacts/heldout-evaluation.json] [--reviews REVIEWS.jsonl] [--from-report REPORT.json] [--timeout-ms 60000]');
    return;
  }
  const inputPath = resolve(options.input), inputRaw = await readFile(inputPath);
  const dataset = validateDataset(JSON.parse(inputRaw.toString('utf8').replace(/^\uFEFF/, ''))), inputHash = sha256(inputRaw);
  const reviewRaw = options.reviews ? await readFile(resolve(options.reviews)) : null;
  const reviews = parseReviews(reviewRaw ? reviewRaw.toString('utf8').replace(/^\uFEFF/, '') : '');
  const sampleIds = new Set(dataset.samples.map(sample => sample.id));
  for (const id of reviews.keys()) if (!sampleIds.has(id)) throw new Error(`人工评分引用不存在的 sampleId: ${id}`);
  const outputPath = resolve(options.output);
  if (!outputPath.endsWith('.json')) throw new Error('output 需为 .json 文件路径，同时生成同名 .md');
  const markdownPath = outputPath.slice(0, -5) + '.md';
  const protectedPaths = [inputPath, options.reviews && resolve(options.reviews), options.fromReport && resolve(options.fromReport)].filter(Boolean).map(p => p.toLowerCase());
  if ([outputPath, markdownPath].some(p => protectedPaths.includes(p.toLowerCase()))) throw new Error('输出不能覆盖样本、人工评分或原评测报告');
  let results, generatedAt, runId, baseUrl = options.baseUrl, originalReport = null;
  if (options.fromReport) {
    const previousRaw = await readFile(resolve(options.fromReport));
    const previous = JSON.parse(previousRaw.toString('utf8').replace(/^\uFEFF/, ''));
    if (previous.schemaVersion !== 1 || previous.kind !== 'heldout-evaluation' || previous.input?.sha256 !== inputHash || !Array.isArray(previous.results) || previous.results.length !== dataset.samples.length) {
      throw new Error('原报告格式或样本文件 SHA-256 不匹配，禁止把旧回答复用于新样本');
    }
    const byId = new Map(previous.results.map(r => [r.id, r]));
    if (byId.size !== dataset.samples.length) throw new Error('原报告包含重复题目 ID');
    results = dataset.samples.map(sample => {
      const prior = byId.get(sample.id);
      if (!prior || prior.input?.question !== sample.question || !Number.isFinite(prior.latencyMs) || prior.latencyMs < 0 ||
        !(prior.responseRaw === null || typeof prior.responseRaw === 'string') ||
        !(prior.httpStatus === null || (Number.isInteger(prior.httpStatus) && prior.httpStatus >= 100 && prior.httpStatus <= 599))) throw new Error(`原报告题目数据不完整: ${sample.id}`);
      if ((prior.responseRaw === null ? null : sha256(prior.responseRaw)) !== prior.responseSha256) throw new Error(`原报告响应哈希不匹配: ${sample.id}`);
      return makeResult(sample, { httpStatus: prior.httpStatus, responseRaw: prior.responseRaw, error: prior.error, latencyMs: prior.latencyMs });
    });
    baseUrl = validateBaseUrl(previous.baseUrl);
    generatedAt = previous.generatedAt;
    runId = previous.runId;
    originalReport = { path: resolve(options.fromReport), sha256: sha256(previousRaw) };
  } else {
    generatedAt = new Date().toISOString(); runId = randomUUID();
    results = await runRequests(dataset, options);
  }
  const report = {
    schemaVersion: 1, kind: 'heldout-evaluation', runId, generatedAt, summarizedAt: new Date().toISOString(), baseUrl,
    scope: '独立人工标注集导入工具。冻结声明来自数据提供者；自动指标仅检查引用 ID、拒答标志与响应结构，不衡量事实正确性。缺金标准或缺有效人工复核时不报告全样本事实准确率。',
    input: { path: inputPath, sha256: inputHash, dataset: dataset.dataset },
    reviews: reviewRaw ? { path: resolve(options.reviews), sha256: sha256(reviewRaw), records: reviews.size } : null,
    originalReport, summary: summarize(dataset, results, reviews, inputHash), results
  };
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, JSON.stringify(report, null, 2) + '\n');
  await writeFile(markdownPath, markdownReport(report));
  console.log(`报告：${outputPath}\n摘要：${markdownPath}\n正式统计 ${report.summary.eligibleSamples}/${results.length}；人工复核 ${report.summary.human.reviewedCount}/${report.summary.eligibleSamples}；事实准确率${report.summary.human.fullSetFactualAccuracy.value === null ? '未提供' : ` ${(report.summary.human.fullSetFactualAccuracy.value * 100).toFixed(1)}%`}。`);
  // This is a capture/measurement tool, not a benchmark pass gate.
  if (results.some(r => r.error || !(r.httpStatus >= 200 && r.httpStatus < 300))) process.exitCode = 1;
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`评测失败：${error.message}`); process.exitCode = 1; });
}
