import { createHash } from 'node:crypto';

export const hash = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
export const now = () => new Date().toISOString();
export const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const cap = (v, n = 4000) => String(v ?? '').slice(0, n);
export function normalize(raw, collectedAt = now()) {
  const url = /^https?:\/\//i.test(String(raw.url)) ? cap(raw.url, 2000) : '';
  const summary = cap(raw.summary ?? raw.description);
  const title = cap(raw.title ?? raw.id ?? '未命名情报', 400);
  const tags = Array.isArray(raw.tags) ? raw.tags.slice(0, 30).map(x => cap(x, 100)) : [];
  const content = `${title} ${summary} ${tags.join(' ')}`;
  const classes = [];
  if (/prompt|injection|注入|越狱|jailbreak/i.test(content)) classes.push('提示词注入');
  if (/supply.chain|pickle|供应链|反序列化/i.test(content)) classes.push('供应链安全');
  if (/execution|RCE|执行/i.test(content)) classes.push('代码执行');
  if (/disclos|泄露|隐私|privacy/i.test(content)) classes.push('数据泄露');
  if (/denial|DoS|拒绝服务/i.test(content)) classes.push('拒绝服务');
  if (!classes.length) classes.push(raw.type === 'standard' ? '安全治理' : 'AI 安全');
  const source = cap(raw.source ?? '未知来源', 150);
  const official = /nvd\.nist\.gov|github\.com\/advisories|cve\.org|owasp\.org|atlas\.mitre\.org|nist\.gov/i.test(url);
  const evidence = (Array.isArray(raw.evidence) ? raw.evidence : raw.evidence ? [raw.evidence] : [{ excerpt: summary, url }]).map((e, i) => {
    const item = typeof e === 'string' ? { excerpt: e } : e;
    const excerpt = cap(item.excerpt ?? item.quote ?? item.text ?? summary, 6000);
    return { ...item, id: item.id ?? `ev-${i + 1}`, url: item.url ?? url, excerpt, hash: hash(excerpt), collectedAt: item.collectedAt ?? collectedAt, snapshot: raw.dataMode !== 'live', mode: raw.dataMode ?? 'snapshot' };
  });
  return {
    ...raw, id: cap(raw.id ?? `INT-${hash(url || title).slice(0, 12)}`, 100), title,
    type: ['vulnerability','paper','standard','policy'].includes(raw.type) ? raw.type : 'vulnerability',
    source, url, published: cap(raw.published ?? raw.publishedAt ?? '', 50),
    severity: Object.hasOwn(severityOrder, raw.severity) ? raw.severity : 'info',
    cvss: Number.isFinite(raw.cvss) ? raw.cvss : null, summary,
    products: Array.isArray(raw.products) ? raw.products.map(x => cap(x, 150)).slice(0, 30) : [],
    tags: [...new Set([...tags, ...classes])], categories: classes,
    affected: raw.affected ?? '需查阅原始公告确认受影响版本', fixed: raw.fixed ?? '待核验',
    remediation: raw.remediation ?? '核验原始公告并评估升级；收紧权限和网络暴露。',
    evidence, collectedAt: raw.collectedAt ?? collectedAt, updatedAt: collectedAt,
    contentHash: hash({ title, summary, url, evidence: evidence.map(e => e.hash) }),
    confidence: { score: official ? 95 : /arxiv\.org/i.test(url) ? 80 : 65, kind: 'rule', label: '来源规则分，非统计概率', reasons: [official ? '官方漏洞库或安全组织来源' : '公开研究或社区来源', '保留原始链接与证据快照哈希'] }
  };
}
function cleanProduct(v) { return String(v ?? '').toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]/g, ''); }
export function productMatches(a, b) {
  const x = cleanProduct(a), y = cleanProduct(b);
  return Boolean(x && y && (x === y || (Math.min(x.length, y.length) >= 6 && (x.includes(y) || y.includes(x)))));
}
export function compareVersions(a, b) {
  if (!/^v?\d+(?:\.\d+){0,3}$/.test(String(a)) || !/^v?\d+(?:\.\d+){0,3}$/.test(String(b))) return null;
  const av = String(a).replace(/^v/, '').split('.').map(Number), bv = String(b).replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(av.length, bv.length); i++) { const d = (av[i] ?? 0) - (bv[i] ?? 0); if (d) return Math.sign(d); }
  return 0;
}
function extractRanges(item) {
  const candidates = item.ranges ?? item.versionRanges ?? item.affectedRanges;
  if (Array.isArray(candidates) && candidates.length) return candidates;
  if (item.fixedVersion) return [{ fixed: item.fixedVersion }];
  if (Array.isArray(item.affected)) return item.affected;
  // Only derive unambiguous numeric fixed releases; otherwise preserve unknown status.
  if (/^(?:>=?\s*)?v?\d+(?:\.\d+){1,3}$/.test(String(item.fixed).trim())) return [{ fixed: String(item.fixed).replace(/^>=?\s*/, '') }];
  return [];
}
export function assetFinding(asset, item) {
  if (item.type !== 'vulnerability' || !item.products.some(p => productMatches(asset.product, p))) return null;
  const ranges = extractRanges(item).filter(r => !r.product || productMatches(asset.product, r.product));
  let status = 'unknown', reason = '产品匹配，版本区间证据不足，需人工核验';
  if (compareVersions(asset.version, '0') === null) reason = '产品匹配，资产版本未知或格式不支持，需人工核验';
  else if (ranges.length) {
    const outcomes = ranges.map(r => {
      const fixed = r.fixed ?? r.fixedVersion ?? r.versionEndExcluding;
      const start = r.introduced ?? r.versionStartIncluding ?? '0';
      const last = r.lastAffected ?? r.versionEndIncluding;
      if (fixed && compareVersions(asset.version, fixed) === null) return 'unknown';
      if (compareVersions(asset.version, start) === null) return 'unknown';
      if (last && compareVersions(asset.version, last) === null) return 'unknown';
      if (compareVersions(asset.version, start) < 0 || (fixed && compareVersions(asset.version, fixed) >= 0) || (last && compareVersions(asset.version, last) > 0)) return 'not_affected';
      return fixed || last ? 'affected' : 'unknown';
    });
    status = outcomes.includes('affected') ? 'affected' : outcomes.every(x => x === 'not_affected') ? 'not_affected' : 'unknown';
    reason = status === 'affected' ? '产品与已核验受影响版本区间匹配' : status === 'not_affected' ? '版本位于已知受影响区间之外；仅针对本条公告' : reason;
  }
  return { id: item.id, intelId: item.id, title: item.title, severity: item.severity, status, reason, url: item.url, remediation: item.remediation, fixed: item.fixed, ranges };
}
export function correlate(assets, intel) {
  return assets.map(a => ({ ...a, findings: intel.map(i => assetFinding(a, i)).filter(Boolean) }));
}
const synonyms = [
  ['提示词','提示注入','提示注入攻击','prompt','injection','越狱','jailbreak','提示词注入'],
  ['供应链','supply','pickle','反序列化'], ['漏洞','vulnerability'],
  ['执行','execution','rce'], ['标准','standard','框架','nist','owasp'],
  ['模型','model'], ['修复','升级','fixed','remediation']
];
const retrievalProductKey = value => String(value ?? '').toLowerCase().trim().replace(/[\s._-]+/g, ' ');
const escapePattern = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function productMentionPattern(key) {
  // Treat separators as spelling variants, but do not read a product inside a
  // longer token, package, domain or hyphenated product name.
  const name = key.split(' ').map(escapePattern).join('[\\s._-]+');
  return new RegExp(`(?<![a-z0-9_])(?<![a-z0-9][.-])${name}(?![a-z0-9_]|[.-][a-z0-9])`, 'g');
}
function mentionedProducts(question, items) {
  const products = new Set(items.flatMap(item => item.products ?? []).map(retrievalProductKey).filter(Boolean));
  const mentions = [...products].flatMap(key => [...question.matchAll(productMentionPattern(key))].map(match => ({
    key, start: match.index, end: match.index + match[0].length
  })));
  // A known multiword product takes precedence over a shorter known name at
  // the same position. A separate mention of the shorter name still counts.
  return [...new Set(mentions.filter(mention => !mentions.some(other => other.key !== mention.key &&
    other.start <= mention.start && other.end >= mention.end && other.end - other.start > mention.end - mention.start))
    .sort((a, b) => a.start - b.start).map(mention => mention.key))];
}
const explicitCves = text => [...new Set(String(text).toLowerCase().match(/\bcve-\d{4}-\d{4,}\b/g) ?? [])];
function includesTerm(text, term) {
  return /^[a-z0-9_.-]+$/.test(term) ? new RegExp(`(?<![a-z0-9])${escapePattern(term)}(?![a-z0-9])`).test(text) : text.includes(term);
}
export function retrieve(question, items, limit = 6) {
  const q = String(question).toLowerCase();
  const cves = explicitCves(q);
  const itemCves = new Map(items.map(item => [item, explicitCves(`${item.id} ${item.title} ${item.summary}`)]));
  if (cves.some(id => !items.some(item => itemCves.get(item).includes(id)))) return [];
  const requestedProducts = mentionedProducts(q, items);
  const requestedProductSet = new Set(requestedProducts);
  const english = q.match(/[a-z][a-z0-9_.-]{2,}/g) ?? [];
  const ignored = new Set(['the','and','what','how','about','are','with','for','this','that','please','tell','cve','security','漏洞']);
  const chinese = q.match(/[\u4e00-\u9fff]{2,}/g) ?? [];
  const terms = new Set(english.filter(x => !ignored.has(x)));
  for (const s of chinese) for (let i = 0; i < s.length - 1; i++) terms.add(s.slice(i, i + 2));
  for (const group of synonyms) if (group.some(s => q.includes(s))) for (const s of group) terms.add(s);
  const ranked = items.map(item => {
    const products = (item.products ?? []).map(retrievalProductKey);
    const coveredProducts = products.filter(product => requestedProductSet.has(product));
    const matchingCves = itemCves.get(item).filter(id => cves.includes(id));
    // Generic words such as "漏洞/修复" must not pull a different named
    // product into a question with an explicit product identity.
    if (requestedProducts.length && products.length && !coveredProducts.length && !matchingCves.length) return null;
    const title = `${item.id} ${item.title} ${(item.products ?? []).join(' ')} ${(item.tags ?? []).join(' ')}`.toLowerCase();
    const body = `${title} ${item.summary} ${JSON.stringify(item.affected)} ${JSON.stringify(item.remediation)}`.toLowerCase();
    let score = 0, matched = [];
    for (const t of terms) if (includesTerm(body, t)) { score += includesTerm(title, t) ? (t.length > 3 ? 5 : 2) : 1; matched.push(t); }
    score += matchingCves.length * 50;
    for (const product of coveredProducts) { score += 20; matched.push(`product:${product}`); }
    // A bounded preference for reviewed evidence never creates relevance by
    // itself, and remains much smaller than an explicit CVE match.
    if (score >= 4 && matched.length && item.verifiedAt && Number.isFinite(Date.parse(item.verifiedAt))) score += 8;
    return { item, score, matched, coveredProducts };
  }).filter(row => row && row.score >= 4 && row.matched.length > 0).sort((a, b) => b.score - a.score);
  const selected = [], selectedItems = new Set();
  const add = row => { if (row && !selectedItems.has(row.item)) { selected.push(row); selectedItems.add(row.item); } };
  // Put coverage before the score-only fill so a downstream top-five display
  // keeps all explicitly requested products when at most five are named.
  for (const product of requestedProducts) {
    if (selected.length >= limit) break;
    if (!selected.some(row => row.coveredProducts.includes(product))) add(ranked.find(row => row.coveredProducts.includes(product)));
  }
  for (const row of ranked) { if (selected.length >= limit) break; add(row); }
  return selected.map(({ coveredProducts, ...row }) => row);
}
