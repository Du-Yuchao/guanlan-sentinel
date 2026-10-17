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
export function retrieve(question, items, limit = 6) {
  const q = String(question).toLowerCase();
  const cves = q.match(/cve-\d{4}-\d{4,}/g) ?? [];
  if (cves.some(id => !items.some(x => x.id.toLowerCase() === id || `${x.title} ${x.summary}`.toLowerCase().includes(id)))) return [];
  const english = q.match(/[a-z][a-z0-9_.-]{2,}/g) ?? [];
  const ignored = new Set(['the','and','what','how','about','are','with','for','this','that','please','tell','cve','security','漏洞']);
  const chinese = q.match(/[\u4e00-\u9fff]{2,}/g) ?? [];
  const terms = new Set(english.filter(x => !ignored.has(x)));
  for (const s of chinese) for (let i = 0; i < s.length - 1; i++) terms.add(s.slice(i, i + 2));
  for (const group of synonyms) if (group.some(s => q.includes(s))) for (const s of group) terms.add(s);
  return items.map(item => {
    const title = `${item.id} ${item.title} ${item.products.join(' ')} ${item.tags.join(' ')}`.toLowerCase();
    const body = `${title} ${item.summary} ${JSON.stringify(item.affected)} ${JSON.stringify(item.remediation)}`.toLowerCase();
    let score = 0, matched = [];
    for (const t of terms) if (body.includes(t)) { score += title.includes(t) ? (t.length > 3 ? 5 : 2) : 1; matched.push(t); }
    for (const id of cves) if (item.id.toLowerCase() === id || title.includes(id)) score += 50;
    for (const p of item.products) if (q.includes(p.toLowerCase())) score += 20;
    return { item, score, matched };
  }).filter(x => x.score >= 4 && x.matched.length > 0).sort((a,b) => b.score - a.score).slice(0, limit);
}
