import { hash, now } from './intelligence.mjs';

export const DEFAULT_SOURCES = [
  { id:'nvd',name:'NVD 漏洞库',category:'vulnerability',categoryLabel:'公开漏洞数据库',url:'https://nvd.nist.gov/',adapter:'nvd',description:'NVD 2.0 API，Ollama 关键词结果页，最多 20 条；非全量增量采集' },
  { id:'github',name:'GitHub Security Advisories',category:'repository',categoryLabel:'代码仓库与安全公告',url:'https://github.com/advisories',adapter:'github',description:'公开安全公告 API，最近 100 条中筛选 AI 产品' },
  { id:'vendor',name:'Hugging Face 安全公告',category:'vendor',categoryLabel:'厂商安全公告',url:'https://huggingface.co/docs/hub/security-pickle',adapter:'page',description:'固定官方安全页面变更监测，不代表全站发现' },
  { id:'blog',name:'Trail of Bits 安全研究',category:'blog',categoryLabel:'专业安全博客',url:'https://blog.trailofbits.com/index.xml',adapter:'blog',description:'官方 RSS，最多读取 15 篇 AI 相关研究摘要' },
  { id:'arxiv',name:'arXiv AI 安全论文',category:'paper',categoryLabel:'学术论文',url:'https://arxiv.org/',adapter:'arxiv',description:'arXiv Atom API，prompt injection 关键词最新 10 篇' },
  { id:'standards',name:'NIST AI RMF / OWASP',category:'standard',categoryLabel:'标准与安全框架',url:'https://www.nist.gov/itl/ai-risk-management-framework',adapter:'page',description:'固定官方框架页面变更监测，不代表全站发现' },
  { id:'policy',name:'中国网信网 AI 政策',category:'policy',categoryLabel:'政府政策',url:'https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm',adapter:'page',description:'生成式人工智能服务管理暂行办法，固定页面变更监测' }
].map(s => ({ ...s, status:'snapshot', lastSync:null, count:0 }));

export async function boundedFetch(url, { timeout = 12000, maxBytes = 2500000, headers = {} } = {}) {
  let response;
  try { response = await fetch(url, { signal:AbortSignal.timeout(timeout), redirect:'error', headers:{ 'User-Agent':'Guanlan-Sentinel/1.0 research-intelligence', ...headers } }); }
  catch (error) {
    const code = error.cause?.code;
    const message = ['EACCES','EPERM'].includes(code) ? '网络访问被运行环境权限拦截，请在允许联网的环境中启动服务' : error.name === 'TimeoutError' ? '连接来源超时，请检查网络或代理' : `来源连接失败${code ? `（${code}）` : ''}`;
    throw new Error(message, {cause:error});
  }
  if (!response.ok) throw new Error(`上游 HTTP ${response.status}`);
  if (Number(response.headers.get('content-length') ?? 0) > maxBytes) throw new Error('上游响应超过大小限制');
  const reader = response.body.getReader(); let size = 0; const chunks = [];
  try { while (true) { const { value,done } = await reader.read(); if (done) break; size += value.length; if (size > maxBytes) throw new Error('上游响应超过大小限制'); chunks.push(value); } }
  finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).toString('utf8');
}
const strip = text => String(text ?? '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/\s+/g,' ').trim();
const aiPattern = /ollama|llama|hugging.?face|transformers|pytorch|tensorflow|langchain|langgraph|vllm|litellm|prompt.?injection|artificial intelligence|machine learning|large language/i;
const severityFromCvss = v => v >= 9 ? 'critical' : v >= 7 ? 'high' : v >= 4 ? 'medium' : v > 0 ? 'low' : 'info';
export async function collectSource(source) {
  const at = now();
  if (source.adapter === 'nvd') {
    const raw = await boundedFetch('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ollama&resultsPerPage=20');
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities ?? []).map(({ cve }) => {
      const metric = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0] ?? cve.metrics?.cvssMetricV2?.[0];
      const cvss = metric?.cvssData?.baseScore ?? null;
      const summary = cve.descriptions?.find(d => d.lang === 'en')?.value ?? '';
      return { id:cve.id,title:`${cve.id} · Ollama 安全漏洞`,type:'vulnerability',source:source.name,url:`https://nvd.nist.gov/vuln/detail/${cve.id}`,published:cve.published,severity:severityFromCvss(cvss),cvss,summary,products:['Ollama'],tags:(cve.weaknesses ?? []).flatMap(w => w.description.map(d => d.value)),references:cve.references ?? [],affected:'自动采集，版本区间待人工核验',evidence:[{excerpt:summary,url:`https://nvd.nist.gov/vuln/detail/${cve.id}`,collectedAt:at}],dataMode:'live' };
    });
    return { items, hash:hash(raw), detail:`NVD API 返回 ${items.length} 条，版本区间保留待核验` };
  }
  if (source.adapter === 'github') {
    const raw = await boundedFetch('https://api.github.com/advisories?per_page=100&type=reviewed', {headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}});
    const items = JSON.parse(raw).filter(x => aiPattern.test(`${x.summary} ${x.description} ${JSON.stringify(x.vulnerabilities)}`)).map(x => ({
      id:x.cve_id ?? x.ghsa_id,title:x.summary,type:'vulnerability',source:source.name,url:x.html_url,published:x.published_at,severity:x.severity,cvss:x.cvss?.score ?? null,summary:(x.description ?? '').slice(0,6000),products:(x.vulnerabilities ?? []).map(v => v.package.name),affected:(x.vulnerabilities ?? []).map(v => `${v.package.name}: ${v.vulnerable_version_range}`).join('; '),fixed:(x.vulnerabilities ?? []).map(v => v.first_patched_version ?? '未给出').join('; '),references:x.references ?? [],evidence:[{excerpt:x.description?.slice(0,6000) ?? x.summary,url:x.html_url,collectedAt:at}],dataMode:'live'
    }));
    return { items,hash:hash(raw),detail:`检查最近 100 条公开公告，AI 相关 ${items.length} 条；不声称全量覆盖` };
  }
  if (source.adapter === 'arxiv') {
    const raw = await boundedFetch('https://export.arxiv.org/api/query?search_query=all:%22prompt%20injection%22&start=0&max_results=10&sortBy=submittedDate&sortOrder=descending');
    const entries = [...raw.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map(m => m[1]);
    const field = (s,n) => strip(s.match(new RegExp(`<${n}[^>]*>([\\s\\S]*?)<\\/${n}>`))?.[1] ?? '');
    const items = entries.map(e => { const url = field(e,'id').replace('http:','https:'); return {id:`ARXIV-${url.split('/').pop()}`,title:field(e,'title'),type:'paper',source:source.name,url,published:field(e,'published'),severity:'info',summary:field(e,'summary'),products:[],tags:['提示词注入','研究论文'],dataMode:'live'}; });
    return {items,hash:hash(raw),detail:`arXiv Atom 返回 ${items.length} 篇论文`};
  }
  if (source.adapter === 'blog') {
    const raw = await boundedFetch(source.url);
    const field = (s,n) => strip(s.match(new RegExp(`<${n}[^>]*>([\\s\\S]*?)<\\/${n}>`))?.[1]?.replace(/<!\[CDATA\[|\]\]>/g,'') ?? '');
    const entries = [...raw.matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0,15).map(m=>m[1]);
    const items = entries.filter(e=>aiPattern.test(strip(e))).map(e=>({id:`BLOG-${hash(field(e,'link')).slice(0,12)}`,title:field(e,'title'),type:'paper',source:source.name,url:field(e,'link'),published:field(e,'pubDate'),severity:'info',summary:field(e,'description').slice(0,4000),products:[],tags:['安全研究'],dataMode:'live'}));
    return {items,hash:hash(raw),detail:`官方 RSS 检查 ${entries.length} 篇，AI 相关 ${items.length} 篇`};
  }
  // Only built-in, audited URLs are passed here. User-provided URLs never enter collectors.
  const raw = await boundedFetch(source.url);
  const body = strip(raw);
  if (body.length < 200 || /captcha|access denied|verify you are human/i.test(body.slice(0,1000))) throw new Error('上游返回验证页或正文不足');
  return { items:[],hash:hash(body),detail:`固定官方页面已检查，正文 ${body.length} 字符；变更哈希已记录`,pageExcerpt:body.slice(0,500) };
}
