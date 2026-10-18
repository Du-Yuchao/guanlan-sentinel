import { hash, now } from './intelligence.mjs';

// This is the source file of the official page, not a cached copy or a third-party mirror.
// Verified against https://github.com/huggingface/hub-docs/blob/main/docs/hub/security-pickle.md
const HF_PAGE = 'https://huggingface.co/docs/hub/security-pickle';
export const HF_OFFICIAL_MIRROR = 'https://api.github.com/repos/huggingface/hub-docs/contents/docs/hub/security-pickle.md?ref=main';

export const DEFAULT_SOURCES = [
  { id:'nvd',name:'NVD 漏洞库',category:'vulnerability',categoryLabel:'公开漏洞数据库',url:'https://nvd.nist.gov/',adapter:'nvd',description:'NVD 2.0 API，Ollama 关键词结果页，最多 20 条；非全量增量采集' },
  { id:'github',name:'GitHub Security Advisories',category:'repository',categoryLabel:'代码仓库与安全公告',url:'https://github.com/advisories',adapter:'github',description:'公开安全公告 API，最近 100 条中筛选 AI 产品' },
  { id:'vendor',name:'Hugging Face 安全公告',category:'vendor',categoryLabel:'厂商安全公告',url:HF_PAGE,adapter:'page',description:'固定官方安全页面变更监测；主站不可用时实时读取官方 GitHub 同文档源码，并明确标记备用状态' },
  { id:'blog',name:'Trail of Bits 安全研究',category:'blog',categoryLabel:'专业安全博客',url:'https://blog.trailofbits.com/index.xml',adapter:'blog',description:'官方 RSS，最多读取 15 篇 AI 相关研究摘要' },
  { id:'arxiv',name:'arXiv AI 安全论文',category:'paper',categoryLabel:'学术论文',url:'https://arxiv.org/',adapter:'arxiv',description:'arXiv Atom API，prompt injection 关键词最新 10 篇' },
  { id:'standards',name:'NIST AI RMF / OWASP',category:'standard',categoryLabel:'标准与安全框架',url:'https://www.nist.gov/itl/ai-risk-management-framework',adapter:'page',description:'固定官方框架页面变更监测，不代表全站发现' },
  { id:'policy',name:'中国网信网 AI 政策',category:'policy',categoryLabel:'政府政策',url:'https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm',adapter:'page',description:'生成式人工智能服务管理暂行办法，固定页面变更监测' }
].map(s => ({ ...s, status:'snapshot', lastSync:null, count:0 }));

export class CollectionError extends Error {
  constructor(code, message, { cause, retryable = false, ...details } = {}) {
    super(message, { cause }); this.name = 'CollectionError'; this.code = code;
    this.retryable = retryable; Object.assign(this, details);
  }
}
const fail = (code, message, details) => new CollectionError(code, message, details);
const boundedNumber = (value, fallback, maximum) => Number.isFinite(value) && value > 0 ? Math.min(value, maximum) : fallback;
const cancelBody = body => { try { Promise.resolve(body?.cancel()).catch(() => {}); } catch {} };
function checkedUrl(value, base) {
  let url;
  try { url = new URL(value, base); } catch (cause) { throw fail('INVALID_URL', '来源地址无效', {cause}); }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw fail('UNSAFE_URL', '来源和重定向只允许无凭据的 HTTPS 标准端口地址');
  }
  url.hash = ''; return url;
}
function diagnose(error) {
  if (error instanceof CollectionError) return error;
  const code = error.cause?.code ?? error.code;
  if (['EACCES','EPERM'].includes(code)) return fail('NETWORK_PERMISSION', '网络访问被运行环境权限拦截，请在允许联网的环境中启动服务', {cause:error});
  if (/CERT|TLS|SSL|UNABLE_TO_VERIFY|SELF_SIGNED/.test(code ?? '')) return fail('TLS_ERROR', `来源 TLS 证书校验失败${code ? `（${code}）` : ''}`, {cause:error});
  if (error.name === 'TimeoutError' || ['ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_BODY_TIMEOUT'].includes(code)) return fail('TIMEOUT', '连接或读取来源超时，请检查网络或代理', {cause:error,retryable:true});
  if (['EAI_AGAIN','ECONNRESET','ECONNREFUSED','ECONNABORTED','EPIPE','EHOSTUNREACH','ENETUNREACH','UND_ERR_SOCKET'].includes(code)) return fail('NETWORK_TRANSIENT', `来源临时网络故障（${code}）`, {cause:error,retryable:true});
  if (code === 'ENOTFOUND') return fail('DNS_ERROR', '来源域名解析失败（ENOTFOUND）', {cause:error});
  if (error.name === 'AbortError') return fail('ABORTED', '来源采集已取消', {cause:error});
  return fail('NETWORK_ERROR', `来源连接或读取失败${code ? `（${code}）` : ''}`, {cause:error});
}
function abortable(promise, signal) {
  if (signal.aborted) { Promise.resolve(promise).catch(() => {}); return Promise.reject(signal.reason); }
  return new Promise((resolve, reject) => {
    const abort = () => { cleanup(); reject(signal.reason); };
    const cleanup = () => signal.removeEventListener('abort', abort);
    signal.addEventListener('abort', abort, {once:true});
    Promise.resolve(promise).then(value => { cleanup(); resolve(value); }, error => { cleanup(); reject(error); });
  });
}
function retryDelay(response) {
  const value = response.headers.get('retry-after');
  if (!value) return 0;
  const millis = /^\d+(?:\.\d+)?$/.test(value.trim()) ? Number(value) * 1000 : Date.parse(value) - Date.now();
  return Number.isFinite(millis) ? Math.max(0,millis) : 0;
}
// Metadata is kept separate so existing boundedFetch callers still receive a string.
export async function boundedFetchResult(url, {
  timeout = 10000, totalTimeout = 20000, maxBytes = 2500000, headers = {},
  maxRetries = 2, maxRedirects = 3, backoffMs = 250, maxBackoffMs = 2000,
  allowedRedirectOrigins = [], signal, fetchImpl = globalThis.fetch
} = {}) {
  const initial = checkedUrl(url);
  timeout = boundedNumber(timeout, 10000, 20000);
  totalTimeout = boundedNumber(totalTimeout, 20000, 20000);
  maxBytes = boundedNumber(maxBytes, 2500000, 2500000);
  maxRetries = Math.max(0, Math.min(2, Math.floor(Number(maxRetries) || 0)));
  maxRedirects = Math.max(0, Math.min(3, Math.floor(Number(maxRedirects) || 0)));
  backoffMs = Math.max(0, Math.min(2000, Number(backoffMs) || 0));
  maxBackoffMs = Math.max(backoffMs, Math.min(2000, Number(maxBackoffMs) || 0));
  const origins = new Set([initial.origin, ...allowedRedirectOrigins.map(value => checkedUrl(value).origin)]);
  const deadline = Date.now() + totalTimeout;
  let attempts = 0, redirects = 0, lastError;
  for (let retry = 0; retry <= maxRetries; retry++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const controller = new AbortController();
    const attemptDeadline = Date.now() + Math.min(timeout,remaining);
    const expire = () => controller.abort(fail('TIMEOUT', '连接或读取来源超时，请检查网络或代理', {retryable:true}));
    const checkDeadline = () => { if (Date.now() >= attemptDeadline && !controller.signal.aborted) expire(); if (controller.signal.aborted) throw controller.signal.reason; };
    const timer = setTimeout(expire,Math.min(timeout,remaining));
    const outerAbort = () => controller.abort(signal.reason ?? fail('ABORTED', '来源采集已取消'));
    if (signal?.aborted) outerAbort(); else signal?.addEventListener('abort', outerAbort, {once:true});
    let current = initial, response, reader;
    try {
      for (let hop = 0;; hop++) {
        checkDeadline();
        const requestHeaders = new Headers({'User-Agent':'Guanlan-Sentinel/1.0 research-intelligence', ...headers});
        if (current.origin !== initial.origin) { requestHeaders.delete('authorization'); requestHeaders.delete('cookie'); }
        attempts++;
        response = await abortable(fetchImpl(current.href, {signal:controller.signal,redirect:'manual',headers:requestHeaders}), controller.signal);
        if (![301,302,303,307,308].includes(response.status)) break;
        cancelBody(response.body);
        if (hop >= maxRedirects) throw fail('REDIRECT_LIMIT', '来源重定向次数超过限制');
        const location = response.headers.get('location');
        if (!location) throw fail('INVALID_REDIRECT', '来源重定向缺少 Location 地址');
        const next = checkedUrl(location, current);
        if (!origins.has(next.origin)) throw fail('UNSAFE_REDIRECT', '来源跨域重定向不在审计允许列表中');
        current = next; redirects++;
      }
      if (!response.ok) {
        cancelBody(response.body);
        throw fail(`HTTP_${response.status}`, `上游 HTTP ${response.status}`, {status:response.status,retryable:response.status === 429 || response.status >= 500 && response.status <= 599,retryAfterMs:retryDelay(response)});
      }
      if (Number(response.headers.get('content-length') ?? 0) > maxBytes) {
        cancelBody(response.body); throw fail('RESPONSE_TOO_LARGE', '上游响应超过大小限制');
      }
      // A fixed buffer also bounds memory when an upstream emits millions of tiny chunks.
      let size = 0; const buffer = Buffer.allocUnsafe(Math.ceil(maxBytes));
      if (response.body) {
        reader = response.body.getReader();
        while (true) {
          checkDeadline();
          const {value,done} = await abortable(reader.read(),controller.signal);
          if (done) break;
          if (size + value.byteLength > maxBytes) throw fail('RESPONSE_TOO_LARGE', '上游响应超过大小限制');
          buffer.set(value,size); size += value.byteLength;
        }
      }
      checkDeadline();
      return {text:buffer.subarray(0,size).toString('utf8'),url:current.href,attempts,redirects,retries:retry};
    } catch (error) {
      // Cancel without awaiting: an uncooperative upstream must not extend the deadline.
      try { Promise.resolve(reader?.cancel()).catch(() => {}); } catch {}
      lastError = diagnose(controller.signal.aborted ? controller.signal.reason : error);
      Object.assign(lastError,{url:current.href,attempts,redirects,retries:retry});
    } finally {
      clearTimeout(timer); signal?.removeEventListener('abort',outerAbort);
    }
    if (signal?.aborted || !lastError.retryable || retry === maxRetries) throw lastError;
    const wait = Math.max(Math.min(maxBackoffMs,backoffMs * 2 ** retry),lastError.retryAfterMs ?? 0);
    // If the server requests a longer wait, give up this run instead of retrying too early.
    if (wait > maxBackoffMs || Date.now() + wait >= deadline) break;
    if (wait) {
      const waitController = new AbortController();
      const stop = () => waitController.abort(signal.reason ?? fail('ABORTED', '来源采集已取消'));
      signal?.addEventListener('abort',stop,{once:true});
      let waitTimer;
      try {
        await abortable(new Promise(resolve => { waitTimer = setTimeout(resolve,wait); }),waitController.signal);
      } finally { clearTimeout(waitTimer); signal?.removeEventListener('abort',stop); }
    }
  }
  throw lastError ?? fail('TIMEOUT', '来源采集总时限已到', {retryable:true,attempts,url:initial.href});
}
export async function boundedFetch(url, options) { return (await boundedFetchResult(url,options)).text; }
const strip = text => String(text ?? '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/\s+/g,' ').trim();
const aiPattern = /ollama|llama|hugging.?face|transformers|pytorch|tensorflow|langchain|langgraph|vllm|litellm|prompt.?injection|artificial intelligence|machine learning|large language/i;
const severityFromCvss = v => v >= 9 ? 'critical' : v >= 7 ? 'high' : v >= 4 ? 'medium' : v > 0 ? 'low' : 'info';
function pageBody(raw) {
  const body = strip(raw);
  if (body.length < 200 || /captcha|access denied|verify you are human/i.test(body.slice(0,1000))) throw fail('INVALID_RESPONSE','上游返回验证页或正文不足');
  return body;
}
export async function collectSource(source, {sourceTimeout = 20000, primaryTimeout = 10000, signal, ...requestOptions} = {}) {
  const budget = boundedNumber(sourceTimeout,20000,20000);
  const deadline = Date.now() + budget, controller = new AbortController();
  const timer = setTimeout(() => controller.abort(fail('SOURCE_TIMEOUT','本来源采集总时限已到',{retryable:true})),budget);
  const cancel = () => controller.abort(signal.reason ?? fail('ABORTED','来源采集已取消'));
  if (signal?.aborted) cancel(); else signal?.addEventListener('abort',cancel,{once:true});
  let transport;
  const request = async (url, extra = {}) => {
    if (controller.signal.aborted || Date.now() >= deadline) throw controller.signal.reason ?? fail('SOURCE_TIMEOUT','本来源采集总时限已到',{retryable:true});
    const useMirror = source.id === 'vendor' && source.adapter === 'page' && url === HF_PAGE;
    const options = {...requestOptions,...extra,signal:controller.signal,totalTimeout:Math.min(deadline-Date.now(),useMirror ? boundedNumber(primaryTimeout,10000,budget) : budget)};
    let primary, primaryError;
    try {
      primary = await boundedFetchResult(url,options);
      if (useMirror) pageBody(primary.text);
      transport = {url:primary.url,mode:'primary',attempts:primary.attempts,redirects:primary.redirects,retries:primary.retries};
      return primary.text;
    } catch (error) {
      if (primary) Object.assign(error,{url:primary.url,attempts:primary.attempts,redirects:primary.redirects,retries:primary.retries});
      primaryError = error;
      const fallbackAllowed = ['TIMEOUT','NETWORK_TRANSIENT','DNS_ERROR','NETWORK_ERROR','INVALID_RESPONSE','HTTP_403','HTTP_429'].includes(error.code) || /^HTTP_5\d\d$/.test(error.code);
      if (!useMirror || !fallbackAllowed || controller.signal.aborted) throw error;
    }
    const primaryDetails = {primaryUrl:url,primaryErrorUrl:primaryError.url ?? url,primaryError:primaryError.message,primaryErrorCode:primaryError.code};
    let mirror;
    try {
      mirror = await boundedFetchResult(HF_OFFICIAL_MIRROR,{
        ...requestOptions,signal:controller.signal,totalTimeout:Math.max(1,deadline-Date.now()),
        headers:{Accept:'application/vnd.github.raw+json','X-GitHub-Api-Version':'2022-11-28'},
        // GitHub Contents may redirect to this raw-file CDN; HTTPS is still mandatory.
        allowedRedirectOrigins:['https://raw.githubusercontent.com']
      });
      if (!/^#\s+Pickle Scanning\b/m.test(mirror.text)) throw fail('INVALID_RESPONSE','官方备用未返回预期的 Pickle Scanning 文档源码');
      pageBody(mirror.text);
      transport = {url:mirror.url,mode:'official-mirror',...primaryDetails,mirrorStatus:'succeeded',attempts:(primaryError.attempts ?? 1)+mirror.attempts,redirects:(primaryError.redirects ?? 0)+mirror.redirects,retries:(primaryError.retries ?? 0)+mirror.retries};
      return mirror.text;
    } catch (mirrorError) {
      throw fail('FALLBACK_FAILED',`主站失败：${primaryError.message}；官方备用失败：${mirrorError.message}`,{
        cause:mirrorError,transport:{
          url:mirrorError.url ?? mirror?.url ?? HF_OFFICIAL_MIRROR,mode:'official-mirror',...primaryDetails,
          mirrorStatus:'failed',mirrorErrorCode:mirrorError.code,mirrorError:mirrorError.message,
          attempts:(primaryError.attempts ?? 1)+(mirrorError.attempts ?? mirror?.attempts ?? 0),
          redirects:(primaryError.redirects ?? 0)+(mirrorError.redirects ?? mirror?.redirects ?? 0),
          retries:(primaryError.retries ?? 0)+(mirrorError.retries ?? mirror?.retries ?? 0)
        },
        primaryErrorCode:primaryError.code,mirrorErrorCode:mirrorError.code
      });
    }
  };
  try {
    const result = await collectSourceData(source,request,now());
    return {...result,transport,detail:transport?.mode === 'official-mirror' ? `${result.detail}；主站请求失败：${transport.primaryError}；已实时读取 Hugging Face 官方 GitHub 同文档源码（备用成功），不代表主站恢复` : result.detail};
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) throw fail('INVALID_RESPONSE','上游数据格式不符合预期',{cause:error});
    throw error;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort',cancel); }
}
async function collectSourceData(source, request, at) {
  if (source.adapter === 'nvd') {
    const raw = await request('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ollama&resultsPerPage=20');
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
    const raw = await request('https://api.github.com/advisories?per_page=100&type=reviewed', {headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}});
    const items = JSON.parse(raw).filter(x => aiPattern.test(`${x.summary} ${x.description} ${JSON.stringify(x.vulnerabilities)}`)).map(x => ({
      id:x.cve_id ?? x.ghsa_id,title:x.summary,type:'vulnerability',source:source.name,url:x.html_url,published:x.published_at,severity:x.severity,cvss:x.cvss?.score ?? null,summary:(x.description ?? '').slice(0,6000),products:(x.vulnerabilities ?? []).map(v => v.package.name),affected:(x.vulnerabilities ?? []).map(v => `${v.package.name}: ${v.vulnerable_version_range}`).join('; '),fixed:(x.vulnerabilities ?? []).map(v => v.first_patched_version ?? '未给出').join('; '),references:x.references ?? [],evidence:[{excerpt:x.description?.slice(0,6000) ?? x.summary,url:x.html_url,collectedAt:at}],dataMode:'live'
    }));
    return { items,hash:hash(raw),detail:`检查最近 100 条公开公告，AI 相关 ${items.length} 条；不声称全量覆盖` };
  }
  if (source.adapter === 'arxiv') {
    const raw = await request('https://export.arxiv.org/api/query?search_query=all:%22prompt%20injection%22&start=0&max_results=10&sortBy=submittedDate&sortOrder=descending');
    const entries = [...raw.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map(m => m[1]);
    const field = (s,n) => strip(s.match(new RegExp(`<${n}[^>]*>([\\s\\S]*?)<\\/${n}>`))?.[1] ?? '');
    const items = entries.map(e => { const url = field(e,'id').replace('http:','https:'); return {id:`ARXIV-${url.split('/').pop()}`,title:field(e,'title'),type:'paper',source:source.name,url,published:field(e,'published'),severity:'info',summary:field(e,'summary'),products:[],tags:['提示词注入','研究论文'],dataMode:'live'}; });
    return {items,hash:hash(raw),detail:`arXiv Atom 返回 ${items.length} 篇论文`};
  }
  if (source.adapter === 'blog') {
    const raw = await request(source.url);
    const field = (s,n) => strip(s.match(new RegExp(`<${n}[^>]*>([\\s\\S]*?)<\\/${n}>`))?.[1]?.replace(/<!\[CDATA\[|\]\]>/g,'') ?? '');
    const entries = [...raw.matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0,15).map(m=>m[1]);
    const items = entries.filter(e=>aiPattern.test(strip(e))).map(e=>({id:`BLOG-${hash(field(e,'link')).slice(0,12)}`,title:field(e,'title'),type:'paper',source:source.name,url:field(e,'link'),published:field(e,'pubDate'),severity:'info',summary:field(e,'description').slice(0,4000),products:[],tags:['安全研究'],dataMode:'live'}));
    return {items,hash:hash(raw),detail:`官方 RSS 检查 ${entries.length} 篇，AI 相关 ${items.length} 篇`};
  }
  // Only built-in, audited URLs are passed here. User-provided URLs never enter collectors.
  const raw = await request(source.url);
  const body = pageBody(raw);
  return { items:[],hash:hash(body),detail:`固定官方页面已检查，正文 ${body.length} 字符；变更哈希已记录`,pageExcerpt:body.slice(0,500) };
}
