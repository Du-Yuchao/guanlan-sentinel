import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { resolve, join, extname, dirname, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createStore } from './lib/store.mjs';
import { normalize, correlate, now, hash, severityOrder, productMatches } from './lib/intelligence.mjs';
import { DEFAULT_SOURCES, collectSource } from './lib/collectors.mjs';
import { mergeObservation } from './lib/ingestion.mjs';
import { createModelService } from './lib/model.mjs';
import { createAnalyst } from './lib/analysis.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const STEP_NAMES = [['plan','规划任务'],['collect','采集来源'],['normalize','归一去重'],['enrich','证据富化'],['correlate','资产关联'],['verify','证据核验'],['report','生成报告']];
const MIME = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.woff2':'font/woff2'};
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const json = (res,status,body) => { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(JSON.stringify(body)); };
async function readBody(req) {
  if (!(req.headers['content-type'] ?? '').includes('application/json')) throw new HttpError(415,'请使用 application/json');
  let length = 0; const chunks = [];
  for await (const chunk of req) { length += chunk.length; if (length > 1024 * 1024) throw new HttpError(413,'请求体不能超过 1 MB'); chunks.push(chunk); }
  try { const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!value||typeof value!=='object')throw new Error();return value; } catch { throw new HttpError(400,'JSON 必须为有效对象或数组'); }
}
function validateAsset(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new HttpError(400,'资产必须为对象');
  const product = String(raw.product ?? raw.name ?? '').trim();
  if (!product || product.length > 150) throw new HttpError(400,'资产产品名必填，且不超过 150 字符');
  const fields = ['name','version','environment','owner','exposure'];
  for (const f of fields) if (raw[f] != null && (typeof raw[f] !== 'string' || raw[f].length > 200)) throw new HttpError(400,`资产 ${f} 必须是长度不超过 200 的字符串`);
  const id = String(raw.id ?? `AST-${randomUUID().slice(0,8)}`);
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id)) throw new HttpError(400,'资产 ID 格式无效');
  return {id,name:raw.name ?? product,product,version:raw.version ?? 'unknown',environment:raw.environment ?? '未分类',owner:raw.owner ?? '未指定',exposure:raw.exposure ?? 'unknown',createdAt:now()};
}
function toMarkdown(store) {
  const items = store.all('intel').sort((a,b)=>severityOrder[b.severity]-severityOrder[a.severity]);
  const assets = correlate(store.all('asset'),items);
  const clean = s => typeof s === 'string' ? s.replace(/[\r\n]+/g,' ') : JSON.stringify(s);
  const statusLabels = {affected:'版本命中',not_affected:'已知区间外',unknown:'待核验'};
  const sections = items.map(i=>`### ${clean(i.title)}\n\n- ID：${i.id}；级别：${i.severity}；发布时间：${i.published || '未知'}\n- 来源：[${clean(i.source)}](${i.url})\n- 摘要：${clean(i.summary)}\n- 修复：${clean(i.remediation)}\n- 条目内容 SHA-256：${i.contentHash}\n- 采集时间：${i.collectedAt}；模式：${i.dataMode ?? 'snapshot'}\n${(i.evidence ?? []).map((e,index)=>`- [证据 ${index+1}](${e.url})：${clean(e.excerpt)}${e.kind==='paraphrase'?'（整理摘要，非逐字引文）':''}\n  证据 SHA-256：${e.hash}`).join('\n')}\n`);
  return `# 观澜 SENTINEL · AI 安全情报报告\n\n生成时间：${now()}\n\n本报告以公开证据与本地资产信息生成。规则评分不是概率；未知版本需要核验。\n\n## 概况\n\n- 情报：${items.length} 条\n- 资产：${assets.length} 项\n- 确认版本命中：${assets.reduce((s,a)=>s+a.findings.filter(f=>f.status==='affected').length,0)} 项\n- 来源模式：公开来源快照与实时任务结果分别保留，请查看来源状态。\n\n## 资产处置\n\n${assets.map(a=>`### ${clean(a.name)} · ${clean(a.version)}\n\n${a.findings.map(f=>`- ${f.id}：${statusLabels[f.status] ?? '待核验'}；${clean(f.reason)}。建议：${clean(f.remediation)} [公告](${f.url})`).join('\n') || '- 当前知识库未匹配到公告，此结果不等于安全保证。'}`).join('\n\n')}\n\n## 情报与证据\n\n${sections.join('\n')}`;
}

export function createApplication({ dataDir = process.env.SENTINEL_DATA_DIR || join(ROOT,'data','runtime'), seedPath = join(ROOT,'data','verified_sources.json'), collector = collectSource, modelEnv = process.env, modelFetch = globalThis.fetch } = {}) {
  const store = createStore(resolve(dataDir),seedPath);
  const modelService=createModelService({dataDir:resolve(dataDir),env:modelEnv,fetchImpl:modelFetch});
  const verifiedSnapshots=new Map(store.readSeed().filter(i=>i.verifiedAt).map(i=>[i.id,i]));
  // Repair earlier sparse-live merges even when an old advisory no longer
  // appears in an upstream's limited recent-results window.
  for(const [id,snapshot] of verifiedSnapshots) {
    const prior=store.get('intel',id);
    if(prior?.dataMode!=='live')continue;
    const restored=mergeObservation(prior,normalize(snapshot),{mode:'demo',at:now(),verifiedSnapshot:snapshot});
    const fields=['title','summary','affected','fixed','remediation','ranges','relatedIds','contentHash','verifiedAt'];
    if(fields.some(field=>JSON.stringify(prior[field])!==JSON.stringify(restored[field]))) {
      store.put('intel',restored);store.audit('intel.verified-context-restored',{id,verifiedAt:snapshot.verifiedAt});
    }
  }
  for (const source of DEFAULT_SOURCES) {
    const saved = store.get('source',source.id);
    store.put('source',{...source,...saved,adapter:source.adapter,url:source.url,description:source.description});
  }
  let activeRun = null, activeExecution = null, monitorTimer = null, closing = false;
  const mode = () => {const config=modelService.getPublicConfig();return {llm:config.ready,label:config.ready?'RAG · 本地检索 + 模型生成':'本地证据检索',...(config.ready?{model:config.model,provider:config.provider}:{})};};
  const intel = () => store.all('intel');
  const assets = () => correlate(store.all('asset'),intel());
  const sources = () => store.all('source').map(s=>({...s,count:intel().filter(i=>i.source===s.name || i.sourceId===s.id).length || s.count || 0}));
  function graph() {
    const items = intel(), nodes = [], edges = [], seen = new Set();
    const addNode = node => { if (!seen.has(node.id)) { nodes.push(node); seen.add(node.id); } };
    for (const i of items) {
      addNode({id:i.id,label:i.title,type:i.type,severity:i.severity,url:i.url});
      for (const p of i.products) { const id=`product:${p.toLowerCase()}`; addNode({id,label:p,type:'product'}); edges.push({source:i.id,target:id,label:'涉及产品'}); }
      for (const t of i.categories ?? i.tags.slice(0,3)) { const id=`topic:${t}`; addNode({id,label:t,type:'topic'}); edges.push({source:i.id,target:id,label:'风险分类'}); }
      for (const related of i.relatedIds ?? []) if (items.some(j=>j.id===related)) edges.push({source:i.id,target:related,label:'关联证据'});
    }
    for (const a of assets()) {
      addNode({id:a.id,label:`${a.name} ${a.version}`,type:'asset'});
      for (const f of a.findings) edges.push({source:a.id,target:f.id,label:f.status==='affected'?'版本命中':f.status==='unknown'?'待核验':'已知区间外',status:f.status});
    }
    return {nodes,edges};
  }
  function recommendations() {
    return assets().flatMap(a=>a.findings.filter(f=>f.status!=='not_affected').map(f=>({assetId:a.id,assetName:a.name,intelId:f.id,title:f.title,severity:f.severity,status:f.status,action:f.remediation,reason:f.reason,url:f.url}))).sort((a,b)=>severityOrder[b.severity]-severityOrder[a.severity]).slice(0,12);
  }
  async function execute(run) {
    let collected = [], prepared = [], successfulSources = 0, failedSources = 0, mirroredSources = 0;
    const step = async (id, fn) => {
      const s=run.steps.find(x=>x.id===id); s.status='running'; s.startedAt=now(); store.put('run',run);
      const start=Date.now();
      try { const result=await fn(); s.status='completed'; s.detail=result.detail; s.count=result.count; }
      catch(e) { s.status='failed'; s.detail=e.message; throw e; }
      finally { s.durationMs=Date.now()-start; s.finishedAt=now(); store.put('run',run); }
    };
    try {
      await step('plan',async()=>({detail:`已规划 ${DEFAULT_SOURCES.length} 类来源；${run.mode==='demo'?'使用已保存公开证据快照，验证本地处理链':'固定白名单公开来源，执行受限采集'}；无主动扫描`,count:DEFAULT_SOURCES.length}));
      await step('collect',async()=>{
        if(run.mode==='demo') { collected=store.readSeed(); return {detail:`读取 ${collected.length} 条公开来源快照；本次未访问外网，原始发布时间与来源链接保留`,count:collected.length}; }
        const results=await Promise.allSettled(DEFAULT_SOURCES.map(async source=>{
          const prior=store.get('source',source.id) ?? source;
          try {
            const result=await collector(source);
            const transport=result.transport ?? {url:source.url,mode:'primary'};
            const mirrored=transport.mode==='official-mirror';
            const previousHash=prior.contentHashes?.[transport.url] ?? (prior.transport?.url===transport.url ? prior.contentHash : null);
            const changed=previousHash ? previousHash!==result.hash : null;
            const syncedAt=now();
            const status={...prior,status:mirrored?'degraded':'healthy',lastSync:syncedAt,lastSuccess:syncedAt,lastPrimarySuccess:mirrored?(prior.lastPrimarySuccess ?? null):syncedAt,count:result.items.length,contentHash:result.hash,contentHashes:{...prior.contentHashes,[transport.url]:result.hash},changed,detail:result.detail,error:null,errorCode:null,transport,mode:'live'};
            store.put('source',status); store.audit('source.collected',{sourceId:source.id,contentHash:result.hash,changed,count:result.items.length,transport});
            if(mirrored)mirroredSources++;
            successfulSources++; return result.items.map(i=>({...i,sourceId:source.id}));
          } catch(e) { failedSources++; store.put('source',{...prior,status:'error',lastSync:now(),error:e.message,errorCode:e.code ?? e.cause?.code ?? null,transport:e.transport ?? null,detail:'本次实时采集失败；保留此前快照',mode:'live'}); store.audit('source.failed',{sourceId:source.id,error:e.message,code:e.code ?? null,transport:e.transport ?? null}); throw e; }
        }));
        run.sourceResults=DEFAULT_SOURCES.map(s=>store.get('source',s.id));
        run.sourceStats={total:DEFAULT_SOURCES.length,primary:successfulSources-mirroredSources,mirrored:mirroredSources,failed:failedSources};
        collected=results.filter(r=>r.status==='fulfilled').flatMap(r=>r.value);
        if(!successfulSources) throw new Error(`${failedSources} 个来源全部采集失败；未生成新的实时情报，已有快照保留`);
        return {detail:`${successfulSources-mirroredSources} 个主站成功，${mirroredSources} 个使用官方备用，${failedSources} 个失败；获取 ${collected.length} 条公告/论文。固定页面检查仅记录变更哈希。`,count:collected.length};
      });
      await step('normalize',async()=>{
        const ids=new Set(),urls=new Set(); let duplicate=0;
        prepared=collected.map(i=>normalize({...i,dataMode:run.mode==='demo'?'snapshot':'live'})).filter(i=>{if(ids.has(i.id)||(i.url&&urls.has(i.url))){duplicate++;return false;}ids.add(i.id);if(i.url)urls.add(i.url);return true;});
        return {detail:`归一 ${prepared.length} 条，批内去重 ${duplicate} 条；以 ID 持久化合并`,count:prepared.length};
      });
      await step('enrich',async()=>{
        const corpus=[...intel(),...prepared];
        prepared=prepared.map(i=>mergeObservation(store.get('intel',i.id),i,{mode:run.mode,runId:run.id,at:now(),verifiedSnapshot:verifiedSnapshots.get(i.id)}));
        prepared=prepared.map(i=>({ ...i,
          enrichment:{ products:i.products,versionRanges:i.ranges ?? [],riskCategories:i.categories,cvss:i.cvss,relatedPapers:corpus.filter(j=>j.type==='paper' && j.id!==i.id && j.tags.some(t=>i.tags.includes(t))).slice(0,4).map(j=>j.id),publicReferences:(i.references ?? []).slice(0,10),remediation:i.remediation,evidenceIntegrity:i.evidence.every(e=>e.hash===hash(e.excerpt)),dimensions:['产品与版本','风险分类与CVSS','关联研究','公开参考链接','资产影响','修复建议','证据完整性'],note:'缺失维度保留待核验；公开 PoC 链接仅索引，不执行' }
        }));
        for(const item of prepared) {
          store.put('intel',item);
        }
        return {detail:`完成 7 个维度处理并记录缺失字段；规则来源分不是准确率或统计概率`,count:prepared.length};
      });
      await step('correlate',async()=>{ const list=assets();const findings=list.flatMap(a=>a.findings);return {detail:`关联 ${list.length} 项资产：${findings.filter(f=>f.status==='affected').length} 条版本命中，${findings.filter(f=>f.status==='unknown').length} 条待核验；未匹配不等于无风险`,count:findings.length};});
      await step('verify',async()=>{ const valid=intel().filter(i=>i.url && i.evidence.length && i.evidence.every(e=>e.hash===hash(e.excerpt)));return {detail:`${valid.length}/${intel().length} 条通过来源链接及快照哈希完整性检查；此检查不等于事实准确率评测`,count:valid.length};});
      await step('report',async()=>{const report=toMarkdown(store);store.put('report',{id:run.id,createdAt:now(),markdown:report,hash:hash(report)});return {detail:`已生成报告与处置建议，SHA-256 ${hash(report).slice(0,16)}…`,count:1};});
      run.status=failedSources||mirroredSources?'partial':'completed';run.summary=`${run.mode==='demo'?'快照演示':'实时采集'}完成，处理 ${prepared.length} 条情报${run.mode==='live'?`；主站成功 ${successfulSources-mirroredSources}，官方备用 ${mirroredSources}，失败 ${failedSources}`:''}`;
    } catch(e) {run.status='failed';run.summary=e.message;}
    finally {run.finishedAt=now();store.put('run',run);store.audit('run.finished',{runId:run.id,status:run.status,mode:run.mode});activeRun=null;}
  }
  function startRun(requestedMode='demo') {
    if(!['demo','live'].includes(requestedMode)) throw new HttpError(400,'mode 必须为 demo 或 live');
    if(activeRun) throw new HttpError(409,'已有任务执行中，请等待完成');
    const run={id:`RUN-${randomUUID().slice(0,8)}`,mode:requestedMode,status:'running',startedAt:now(),finishedAt:null,steps:STEP_NAMES.map(([id,name])=>({id,name,status:'pending',detail:'等待执行',durationMs:null})),summary:'任务已创建'};
    store.put('run',run);activeRun=run.id;setImmediate(()=>{ if(!closing) activeExecution=execute(run); });return run;
  }
  function monitorConfig() { return store.get('config','monitor') ?? {id:'monitor',enabled:false,intervalMinutes:360,lastRun:null,nextRun:null}; }
  function scheduleMonitor() {
    if(monitorTimer) clearTimeout(monitorTimer);
    const cfg=monitorConfig();if(!cfg.enabled || closing) return;
    const delay=Math.max(1000,Date.parse(cfg.nextRun ?? '')-Date.now() || cfg.intervalMinutes*60000);
    monitorTimer=setTimeout(()=>{
      if(!activeRun) { try {startRun('live');cfg.lastRun=now();}catch{} }
      cfg.nextRun=new Date(Date.now()+cfg.intervalMinutes*60000).toISOString();store.put('config',cfg);scheduleMonitor();
    },delay);monitorTimer.unref();
  }
  scheduleMonitor();
  const ask=createAnalyst({getIntel:intel,getAssets:assets,getRecommendations:recommendations,modelService,audit:(action,detail)=>store.audit(action,detail)});
  const server=http.createServer(async(req,res)=>{
    res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const host=req.headers.host ?? '';
      if(!/^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host)) throw new HttpError(403,'仅接受本机 Host');
      const url=new URL(req.url,`http://${host}`), path=url.pathname;
      if(['POST','PUT','PATCH','DELETE'].includes(req.method)) {
        if(req.headers.origin && req.headers.origin!==`http://${host}` && req.headers.origin!==`https://${host}`) throw new HttpError(403,'跨来源写请求被拒绝');
        if(req.headers['sec-fetch-site']==='cross-site') throw new HttpError(403,'跨站写请求被拒绝');
      }
      if(req.method==='GET' && path==='/api/model/config') return json(res,200,{config:modelService.getPublicConfig(),mode:mode()});
      if(req.method==='POST' && path==='/api/model/config') {
        const config=await modelService.updateConfig(await readBody(req));
        store.audit('model.config.updated',{enabled:config.enabled,provider:config.provider,model:config.model,apiKeySet:config.apiKeySet,includeAssets:config.includeAssets});
        return json(res,200,{config:modelService.getPublicConfig(),mode:mode()});
      }
      if(req.method==='POST' && path==='/api/model/test') {
        const input=await readBody(req);
        try {return json(res,200,await modelService.testConnection(input));}
        catch(error) {return json(res,200,{ok:false,error:error.message});}
      }
      if(req.method==='GET' && path==='/api/health') return json(res,200,{ok:true,name:'观澜 SENTINEL',version:'1.0.0',time:now(),mode:mode(),database:'sqlite',activeRun});
      if(req.method==='GET' && path==='/api/overview') {
        const items=intel(), sourceList=sources(), assetList=assets();
        const categories=['vulnerability','paper','standard','policy'].map(name=>({name,count:items.filter(i=>i.type===name).length}));
        const dates=[...new Set(items.map(i=>i.published?.slice(0,10)).filter(Boolean))].sort().slice(-14);
        return json(res,200,{stats:{total:items.length,critical:items.filter(i=>i.severity==='critical').length,sources:sourceList.length,assets:assetList.length,affected:assetList.flatMap(a=>a.findings).filter(f=>f.status==='affected').length},trend:dates.map(date=>({date,count:items.filter(i=>i.published.startsWith(date)).length})),categories,recent:items.sort((a,b)=>(b.published ?? '').localeCompare(a.published ?? '')).slice(0,8),sourceHealth:sourceList,mode:mode(),recommendations:recommendations(),monitor:monitorConfig()});
      }
      if(req.method==='GET' && path==='/api/intel') {const q=(url.searchParams.get('q') ?? '').toLowerCase(),type=url.searchParams.get('type'),severity=url.searchParams.get('severity');const items=intel().filter(i=>(!q || JSON.stringify(i).toLowerCase().includes(q))&&(!type || type==='all' || i.type===type)&&(!severity || severity==='all' || i.severity===severity));return json(res,200,{items,total:items.length});}
      if(req.method==='GET' && path.startsWith('/api/intel/')) {const item=store.get('intel',decodeURIComponent(path.slice(11)));if(!item) throw new HttpError(404,'情报不存在');return json(res,200,{item,evidence:item.evidence,related:intel().filter(i=>i.id!==item.id && ((item.relatedIds ?? []).includes(i.id)||i.products.some(p=>item.products.some(x=>productMatches(p,x)))||i.tags.some(t=>item.tags.includes(t)))).slice(0,8),assets:assets().filter(a=>a.findings.some(f=>f.id===item.id))});}
      if(req.method==='GET' && path==='/api/graph') return json(res,200,graph());
      if(req.method==='GET' && path==='/api/assets') return json(res,200,{items:assets()});
      if(req.method==='POST' && path==='/api/assets') {const asset=validateAsset(await readBody(req));store.put('asset',asset);store.audit('asset.created',{id:asset.id});return json(res,201,{item:correlate([asset],intel())[0]});}
      if(req.method==='POST' && path==='/api/assets/import') {
        const body=await readBody(req);
        if(body.components !== undefined && (!Array.isArray(body.components) || body.components.some(c=>!c||typeof c!=='object'))) throw new HttpError(400,'CycloneDX components 必须为对象数组');
        const list=Array.isArray(body)?body:body.assets ?? (body.components?.map(c=>({name:c.name,product:c.name,version:c.version,environment:'SBOM',owner:'SBOM 导入',exposure:'unknown'})));
        if(!Array.isArray(list)||!list.length||list.length>200) throw new HttpError(400,'需提供 1–200 项 assets 数组或 CycloneDX components');
        const validated=list.map(validateAsset);for(const a of validated) store.put('asset',a);store.audit('assets.imported',{count:validated.length});return json(res,201,{imported:validated.length,items:correlate(validated,intel())});
      }
      if(req.method==='GET' && path==='/api/sources') return json(res,200,{items:sources()});
      if(req.method==='GET' && path==='/api/runs') return json(res,200,{items:store.all('run').slice(0,50)});
      if(req.method==='POST' && path==='/api/runs') {const body=await readBody(req);const run=startRun(body.mode ?? 'demo');return json(res,202,{runId:run.id,run});}
      if(req.method==='GET' && path.startsWith('/api/runs/')) {const run=store.get('run',path.slice(10));if(!run) throw new HttpError(404,'任务不存在');return json(res,200,{run});}
      if(req.method==='POST' && path==='/api/ask') {const body=await readBody(req);if(typeof body.question!=='string'||!body.question.trim()||body.question.length>4000) throw new HttpError(400,'问题长度需在 1–4000 字符');return json(res,200,await ask(body.question.trim(),body.history ?? []));}
      if(req.method==='GET' && path==='/api/report') {res.writeHead(200,{'Content-Type':'text/markdown; charset=utf-8','Content-Disposition':'attachment; filename="sentinel-intelligence-report.md"'});return res.end(toMarkdown(store));}
      if(req.method==='GET' && path==='/api/audit') return json(res,200,{items:store.audits()});
      if(req.method==='GET' && path==='/api/monitor') return json(res,200,monitorConfig());
      if(req.method==='POST' && path==='/api/monitor') {const body=await readBody(req);const interval=Number(body.intervalMinutes ?? 360);if(typeof body.enabled!=='boolean'||!Number.isInteger(interval)||interval<5||interval>1440) throw new HttpError(400,'enabled 必须为布尔值，intervalMinutes 需在 5–1440 之间');const cfg={...monitorConfig(),enabled:body.enabled,intervalMinutes:interval,nextRun:body.enabled?new Date(Date.now()+interval*60000).toISOString():null};store.put('config',cfg);scheduleMonitor();store.audit('monitor.updated',cfg);return json(res,200,cfg);}
      if(path.startsWith('/api/')) throw new HttpError(404,'接口不存在');
      if(!['GET','HEAD'].includes(req.method)) throw new HttpError(405,'不支持的方法');
      let decoded;try {decoded=decodeURIComponent(path);}catch{throw new HttpError(400,'路径无效');}
      if(decoded.includes('\0')||decoded.includes('\\')||decoded.split('/').includes('..')) throw new HttpError(403,'路径被拒绝');
      const staticDir=join(ROOT,'static'), publicPath=decoded.startsWith('/static/')?decoded.slice(7):decoded, filename=resolve(staticDir,'.'+(publicPath==='/'?'/index.html':publicPath));
      if(!filename.startsWith(staticDir+sep)) throw new HttpError(403,'路径被拒绝');
      try {const info=await stat(filename);if(!info.isFile()) throw new Error();const bytes=await readFile(filename);res.writeHead(200,{'Content-Type':MIME[extname(filename)] ?? 'application/octet-stream','Cache-Control':'no-cache'});return res.end(req.method==='HEAD'?undefined:bytes);}catch{throw new HttpError(404,'页面不存在');}
    } catch(e) { if(!res.headersSent) json(res,e.status ?? 500,{error:e.status?e.message:'服务内部错误，请查看本地日志'}); else res.end(); if(!e.status) console.error('[SENTINEL]',e.message); }
  });
  server.requestTimeout=30000;server.headersTimeout=10000;
  return {server,store,startRun,ask,graph,mode,modelService,close:async()=>{closing=true;if(monitorTimer)clearTimeout(monitorTimer);await new Promise(resolve=>server.close(resolve));server.closeAllConnections();if(activeExecution)await activeExecution;if(activeRun){const run=store.get('run',activeRun);run.status='interrupted';run.finishedAt=now();store.put('run',run);}store.close();}};
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const app=createApplication(); const port=Number(process.env.PORT ?? 8787),host=process.env.HOST ?? '127.0.0.1';
  app.server.listen(port,host,()=>console.log(`观澜 SENTINEL 已启动：http://${host}:${app.server.address().port} · ${app.mode().label}`));
  let exiting=false;for(const signal of ['SIGINT','SIGTERM']) process.on(signal,async()=>{if(exiting)return;exiting=true;await app.close();process.exit(0);});
}
