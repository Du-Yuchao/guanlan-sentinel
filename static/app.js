'use strict';

const ICONS = {
  overview:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  sparkles:'<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5Z"/><path d="m20 2 .5 1.5L22 4l-1.5.5L20 6l-.5-1.5L18 4l1.5-.5Z"/>',
  graph:'<circle cx="12" cy="12" r="3"/><circle cx="5" cy="4" r="2"/><circle cx="20" cy="5" r="2"/><circle cx="4" cy="19" r="2"/><circle cx="20" cy="19" r="2"/><path d="m6 6 4 4m4-1 4-3M6 18l4-4m4 0 4 4"/>',
  assets:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M16 6.5h2M16 17.5h2"/>',
  runs:'<path d="m9 3 10 6v6l-10 6-5-3V6Z"/><path d="m9 9 6 3-6 3Z"/>',
  arrow:'<path d="M5 12h14m-5-5 5 5-5 5"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  down:'<path d="m6 9 6 6 6-6"/>',
  external:'<path d="M14 3h7v7m0-7L10 14"/><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
  download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
  upload:'<path d="M12 16V4m-5 5 5-5 5 5M4 16v4h16v-4"/>',
  refresh:'<path d="M20 7a9 9 0 0 0-15-2L3 8m0-5v5h5M4 17a9 9 0 0 0 15 2l2-3m0 5v-5h-5"/>',
  shield:'<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6Z"/><path d="m8 12 3 3 5-6"/>',
  alert:'<path d="m12 3 10 18H2Z"/><path d="M12 9v5m0 3v.01"/>',
  database:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 4 16 4 16 0V5M4 12v7c0 4 16 4 16 0v-7"/>',
  globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  book:'<path d="M3 4h6l3 2 3-2h6v15h-6l-3 2-3-2H3Zm9 2v15"/>',
  file:'<path d="M14 2H5v20h14V7Zm0 0v5h5M8 12h8M8 16h6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  plus:'<path d="M12 4v16M4 12h16"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.01"/>',
  menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
  play:'<path d="m7 4 14 8-14 8Z"/>',
  link:'<path d="m10 14 4-4m-5-2 3-3a5 5 0 0 1 7 7l-3 3m-1 1-3 3a5 5 0 0 1-7-7l3-3"/>',
  filter:'<path d="M3 5h18l-7 8v6l-4 2v-8Z"/>',
  terminal:'<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3m6 0h5"/>',
  network:'<circle cx="12" cy="5" r="3"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.file}</svg>`;
const $ = (query, root=document) => root.querySelector(query);
const $$ = (query, root=document) => [...root.querySelectorAll(query)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = url => {try {const u=new URL(url);return ['https:','http:'].includes(u.protocol)?esc(u.href):'#';}catch{return '#';}};
const asArray = value => Array.isArray(value)?value:[];
const shortDate = value => value ? String(value).slice(0,10) : '未记录';
const dateTime = value => {if(!value)return '尚未同步';const d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});};
const TYPES = {vulnerability:'漏洞情报',paper:'研究论文',standard:'安全标准',policy:'政策动态'};
const SEVERITIES = {critical:'严重',high:'高危',medium:'中危',low:'低危',info:'信息'};
const STATUSES = {completed:'已完成',complete:'已完成',success:'已完成',running:'运行中',pending:'等待中',failed:'失败',error:'失败',partial:'部分完成',interrupted:'已中断',queued:'排队中',warning:'有提示',skipped:'已跳过',healthy:'正常',ok:'正常',idle:'待采集',snapshot:'离线快照',offline:'离线快照',available:'可用',active:'正常',configured:'已配置'};
const PAGES = [{id:'overview',name:'情报总览',icon:'overview'},{id:'explore',name:'情报探索',icon:'search'},{id:'ask',name:'智能研判',icon:'sparkles'},{id:'graph',name:'知识图谱',icon:'graph'},{id:'assets',name:'资产影响',icon:'assets'},{id:'runs',name:'智能体运行',icon:'runs'}];
const state = {route:'overview',pageToken:0,filter:{q:'',type:'',severity:''},mode:null,graph:null,graphSelected:null,messages:[],asking:false,runId:null,runTimer:null,monitor:null,drawerFocus:null,modalFocus:null};
const badge = level => `<span class="badge severity-${Object.hasOwn(SEVERITIES,level)?level:'info'}">${SEVERITIES[level]||'信息'}</span>`;
const tags = values => asArray(values).slice(0,4).map(v=>`<span class="tag">${esc(v)}</span>`).join('');
const typeName = type => TYPES[type] || type || '知识条目';
const empty = (title,description,action='') => `<div class="empty">${icon('search')}<h3>${esc(title)}</h3><p>${esc(description)}</p>${action}</div>`;
const loading = (message='正在加载情报数据') => `<div class="loading"><span class="spinner"></span>${esc(message)}</div>`;

async function api(path,options={}) {
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),65000);
  try {
    const res=await fetch(path,{...options,headers:{'Content-Type':'application/json',...options.headers},signal:controller.signal});
    let data;
    try {data=await res.json();} catch {throw new Error('服务返回了无法识别的数据，请确认后端已启动。');}
    if(!res.ok)throw new Error(typeof data.error==='string'?data.error:data.message||`请求失败（${res.status}）`);
    return data;
  } catch(error) {
    if(error.name==='AbortError')throw new Error('请求超时，请稍后重试。');
    if(error instanceof TypeError)throw new Error('暂时无法连接本地服务，请确认启动窗口仍然运行。');
    throw error;
  } finally {clearTimeout(timeout);}
}
function toast(message,error=false){const el=document.createElement('div');el.className=`toast${error?' error':''}`;el.textContent=message;$('#toasts').appendChild(el);setTimeout(()=>el.remove(),6500);}
function setMode(mode){state.mode=mode;$('#mode-label').innerHTML=`<i class="status-dot"></i>${esc(mode?.llm?'大模型增强研判':'本地证据检索')}`;}
function heading(eyebrow,title,description,actions=''){return `<div class="page-heading"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p>${description}</p></div><div class="heading-actions">${actions}</div></div>`;}
const runButton = `<button class="btn btn-primary" data-action="run">${icon('play')}运行采集</button>`;
const exportButton = `<button class="btn" data-action="export">${icon('download')}<span class="export-label">导出报告</span></button>`;
function go(route,query=''){location.hash=route+(query?'?'+query:'');}
function tableRows(items,full=false){return items.map(item=>`<tr tabindex="0" role="button" aria-label="查看 ${esc(item.title)}" data-intel="${esc(item.id)}"><td><span class="table-title">${esc(item.title)}</span><div class="table-meta"><span>${esc(typeName(item.type))}</span><span>·</span><span>${esc(asArray(item.products).join(' / ') || asArray(item.tags).slice(0,2).join(' / ') || 'AI 安全')}</span></div></td><td>${badge(item.severity)}</td><td class="nowrap">${esc(item.source||'公开来源')}</td>${full?`<td class="nowrap">${esc(shortDate(item.published))}</td>`:''}<td>${icon('chevron')}</td></tr>`).join('');}
function intelTable(items,full=false){return `<div class="table-scroll"><table class="intelligence-table ${full?'explore-table':''}"><thead><tr><th>情报标题</th><th>风险等级</th><th>情报来源</th>${full?'<th>发布时间</th>':''}<th aria-label="查看详情"></th></tr></thead><tbody>${tableRows(items,full)}</tbody></table></div>`;}
function sourceRows(sources){return sources.map(source=>`<div class="source-row"><span class="source-logo">${esc((source.name||source.id||'S').slice(0,2).toUpperCase())}</span><div class="source-info"><strong>${esc(source.name||source.id)}</strong><small>${source.count!==undefined?`${Number(source.count)||0} 条情报 · `:''}${esc(source.lastSync?dateTime(source.lastSync):'等待首次采集')}</small></div><span class="source-status"><i class="status-dot" ${['failed','error'].includes(source.status)?'style="background:#dc8690"':''}></i>${esc(STATUSES[source.status]||source.status||'已配置')}</span></div>`).join('');}

async function route(){
  const [raw,query='']=location.hash.slice(1).split('?');
  state.route=PAGES.some(p=>p.id===raw)?raw:'overview';
  const token=++state.pageToken;
  $('#sidebar').classList.remove('open');
  $$('.nav-item').forEach(el=>{el.classList.toggle('active',el.dataset.route===state.route);el.setAttribute('aria-current',el.dataset.route===state.route?'page':'false');});
  $('#breadcrumb-current').textContent=PAGES.find(p=>p.id===state.route).name;
  $('#main').innerHTML=loading();
  document.title=`${PAGES.find(p=>p.id===state.route).name} · 观澜 SENTINEL`;
  try {
    let html='';
    if(state.route==='overview')html=await overviewPage();
    if(state.route==='explore'){state.filter.q=new URLSearchParams(query).get('q')||'';html=await explorePage();}
    if(state.route==='ask')html=askPage();
    if(state.route==='graph')html=await graphPage();
    if(state.route==='assets')html=await assetsPage();
    if(state.route==='runs')html=await runsPage();
    if(token!==state.pageToken)return;
    $('#main').innerHTML=`<div class="page-fade">${html}</div>`;
    if(state.route==='graph')renderGraph();
    if(state.route==='ask')renderMessages();
  }catch(error){if(token===state.pageToken)$('#main').innerHTML=empty('加载遇到问题',error.message,'<button class="btn" data-action="retry">重新加载</button>');}
}

function trendChart(trend){
  const items=asArray(trend);if(!items.length||!items.some(p=>Number(p.count)>0))return empty('暂无趋势数据','执行采集后，将展示情报条目的发布日期分布。');
  const w=640,h=145,left=28,right=12,top=12,bottom=25;
  const max=Math.max(1,...items.map(p=>Number(p.count)||0));
  const ceiling=Math.ceil(max/4)*4;
  const x=i=>left+(items.length===1?.5:i/(items.length-1))*(w-left-right);
  const y=n=>top+(1-n/ceiling)*(h-top-bottom);
  const pts=items.map((p,i)=>[x(i),y(Number(p.count)||0)]);
  const line=pts.map((p,i)=>`${i?'L':'M'}${p.join(',')}`).join(' ');
  const area=`${line} L${pts.at(-1)[0]},${h-bottom} L${pts[0][0]},${h-bottom} Z`;
  return `<div class="trend-chart"><svg viewBox="0 0 ${w} ${h}" role="img" aria-label="情报发布时间分布：${esc(items.map(p=>p.date+' '+p.count+' 条').join('，'))}"><defs><linearGradient id="area-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#a0a8ee" stop-opacity=".25"/><stop offset="100%" stop-color="#a0a8ee" stop-opacity=".02"/></linearGradient></defs>${[0,1,2,3,4].map(i=>`<line class="chart-grid" x1="${left}" y1="${y(ceiling*i/4)}" x2="${w-right}" y2="${y(ceiling*i/4)}"/><text class="chart-label" x="0" y="${y(ceiling*i/4)+3}">${ceiling*i/4}</text>`).join('')}<path d="${area}" fill="url(#area-fill)"/><path d="${line}" fill="none" stroke="#7f88e6" stroke-width="2.3" stroke-linejoin="round"/>${pts.map((p,i)=>`<circle cx="${p[0]}" cy="${p[1]}" r="3.3" fill="#fff" stroke="#7f88e6" stroke-width="1.7"><title>${esc(items[i].date)}：${Number(items[i].count)||0} 条</title></circle>`).join('')}${items.map((p,i)=>i===0||i===items.length-1||i%Math.max(1,Math.ceil(items.length/7))===0?`<text class="chart-label" text-anchor="${i===0?'start':i===items.length-1?'end':'middle'}" x="${x(i)}" y="${h-3}">${esc(String(p.date).slice(5))}</text>`:'').join('')}</svg></div>`;
}
async function overviewPage(){
  const data=await api('/api/overview');setMode(data.mode);
  const stats=data.stats||{},colors=['#8792e6','#6fb7bd','#c3a2dd','#d8bb85'];
  const categories=asArray(data.categories);const total=categories.reduce((sum,c)=>sum+(Number(c.count)||0),0)||1;
  return heading('INTELLIGENCE OVERVIEW','AI 安全情报总览','汇聚 AI 安全知识，连接情报与资产，让每一次研判有据可循。',exportButton+runButton)+
  `<div class="stats-grid">${[
    ['情报知识总量',stats.total,'database','','已入库','去重后的知识条目'],
    ['严重风险情报',stats.critical,'shield','red','关注重点','按严重风险级别统计'],
    ['情报数据源',stats.sources,'globe','teal','多源覆盖','接入公开可信来源'],
    ['纳管资产',stats.assets,'assets','gold','关联分析','按产品及版本匹配'],
  ].map(([label,value,i,c,tag,desc])=>`<div class="panel stat-card"><div class="stat-top"><span>${label}</span><span class="stat-icon ${c}">${icon(i)}</span></div><div class="stat-value">${Number(value||0).toLocaleString('zh-CN')}</div><div class="stat-foot"><b>${tag}</b><span>· ${desc}</span></div></div>`).join('')}</div>
  <div class="overview-row"><section class="panel chart-panel"><div class="panel-header"><div><h2>情报发布时间分布</h2><p class="panel-subtitle">当前知识库 · 按原文发布日期分组</p></div><span class="chart-legend"><i class="legend-dot"></i>公开条目</span></div><div class="panel-body">${trendChart(data.trend)}</div></section><section class="panel chart-panel"><div class="panel-header"><div><h2>知识覆盖分布</h2><p class="panel-subtitle">从技术风险到治理实践</p></div>${icon('overview')}</div><div class="category-list">${categories.map((c,i)=>`<div class="category-row"><span class="category-label"><i class="category-dot" style="background:${colors[i%4]}"></i>${esc(typeName(c.name))}</span><span class="category-bar"><span style="width:${Math.max(0,Math.min(100,c.count/total*100))}%;background:${colors[i%4]}"></span></span><span class="category-value">${Number(c.count)||0}</span></div>`).join('')||'<p class="panel-subtitle">尚无知识分类</p>'}</div><div style="padding:0 24px 20px"><div class="notice blue">${icon('info')}覆盖漏洞、论文、标准与政策，保留来源与证据链。</div></div></section></div>
  <div class="overview-row"><section class="panel"><div class="panel-header table-header"><div><h2>近期安全情报</h2><p class="panel-subtitle">值得关注的公开情报与研究进展</p></div><a class="text-link" href="#explore">查看全部 ${icon('arrow')}</a></div>${asArray(data.recent).length?intelTable(data.recent):empty('知识库尚未入库','运行离线回放，或实时采集公开情报。',runButton)}</section><section class="panel"><div class="panel-header"><div><h2>数据源状态</h2><p class="panel-subtitle">公开来源 · 持续可追踪</p></div><a class="text-link" href="#runs">${icon('arrow')}</a></div><div class="source-health">${sourceRows(asArray(data.sourceHealth))||'<p class="panel-subtitle">暂无已配置来源</p>'}</div></section></div>
  ${recommendationQueue(data.recommendations)}
  <div class="notice overview-notice">${icon('info')}演示知识库含公开资料的历史快照，条目日期与原文链接均可查看。实时采集结果与离线回放均记录运行轨迹；风险结论需结合实际部署复核。</div>`;
}

function recommendationQueue(recommendations){
  const items=asArray(recommendations).slice(0,4);
  return `<section class="panel recommendation-panel"><div class="panel-header"><div><h2>优先处置建议</h2><p class="panel-subtitle">根据资产关联与情报风险等级排序 · 版本命中及待核验条目</p></div><a class="text-link" href="#assets">全部资产 ${icon('arrow')}</a></div>${items.length?`<div class="recommendation-grid">${items.map((item,i)=>`<article class="recommendation-card"><div class="recommendation-top"><span class="recommendation-rank">${String(i+1).padStart(2,'0')}</span><span class="recommendation-asset">${icon('assets')}${esc(item.assetName)}</span>${badge(item.severity)}</div><button class="recommendation-title" data-intel="${esc(item.intelId)}">${esc(item.title)}</button><p class="recommendation-action">${esc(typeof item.action==='string'?item.action:JSON.stringify(item.action))}</p><div class="recommendation-bottom"><span class="recommendation-status ${item.status==='affected'?'matched':''}" title="${esc(item.reason)}">${item.status==='affected'?'受影响版本命中':'版本影响待核验'}</span><button class="text-link" data-intel="${esc(item.intelId)}">核验证据 ${icon('arrow')}</button></div></article>`).join('')}</div>`:`<div class="panel-body"><div class="notice">${icon('check')}当前知识库尚未匹配出需要处置的资产风险。添加资产版本或采集新情报后，将重新生成建议。</div></div>`}</section>`;
}

async function explorePage(){
  const params=new URLSearchParams(state.filter);const data=await api('/api/intel?'+params);
  return heading('INTELLIGENCE EXPLORER','情报探索','把分散的安全信息，变成可检索、可核验、可行动的知识。',exportButton+runButton)+
  `<section class="panel"><form id="intel-filters" class="filters"><label class="search-input">${icon('search')}<input name="q" value="${esc(state.filter.q)}" placeholder="搜索标题、产品、CVE 或技术关键词" aria-label="搜索情报"></label><select name="type" aria-label="情报类型"><option value="">全部类型</option>${Object.entries(TYPES).map(([v,n])=>`<option value="${v}" ${state.filter.type===v?'selected':''}>${n}</option>`).join('')}</select><select name="severity" aria-label="风险级别"><option value="">全部风险</option>${Object.entries(SEVERITIES).map(([v,n])=>`<option value="${v}" ${state.filter.severity===v?'selected':''}>${n}</option>`).join('')}</select><button class="btn btn-small" type="submit">${icon('filter')}筛选</button><button class="btn btn-ghost btn-small" type="button" data-action="reset-filter">重置</button><span class="result-count" id="result-count">共 ${Number(data.total)||0} 条结果</span></form><div id="intel-results">${asArray(data.items).length?intelTable(data.items,true):empty('没有找到匹配的情报','试试其他关键词，或清除筛选条件。')}</div></section><div class="notice mt-20">${icon('link')}点击条目查看证据、原文出处、影响范围与关联资产。历史快照用于验证流程，最新风险状态请核对原始公告。</div>`;
}
let filterToken=0;
async function applyFilter(){
  const form=$('#intel-filters');if(!form)return;
  const vals=new FormData(form);state.filter={q:String(vals.get('q')||''),type:String(vals.get('type')||''),severity:String(vals.get('severity')||'')};
  const token=++filterToken;$('#intel-results').innerHTML=loading('检索知识库');
  try{const data=await api('/api/intel?'+new URLSearchParams(state.filter));if(token!==filterToken||state.route!=='explore')return;$('#result-count').textContent=`共 ${Number(data.total)||0} 条结果`;$('#intel-results').innerHTML=asArray(data.items).length?intelTable(data.items,true):empty('没有找到匹配的情报','试试其他关键词，或清除筛选条件。');}catch(error){if(token===filterToken&&$('#intel-results'))$('#intel-results').innerHTML=empty('检索失败',error.message,'<button class="btn" data-action="filter-retry">重新检索</button>');}
}

function askPage(){return heading('EVIDENCE-BASED ANALYSIS','智能研判','连接问题、证据与行动建议，让安全判断更加清晰。')+
  `<div class="question-layout"><section class="panel"><div id="qa-content"></div><div class="question-input-wrap"><form id="ask-form"><div class="question-input"><textarea id="question" name="question" aria-label="输入研判问题" placeholder="询问 AI 产品风险、攻击防护或资产修复优先级…" rows="2" maxlength="2000" required></textarea><button class="btn btn-primary" type="submit" id="ask-submit">${icon('arrow')}研判</button></div><div class="input-footnote"><span>${state.mode?.llm?'已连接大模型 · 回答附证据引用':'本地证据检索 · 无需模型密钥'}</span><span>Ctrl + Enter 发送</span></div></form></div></section><aside class="qa-side"><section class="panel"><div class="panel-header"><h2>从问题到行动</h2></div><div class="panel-body">${[['01','理解研判问题','定位产品、风险类型与分析范围。'],['02','检索可核验证据','从知识库召回相关条目，保留出处。'],['03','关联资产上下文','结合版本与暴露信息，评估潜在影响。'],['04','形成有依据的答复','附引用与检索轨迹，证据不足时明确说明。']].map(([n,h,p])=>`<div class="flow-step"><span class="flow-number">${n}</span><div><h3>${h}</h3><p>${p}</p></div></div>`).join('')}</div></section><section class="panel"><div class="panel-body"><div class="notice blue">${icon('shield')}外部文档作为待核验的数据处理。回答提供原文链接，避免将检索内容中的指令当作系统操作。</div><p class="monitor-note">当前${state.mode?.llm?'使用大模型增强生成，引用来自本地知识库。':'使用可复现的本地检索与规则摘要，尚未配置大模型服务。'}</p></div></section></aside></div>`;}
function formatAnswer(answer,citations){
  return String(answer||'没有返回分析内容。').split(/\n\n+/).map(paragraph=>{
    let text=esc(paragraph).replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
    text=text.replace(/\[(\d+)\]/g,(original,index)=>{
      const citation=asArray(citations)[Number(index)-1];
      return citation?.id?`<button class="inline-citation" data-intel="${esc(citation.id)}" aria-label="查看引用 ${Number(index)}">[${Number(index)}]</button>`:original;
    });
    return `<p>${text}</p>`;
  }).join('');
}
function renderMessages(){
  const target=$('#qa-content');if(!target)return;
  if(!state.messages.length){target.innerHTML=`<div class="assistant-welcome"><div class="assistant-orb">${icon('sparkles')}</div><h2>让安全知识，回答真实问题</h2><p>从一个产品、一种攻击，或一项资产开始。<br>所有回答都可以回到它的证据。</p></div><div class="question-cards">${['Ollama 有哪些安全风险，应该如何修复？','提示注入有哪些风险，应当如何防护？','当前资产中，应该优先修复哪些安全问题？'].map(q=>`<button class="question-card" data-question="${esc(q)}">${q}${icon('arrow')}</button>`).join('')}</div>`;return;}
  target.innerHTML=`<div class="qa-messages">${state.messages.map(message=>`<div><div class="qa-question">${esc(message.question)}</div>${message.loading?loading('正在检索本地证据并关联资产'):message.error?`<div class="notice mt-20">${icon('alert')}${esc(message.error)}</div>`:`<div class="qa-answer mt-20"><div class="answer-topline">${icon('sparkles')}观澜研判<span class="tag">${message.mode==='llm'?'模型增强 · 附证据':'本地检索基线'}</span>${message.abstained?'<span class="tag">证据不足</span>':''}</div><div class="answer-body">${formatAnswer(message.answer,message.citations)}</div>${asArray(message.trace).length?`<div class="trace-list">${message.trace.map(t=>`<span class="trace-tag" title="${esc(t.detail||'')}">${esc(t.name)} · ${esc(STATUSES[t.status]||t.status||'完成')}</span>`).join('')}</div>`:''}${asArray(message.citations).length?`<div class="citation-list">${message.citations.map((c,i)=>`<div class="citation-card"><span class="citation-number">${i+1}</span><div><a href="${safeUrl(c.url)}" target="_blank" rel="noopener noreferrer"><strong>${esc(c.title)} ↗</strong></a>${c.excerpt?`<p>${esc(c.excerpt)}</p>`:''}${c.id?`<button class="text-link" data-intel="${esc(c.id)}" style="font-size:11px;margin-top:5px">查看知识条目</button>`:''}</div></div>`).join('')}</div>`:''}</div>`}</div>`).join('')}</div>`;
}
async function ask(question){
  if(state.asking||!question.trim())return;
  state.asking=true;const message={question:question.trim(),loading:true};state.messages.push(message);renderMessages();
  if($('#question'))$('#question').value='';if($('#ask-submit'))$('#ask-submit').disabled=true;
  try{Object.assign(message,await api('/api/ask',{method:'POST',body:JSON.stringify({question:message.question})}),{loading:false});}
  catch(error){message.loading=false;message.error=error.message;}
  finally{state.asking=false;renderMessages();if($('#ask-submit'))$('#ask-submit').disabled=false;}
}

const GRAPH_COLORS={vulnerability:'#d68a95',intel:'#8f9ce0',paper:'#91a6d8',standard:'#8db8b8',policy:'#b49ecb',product:'#7caac5',asset:'#a5b888',tag:'#b1a4ce',topic:'#b1a4ce',technique:'#b1a4ce',source:'#b8ab91',entity:'#93a7ba'};
const GRAPH_TYPES={...TYPES,intel:'情报',product:'产品',asset:'资产',tag:'知识标签',topic:'风险分类',technique:'技术',source:'来源',entity:'实体'};
async function graphPage(){
  const data=await api('/api/graph');state.graph={nodes:asArray(data.nodes),edges:asArray(data.edges)};
  return heading('KNOWLEDGE GRAPH','知识图谱','从孤立条目到关联知识，探索风险、产品与资产之间的联系。',`<button class="btn" data-action="reset-graph">${icon('refresh')}重置视图</button>`)+
    `<div class="graph-layout"><section class="panel"><div class="panel-header"><div><h2>安全知识关系网络</h2><p class="panel-subtitle">点击节点查看其关联；拖动背景可平移，滚轮缩放</p></div><span class="graph-count">${data.nodes.length} 节点 / ${data.edges.length} 关系</span></div><div class="graph-canvas" id="graph-canvas"></div><div class="graph-legend">${[...new Set(data.nodes.map(n=>n.type))].map(t=>`<span><i class="category-dot" style="background:${GRAPH_COLORS[t]||GRAPH_COLORS.entity}"></i>${esc(GRAPH_TYPES[t]||t)}</span>`).join('')}</div></section><aside class="panel" id="graph-detail"><div class="graph-info"><div class="assistant-orb">${icon('graph')}</div><h3>发现知识之间的联系</h3><p>选择一个节点，查看关联产品、情报条目、技术主题与资产。</p><div class="notice blue">${icon('info')}所有节点与边均来自当前知识库，关系随入库和资产变更更新。</div></div></aside></div>`;
}
let graphTransform={x:0,y:0,scale:1};
function renderGraph(){
  const container=$('#graph-canvas');if(!container||!state.graph)return;
  const nodes=state.graph.nodes,edges=state.graph.edges;if(!nodes.length){container.innerHTML=empty('图谱尚未建立','采集情报后自动构建知识关系。',runButton);return;}
  const width=850,height=510,cx=425,cy=240;
  const degree=Object.fromEntries(nodes.map(n=>[n.id,0]));edges.forEach(e=>{degree[e.source]=(degree[e.source]||0)+1;degree[e.target]=(degree[e.target]||0)+1;});
  const sorted=[...nodes].sort((a,b)=>(degree[b.id]||0)-(degree[a.id]||0));
  const points=new Map();
  sorted.forEach((n,i)=>{let r,angle;if(i===0){r=0;angle=0;}else {const ring=i<=8?1:i<=24?2:3;const start=ring===1?1:ring===2?9:25;const count=ring===1?Math.min(8,sorted.length-1):ring===2?Math.min(16,sorted.length-9):Math.max(1,sorted.length-25);r=ring===1?103:ring===2?181:240;angle=(i-start)/count*Math.PI*2+(ring===2?.22:0);}points.set(n.id,{x:cx+Math.cos(angle)*r*1.35,y:cy+Math.sin(angle)*r*.85,r:Math.min(17,8+Math.sqrt(degree[n.id]||0)*1.9)});});
  container.innerHTML=`<svg id="graph-svg" viewBox="0 0 ${width} ${height}" aria-label="安全知识图谱"><g id="graph-pan">${edges.map(e=>{const a=points.get(e.source),b=points.get(e.target);return a&&b?`<line class="graph-edge" data-from="${esc(e.source)}" data-to="${esc(e.target)}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"><title>${esc(e.label)}</title></line>`:'';}).join('')}${nodes.map(n=>{const p=points.get(n.id);const labelY=n.type==='product'&&p.x<cx?p.y-p.r-12:p.y+p.r+20;return `<g class="graph-node" data-kind="${esc(n.type)}" data-node="${esc(n.id)}" role="button" tabindex="0" aria-label="${esc(n.label)}，${esc(GRAPH_TYPES[n.type]||n.type)}"><circle cx="${p.x}" cy="${p.y}" r="${p.r+5}" fill="${GRAPH_COLORS[n.type]||GRAPH_COLORS.entity}" opacity=".08"/><circle cx="${p.x}" cy="${p.y}" r="${p.r}" fill="${GRAPH_COLORS[n.type]||GRAPH_COLORS.entity}" stroke="#fff" stroke-width="2"/><text x="${p.x}" y="${labelY}" text-anchor="middle">${esc(n.label.length>19?n.label.slice(0,18)+'…':n.label)}</text><title>${esc(n.label)}</title></g>`;}).join('')}</g></svg>`;
  graphTransform={x:0,y:0,scale:1};
  const svg=$('#graph-svg');let drag=null;
  svg.addEventListener('wheel',e=>{e.preventDefault();graphTransform.scale=Math.max(.5,Math.min(2.8,graphTransform.scale*(e.deltaY>0?.9:1.1)));updateGraphTransform();},{passive:false});
  svg.addEventListener('pointerdown',e=>{if(e.target.closest('.graph-node'))return;drag={x:e.clientX,y:e.clientY,ox:graphTransform.x,oy:graphTransform.y};svg.setPointerCapture(e.pointerId);svg.style.cursor='grabbing';});
  svg.addEventListener('pointermove',e=>{if(!drag)return;const ratio=850/svg.getBoundingClientRect().width;graphTransform.x=drag.ox+(e.clientX-drag.x)*ratio;graphTransform.y=drag.oy+(e.clientY-drag.y)*ratio;updateGraphTransform();});
  svg.addEventListener('pointerup',()=>{drag=null;svg.style.cursor='grab';});
  if(state.graphSelected&&nodes.some(n=>n.id===state.graphSelected))selectGraph(state.graphSelected);
}
function updateGraphTransform(){const g=$('#graph-pan');if(g)g.setAttribute('transform',`translate(${graphTransform.x+425*(1-graphTransform.scale)},${graphTransform.y+255*(1-graphTransform.scale)}) scale(${graphTransform.scale})`);}
function selectGraph(id){
  state.graphSelected=id;const node=state.graph.nodes.find(n=>n.id===id);if(!node)return;
  const edges=state.graph.edges.filter(e=>e.source===id||e.target===id);const ids=new Set([id,...edges.map(e=>e.source===id?e.target:e.source)]);
  $$('.graph-node').forEach(el=>{el.classList.toggle('selected',el.dataset.node===id);el.style.opacity=ids.has(el.dataset.node)?'1':'.28';});
  $$('.graph-edge').forEach(el=>{const selected=el.dataset.from===id||el.dataset.to===id;el.style.stroke=selected?'#9ba8d7':'#e8edf4';el.style.opacity=selected?'1':'.3';el.style.strokeWidth=selected?'2':'1';});
  $('#graph-detail').innerHTML=`<div class="graph-info"><span class="tag">${esc(GRAPH_TYPES[node.type]||node.type)}</span><h3>${esc(node.label)}</h3>${node.severity?badge(node.severity):''}<p>${edges.length} 个直接关联</p>${['intel','vulnerability','paper','standard','policy'].includes(node.type)?`<button class="btn btn-small" data-intel="${esc(node.intelId||node.id.replace(/^intel:/,''))}">${icon('file')}查看证据详情</button>`:''}<ul class="graph-relations">${edges.map(e=>{const other=state.graph.nodes.find(n=>n.id===(e.source===id?e.target:e.source));return other?`<li><span>${esc(e.label||'关联')}</span><button data-node="${esc(other.id)}">${esc(other.label)}</button></li>`:'';}).join('')||'<li>暂无直接关联。</li>'}</ul></div>`;
}

async function assetsPage(){
  const data=await api('/api/assets');
  return heading('ASSET EXPOSURE','资产影响','将公开风险与真实部署关联，明确修复优先级。',`<button class="btn" data-action="import-assets">${icon('upload')}导入资产</button><button class="btn btn-primary" data-action="add-asset">${icon('plus')}新增资产</button>`)+
  `<div class="notice asset-notice">${icon('shield')}资产匹配基于产品名称、版本范围与暴露属性，用于辅助排查。命中结果不代表已被利用，请结合部署配置核验。内置资产仅为演示样例。</div><div class="asset-grid">${asArray(data.items).map(asset=>`<section class="panel asset-card"><div class="asset-top"><span class="asset-icon">${icon('assets')}</span><div><h2>${esc(asset.name)}</h2><p>${esc(asset.product)} · ${esc(asset.version||'版本未提供')}</p></div></div><div class="asset-properties"><div class="asset-property"><label>部署环境</label><span>${esc(asset.environment||'未指定')}</span></div><div class="asset-property"><label>资产负责人</label><span>${esc(asset.owner||'未指定')}</span></div><div class="asset-property"><label>访问范围</label><span>${esc(({public:'互联网暴露',internal:'内网',private:'私有',internet:'互联网暴露',local:'本地'})[asset.exposure]||asset.exposure||'未指定')}</span></div><div class="asset-property"><label>关联风险</label><span>${asArray(asset.findings).filter(f => f.status !== 'not_affected').length} 项</span></div></div><div class="asset-findings"><div class="asset-findings-head"><span>影响分析</span><span>${asArray(asset.findings).length?'需要核验':'当前匹配结果'}</span></div>${asArray(asset.findings).length?asset.findings.map(f=>`<button class="asset-finding finding-${esc(f.status||'unknown')}" data-intel="${esc(f.id||f.intelId||f.intel_id)}">${f.status === 'not_affected' ? '已知区间外 · ' : f.status === 'affected' ? '版本命中 · ' : '待核验 · '}${esc(f.title||f.reason||'查看关联安全情报')}<br><span style="font-size:11px;opacity:.8">${esc(f.reason||f.matchReason||'产品与版本规则匹配，请核验实际部署')}</span></button>`).join(''):`<div class="asset-safe">${icon('check')}当前知识库未匹配到风险</div>`}</div></section>`).join('')}</div>${!asArray(data.items).length?`<section class="panel">${empty('开始管理你的 AI 资产','添加产品版本，或导入 JSON / CycloneDX 清单，建立风险与资产的联系。','<button class="btn btn-primary" data-action="add-asset">新增资产</button>')}</section>`:''}`;
}
function showAssetForm(){showModal('新增资产',`<form id="asset-form"><div class="form-grid"><div class="form-field full"><label for="asset-name">资产名称 *</label><input id="asset-name" name="name" placeholder="例如：生产环境推理服务" required maxlength="120"></div><div class="form-field"><label for="asset-product">产品名称 *</label><input id="asset-product" name="product" placeholder="例如：Ollama" required maxlength="100"></div><div class="form-field"><label for="asset-version">版本 *</label><input id="asset-version" name="version" placeholder="例如：0.1.33" required maxlength="50"></div><div class="form-field"><label for="asset-environment">部署环境</label><select id="asset-environment" name="environment"><option value="生产">生产</option><option value="测试">测试</option><option value="开发">开发</option></select></div><div class="form-field"><label for="asset-exposure">访问范围</label><select id="asset-exposure" name="exposure"><option value="internal">内网访问</option><option value="public">互联网暴露</option><option value="local">本地使用</option></select></div><div class="form-field full"><label for="asset-owner">负责人</label><input id="asset-owner" name="owner" placeholder="例如：AI 平台组" maxlength="100"></div></div><p class="form-help">提交后自动匹配当前知识库中的漏洞与修复建议。</p><div class="form-actions"><button class="btn" type="button" data-action="close-modal">取消</button><button class="btn btn-primary" type="submit">保存并分析</button></div></form>`);}
function showImport(){showModal('导入资产清单',`<form id="import-form"><div class="notice blue">${icon('info')}支持 JSON 资产数组、含 assets 的对象，或 CycloneDX BOM 的 components 列表。</div><div class="form-field full mt-20"><label for="import-file">选择 JSON 文件</label><input type="file" id="import-file" accept=".json,application/json"></div><div class="form-field full mt-20"><label for="import-json">或粘贴 JSON 内容</label><textarea id="import-json" name="json" aria-label="资产 JSON 内容" placeholder='[{"name":"推理服务","product":"Ollama","version":"0.1.33","exposure":"internal"}]'></textarea></div><p class="form-help">导入后会保留原有资产，并执行版本影响分析。</p><div class="form-actions"><button class="btn" type="button" data-action="close-modal">取消</button><button class="btn btn-primary" type="submit">导入并分析</button></div></form>`);}

async function runsPage(){
  const results=await Promise.all([api('/api/runs'),api('/api/sources'),api('/api/monitor')]);const [runs,sources,monitor]=results;state.monitor=monitor.monitor||monitor;
  return heading('AGENT OPERATIONS','智能体运行','让采集、解析、去重与关联分析成为可观察的工作流。',runButton)+
  `<div class="runs-layout"><section class="panel"><div class="panel-header table-header"><div><h2>工作流运行记录</h2><p class="panel-subtitle">查看每次任务的执行步骤与结果</p></div><button class="text-link" data-action="retry">${icon('refresh')}刷新</button></div>${asArray(runs.items).length?runs.items.map(run=>`<div class="run-item" data-run="${esc(run.id)}" role="button" tabindex="0"><span class="run-icon">${icon('runs')}</span><div class="run-info"><strong>${run.mode==='live'?'实时公开情报采集':'离线快照回放'}</strong><small>${esc(dateTime(run.startedAt||run.createdAt))} · ${esc(String(run.id).slice(-8))}</small></div><span class="status status-${esc(run.status)}">${esc(STATUSES[run.status]||run.status)}</span>${icon('chevron')}</div>`).join(''):empty('还没有执行记录','选择离线回放验证完整流程，或实时采集最新公开情报。',runButton)}</section><aside><section class="panel"><div class="panel-header"><h2>持续监测</h2>${icon('clock')}</div><div class="panel-body"><div class="monitor-row"><div><h3>定时采集公开情报</h3><p id="monitor-status">${state.monitor.enabled?'已开启，服务运行期间自动采集':'按需运行，尚未开启定时任务'}</p></div><button class="switch ${state.monitor.enabled?'on':''}" id="monitor-switch" data-action="toggle-monitor" role="switch" aria-checked="${!!state.monitor.enabled}" aria-label="定时采集开关"></button></div><div class="monitor-form"><label for="monitor-interval">监测间隔</label><select id="monitor-interval">${[15,30,60,120,360,1440].map(n=>`<option value="${n}" ${Number(state.monitor.intervalMinutes||60)===n?'selected':''}>${n<60?n+' 分钟':n/60+' 小时'}</option>`).join('')}</select><button class="btn btn-small" data-action="save-monitor">保存</button></div><p class="monitor-note">定时任务在本地服务保持运行时执行。网络不可用时记录失败原因，可从运行记录中重试采集。</p></div></section><section class="panel mt-20"><div class="panel-header"><div><h2>公开情报数据源</h2><p class="panel-subtitle">状态与采集记录同步更新</p></div></div><div class="source-health">${sourceRows(asArray(sources.items))}</div></section></aside></div>`;
}
function runOptions(){showModal('启动情报工作流',`<div class="run-options"><button class="run-option" data-start-run="demo">${icon('database')}<span><strong>离线快照回放</strong><p>使用内置公开资料快照，执行解析、去重、分类与资产关联。无需网络，适合验证与演示。</p></span></button><button class="run-option" data-start-run="live">${icon('globe')}<span><strong>实时公开情报采集</strong><p>连接已配置的公开数据源，采集最新内容并建立证据链。网络与来源服务可用性会影响结果。</p></span></button></div><p class="form-help">每一步执行状态均写入运行记录。采集失败不会伪装为成功。</p>`);}
async function startRun(mode){
  $$('[data-start-run]').forEach(b=>b.disabled=true);
  try{const data=await api('/api/runs',{method:'POST',body:JSON.stringify({mode})});closeModal();openRun(data.runId||data.run?.id,data.run);toast(mode==='demo'?'离线回放已启动':'实时采集已启动');}catch(error){toast(error.message,true);$$('[data-start-run]').forEach(b=>b.disabled=false);}
}
function runDetailHtml(run){
  const summary=typeof run.summary==='string'?run.summary:run.summary?Object.entries(run.summary).map(([k,v])=>`${({total:'处理总量',inserted:'新增条目',updated:'更新条目',skipped:'跳过条目',duplicates:'重复条目',errors:'失败数',collected:'采集条目',newItems:'新增条目',matchedAssets:'命中资产',fetched:'采集条目'})[k]||k}：${typeof v==='object'?JSON.stringify(v):v}`).join('\n'):'';
  return `<div class="drawer-body"><div class="detail-kind"><span class="tag">${run.mode==='live'?'实时采集':'离线回放'}</span><span class="status status-${esc(run.status)}">${esc(STATUSES[run.status]||run.status)}</span></div><h2 class="detail-title">情报采集与知识构建</h2><div class="detail-meta"><span>开始于 ${esc(dateTime(run.startedAt||run.createdAt))}</span>${run.finishedAt?`<span>完成于 ${esc(dateTime(run.finishedAt))}</span>`:''}</div>${summary?`<div class="run-summary ${run.status==='failed'?'failed':''}">${esc(summary)}</div>`:''}<div class="run-steps">${asArray(run.steps).map((step,i)=>`<div class="run-step"><span class="step-dot ${esc(step.status)}">${step.status==='running'?'<span class="spinner" style="width:12px;height:12px"></span>':['completed','success','complete'].includes(step.status)?icon('check'):['error','failed'].includes(step.status)?icon('close'):i+1}</span><div><h3>${esc(step.name)}</h3><p>${esc(typeof step.detail==='object'?JSON.stringify(step.detail):step.detail||'等待执行')}</p>${step.durationMs!==undefined?`<small>耗时 ${Number(step.durationMs)<1000?Number(step.durationMs)+' ms':(Number(step.durationMs)/1000).toFixed(2)+' s'}</small>`:''}</div></div>`).join('')}</div>${['completed','complete','success','partial','failed'].includes(run.status)?'<button class="btn btn-primary" data-action="run">再次运行</button>':'<div class="notice">'+icon('info')+'任务在后台执行，关闭此面板后仍可在运行记录中查看进度。</div>'}</div>`;
}
let runPollToken=0;
async function openRun(id,existing){
  if(!id){toast('运行记录缺少标识',true);return;}
  ++intelDetailToken;clearTimeout(state.runTimer);const pollToken=++runPollToken;
  state.runId=id;showDrawer('工作流执行详情',loading('读取运行记录'));
  const poll=async()=>{if(state.runId!==id||$('#drawer').hidden||pollToken!==runPollToken)return;try{const data=existing?{run:existing}:await api('/api/runs/'+encodeURIComponent(id));existing=null;if(state.runId!==id||$('#drawer').hidden||pollToken!==runPollToken)return;const run=data.run||data;$('#drawer-content').innerHTML=runDetailHtml(run);if(['running','pending','queued'].includes(run.status)){state.runTimer=setTimeout(poll,1000);}else if(state.route==='overview'||state.route==='runs'){route();}}catch(error){if(state.runId===id&&pollToken===runPollToken){$('#drawer-content').innerHTML=empty('读取运行记录失败',error.message,`<button class="btn" data-run="${esc(id)}">重试</button>`);}}};poll();
}

function showDrawer(title,content){
  if($('#drawer').hidden)state.drawerFocus=document.activeElement;$('#overlay').hidden=false;$('#drawer').hidden=false;document.body.style.overflow='hidden';
  $('#drawer').innerHTML=`<div class="drawer-head"><h2 id="drawer-title">${esc(title)}</h2><button class="icon-button" data-action="close-drawer" aria-label="关闭详情">${icon('close')}</button></div><div id="drawer-content">${content}</div>`;
  $('[data-action="close-drawer"]').focus();
}
function restoreFocus(previous){if(previous?.isConnected && !previous.closest('[hidden]'))previous.focus();else $('#main').focus();}
function closeDrawer(){++intelDetailToken;++runPollToken;state.runId=null;clearTimeout(state.runTimer);$('#drawer').hidden=true;$('#overlay').hidden=true;document.body.style.overflow='';restoreFocus(state.drawerFocus);}
function showModal(title,content){state.modalFocus=document.activeElement;$('#modal-shell').hidden=false;document.body.style.overflow='hidden';$('#modal').innerHTML=`<div class="modal-header"><h2 id="modal-title">${esc(title)}</h2><button class="icon-button" data-action="close-modal" aria-label="关闭窗口">${icon('close')}</button></div><div class="modal-body">${content}</div>`;const first=$('input,textarea,button[data-start-run]',$('#modal'));(first||$('[data-action="close-modal"]')).focus();}
function closeModal(){$('#modal-shell').hidden=true;if($('#drawer').hidden)document.body.style.overflow='';restoreFocus(state.modalFocus);}
let intelDetailToken=0;
async function openIntel(id){
  if(!id||id==='undefined'){toast('该关联条目暂无可用详情',true);return;}
  state.runId=null;clearTimeout(state.runTimer);const token=++intelDetailToken;showDrawer('情报证据详情',loading('载入原始证据与资产关联'));
  try{
    const data=await api('/api/intel/'+encodeURIComponent(id));if(token!==intelDetailToken||$('#drawer').hidden)return;const item=data.item||data;
    const val=v=>Array.isArray(v)?v.map(x=>typeof x==='object'?JSON.stringify(x):x).join('\n'):typeof v==='object'&&v!==null?JSON.stringify(v,null,2):v;
    $('#drawer-content').innerHTML=`<div class="drawer-body"><div class="detail-kind"><span class="tag">${esc(typeName(item.type))}</span>${badge(item.severity)}${item.cvss?`<span class="tag">CVSS ${esc(item.cvss)}</span>`:''}<span class="tag">${item.dataMode==='live'?'实时采集':'来源快照'}</span></div><h2 class="detail-title">${esc(item.title)}</h2><div class="detail-meta"><span>${esc(item.source)}</span><span>${esc(shortDate(item.published))}</span><span>${esc(item.id)}</span><span>采集：${esc(dateTime(item.collectedAt))}</span></div><p class="detail-summary">${esc(item.summary||'暂无摘要，请查阅原始来源。')}</p><a class="drawer-source-link" href="${safeUrl(item.url)}" target="_blank" rel="noopener noreferrer">${icon('external')}查看原始来源</a><div class="detail-tags">${tags(item.tags)}${tags(item.products)}</div><section class="detail-section"><h3>${icon('alert')}影响范围</h3><p>${esc(val(item.affected)||'该条目未提供明确的受影响版本范围，请核验原文。')}</p></section><section class="detail-section"><h3>${icon('shield')}修复与行动建议</h3><p>${esc(val(item.remediation)||'结合原始来源与部署环境评估适用的缓解措施。')}</p>${item.fixed?`<p style="margin-top:10px">修复版本：${esc(val(item.fixed))}</p>`:''}</section><section class="detail-section"><h3>${icon('link')}证据记录</h3>${(asArray(data.evidence).length?data.evidence:asArray(item.evidence)).map(e=>`<div class="evidence-block">${esc(typeof e==='string'?e:e.excerpt||e.text||e.quote||e.content||val(e))}${e.url?`<br><a class="text-link" href="${safeUrl(e.url)}" target="_blank" rel="noopener noreferrer">证据来源 ↗</a>`:''}${e.hash?`<div class="evidence-hash" title="${esc(e.hash)}">SHA-256 ${esc(e.hash)}</div>`:''}${e.collectedAt?`<div class="evidence-time">采集时间：${esc(dateTime(e.collectedAt))}</div>`:''}</div>`).join('')||'<p>原始来源链接见上。该条目未单独提供摘录证据。</p>'}</section><section class="detail-section"><h3>${icon('assets')}关联资产</h3>${asArray(data.assets).length?data.assets.map(a=>`<div class="evidence-block">${esc(a.name||a.asset?.name||a.id)} · ${esc(a.version||a.asset?.version||'')}<br>${esc(a.findings?.find(f=>f.id===item.id)?.reason||a.reason||a.matchReason||'产品与版本规则关联，需核验部署配置')}</div>`).join(''):'<p>当前纳管资产中暂无关联结果。</p>'}</section>${asArray(data.related).length?`<section class="detail-section"><h3>${icon('graph')}关联知识</h3>${data.related.map(r=>`<button class="related-item" data-intel="${esc(r.id)}">${esc(r.title)}</button>`).join('')}</section>`:''}<div class="notice mt-20">${icon('info')}知识库包含公开资料的历史快照。请以原始公告的最新版本为准；来源与入库时间用于追溯。</div></div>`;
  }catch(error){if(token===intelDetailToken&&!$('#drawer').hidden)$('#drawer-content').innerHTML=empty('情报详情加载失败',error.message,`<button class="btn" data-intel="${esc(id)}">重新加载</button>`);}
}
async function exportReport(button){
  button.disabled=true;try{const res=await fetch('/api/report');if(!res.ok)throw new Error('报告生成失败，请稍后重试。');const blob=await res.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='观澜-AI安全研判报告-'+new Date().toLocaleDateString('sv-SE')+'.md';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('研判报告已导出（Markdown）');}catch(error){toast(error.message,true);}finally{button.disabled=false;}
}
async function saveMonitor(toggle=false){
  if(!state.monitor)return;const enabled=toggle?!state.monitor.enabled:!!state.monitor.enabled;const intervalMinutes=Number($('#monitor-interval')?.value||60);
  try{const data=await api('/api/monitor',{method:'POST',body:JSON.stringify({enabled,intervalMinutes})});state.monitor=data.monitor||data;toast(enabled?'持续监测配置已保存':'持续监测已关闭');await route();}catch(error){toast(error.message,true);}
}

document.addEventListener('click',e=>{
  const intel=e.target.closest('[data-intel]');if(intel){openIntel(intel.dataset.intel);return;}
  const node=e.target.closest('[data-node]');if(node){selectGraph(node.dataset.node);return;}
  const run=e.target.closest('[data-run]');if(run){openRun(run.dataset.run);return;}
  const start=e.target.closest('[data-start-run]');if(start){startRun(start.dataset.startRun);return;}
  const question=e.target.closest('[data-question]');if(question){ask(question.dataset.question);return;}
  const action=e.target.closest('[data-action]');if(!action)return;
  const actions={run:runOptions,export:()=>exportReport(action),retry:route,'close-drawer':closeDrawer,'close-modal':closeModal,'add-asset':showAssetForm,'import-assets':showImport,'filter-retry':applyFilter,'toggle-monitor':()=>saveMonitor(true),'save-monitor':()=>saveMonitor(false),'reset-graph':()=>{state.graphSelected=null;renderGraph();$('#graph-detail').innerHTML='<div class="graph-info"><h3>选择节点探索关系</h3><p>点击图谱中的任意节点，查看其关联知识。</p></div>';},'reset-filter':()=>{state.filter={q:'',type:'',severity:''};$('#intel-filters').reset();$('#intel-filters [name=q]').value='';$('#intel-filters [name=type]').value='';$('#intel-filters [name=severity]').value='';applyFilter();}};
  actions[action.dataset.action]?.();
});
document.addEventListener('submit',async e=>{
  e.preventDefault();const form=e.target;
  if(form.id==='global-search'){const q=$('input',form).value.trim();go('explore',new URLSearchParams({q}).toString());return;}
  if(form.id==='intel-filters'){applyFilter();return;}
  if(form.id==='ask-form'){ask($('#question').value);return;}
  if(form.id==='asset-form'){const button=$('[type=submit]',form);button.disabled=true;try{await api('/api/assets',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(form)))});closeModal();toast('资产已添加，影响分析已更新');await route();}catch(error){toast(error.message,true);}finally{button.disabled=false;}return;}
  if(form.id==='import-form'){const button=$('[type=submit]',form);button.disabled=true;try{const text=$('#import-json').value.trim();if(!text)throw new Error('请选择 JSON 文件或粘贴资产清单。');let data;try{data=JSON.parse(text);}catch{throw new Error('JSON 格式不正确，请检查逗号、引号与括号。');}if(Array.isArray(data))data={assets:data};const result=await api('/api/assets/import',{method:'POST',body:JSON.stringify(data)});closeModal();toast(`资产导入完成${result.imported!==undefined?'，新增 '+result.imported+' 项':''}`);await route();}catch(error){toast(error.message,true);}finally{button.disabled=false;}}
});
document.addEventListener('change',async e=>{
  if(e.target.matches('#intel-filters select'))applyFilter();
  if(e.target.id==='import-file'){const file=e.target.files[0];if(file){if(file.size>900*1024){toast('文件过大，请使用 900 KB 以下的资产清单。',true);e.target.value='';return;}try{$('#import-json').value=await file.text();}catch{toast('无法读取所选文件。',true);}}}
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){if(!$('#modal-shell').hidden)closeModal();else if(!$('#drawer').hidden)closeDrawer();else $('#sidebar').classList.remove('open');}
  if(e.key==='/'&&!e.ctrlKey&&!e.metaKey&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){e.preventDefault();$('#global-search input').focus();}
  if(e.key==='Enter'&&e.ctrlKey&&e.target.id==='question'){e.preventDefault();ask(e.target.value);}
  if((e.key==='Enter'||e.key===' ')&&e.target.matches('[role=button]:not(button)')){e.preventDefault();e.target.click();}
  if(e.key==='Tab'){const dialog=!$('#modal-shell').hidden?$('#modal'):!$('#drawer').hidden?$('#drawer'):null;if(dialog){const focusable=$$('button:not(:disabled),a[href],input,textarea,select,[tabindex="0"]',dialog).filter(el=>!el.hidden);const first=focusable[0],last=focusable.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}}
});
$('#overlay').addEventListener('click',closeDrawer);
$('#modal-shell').addEventListener('click',e=>{if(e.target.id==='modal-shell')closeModal();});
$('#menu-button').innerHTML=icon('menu');
$('#menu-button').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
document.addEventListener('click',e=>{if($('#sidebar').classList.contains('open')&&!e.target.closest('#sidebar')&&!e.target.closest('#menu-button'))$('#sidebar').classList.remove('open');});
$$('[data-icon]').forEach(el=>el.innerHTML=icon(el.dataset.icon));
$('#navigation').innerHTML=PAGES.map(p=>`<a class="nav-item" data-route="${p.id}" href="#${p.id}">${icon(p.icon)}<span>${p.name}</span>${p.id==='runs'?'<i class="nav-indicator"></i>':''}</a>`).join('');
window.addEventListener('hashchange',route);
route();
if(state.route!=='overview')api('/api/overview').then(data=>setMode(data.mode)).catch(()=>{});






