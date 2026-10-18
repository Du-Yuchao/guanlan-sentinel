import { readFileSync, statSync } from 'node:fs';
import { mkdir, writeFile, chmod, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULTS = Object.freeze({ enabled:false, provider:'openai-compatible', baseUrl:'', model:'', apiKey:'', label:'自定义大模型', topK:5, temperature:0.1, timeoutMs:30000, includeAssets:false, rewriteQueries:true, allowNoApiKey:false });
const FIELDS = Object.keys(DEFAULTS);

export class ModelError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'ModelError'; this.code = code; this.status = status; }
}
const fail = (code, message, status) => new ModelError(code, message, status);
const own = (object, key) => Object.hasOwn(object, key);
const cancel = body => { try { Promise.resolve(body?.cancel()).catch(() => {}); } catch {} };

function isLoopback(url) {
  return url.hostname === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname);
}
function endpoint(value, provider) {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\\?#]/.test(value)) throw fail('INVALID_BASE_URL', '模型 API 地址无效，请使用不含查询参数、片段或凭据的完整地址');
  let url;
  try { url = new URL(value); } catch { throw fail('INVALID_BASE_URL', '模型 API 地址无效，请填写完整的 HTTPS 地址'); }
  if (url.username || url.password || !['https:','http:'].includes(url.protocol)) throw fail('UNSAFE_BASE_URL', '模型 API 只允许无凭据的 HTTPS 地址；本机 IP 地址可使用 HTTP');
  const namedLoopback = url.hostname === 'localhost';
  if (namedLoopback) url.hostname = '127.0.0.1';
  // Only literal loopback IPs may use HTTP. Do not rely on DNS or the hosts file.
  const authority = value.match(/^https?:\/\/(\[[^\]]+\]|[^/:]+)(?::\d+)?(?:\/|$)/i)?.[1];
  if (url.protocol === 'http:' && (!isLoopback(url) || authority?.toLowerCase() !== (namedLoopback ? 'localhost' : url.hostname))) throw fail('UNSAFE_BASE_URL', 'HTTP 仅允许本机 localhost、127.0.0.1 或 [::1] 地址，远程服务请使用 HTTPS');
  let path = url.pathname.replace(/\/+$/, '');
  const suffix = provider === 'anthropic' ? '/messages' : '/chat/completions';
  if (provider === 'anthropic' && /\/chat\/completions$/i.test(path) || provider !== 'anthropic' && /\/messages$/i.test(path)) throw fail('PROVIDER_URL_MISMATCH', 'API 地址与所选协议不匹配');
  if (!path) path = '/v1';
  if (!path.endsWith(suffix)) path += suffix;
  url.pathname = path;
  return url;
}
function stringField(value, name, max, allowEmpty = false) {
  if (typeof value !== 'string' || value.length > max || /[\x00-\x1f\x7f]/.test(value)) throw fail('INVALID_CONFIG', `${name}格式无效`);
  const cleaned = value.trim();
  if (!allowEmpty && !cleaned) throw fail('INVALID_CONFIG', `${name}不能为空`);
  return cleaned;
}
function normalize(input, previous = DEFAULTS, { allowIncomplete = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('INVALID_CONFIG', '模型配置必须是一个对象');
  const next = Object.fromEntries(FIELDS.map(key => [key, own(input,key) ? input[key] : previous[key]]));
  if (!['openai-compatible','anthropic'].includes(next.provider)) throw fail('INVALID_PROVIDER', '请选择 OpenAI 兼容协议或 Anthropic Messages 协议');
  for (const key of ['enabled','includeAssets','rewriteQueries','allowNoApiKey']) if (typeof next[key] !== 'boolean') throw fail('INVALID_CONFIG', '模型开关设置必须为布尔值');
  next.baseUrl = stringField(next.baseUrl, 'API 地址', 2048, true);
  next.model = stringField(next.model, '模型名称', 160, true);
  next.label = stringField(next.label, '配置名称', 80, true) || DEFAULTS.label;
  for (const [key,min,max] of [['topK',3,8],['temperature',0,1],['timeoutMs',10000,45000]]) {
    if (typeof next[key] !== 'number' || !Number.isFinite(next[key]) || next[key] < min || next[key] > max || key !== 'temperature' && !Number.isInteger(next[key])) throw fail('INVALID_CONFIG', `${key} 必须在 ${min} 到 ${max} 之间`);
  }
  const url = next.baseUrl ? endpoint(next.baseUrl,next.provider) : null;
  if (url) next.baseUrl = url.href;
  const previousOrigin = previous.baseUrl ? endpoint(previous.baseUrl,previous.provider).origin : '';
  const identityChanged = next.provider !== previous.provider || (url?.origin ?? '') !== previousOrigin;
  const suppliedKey = own(input,'apiKey') ? stringField(input.apiKey,'API Key',4096,true) : '';
  if (/[^\x21-\x7e]/.test(suppliedKey)) throw fail('INVALID_CONFIG', 'API Key 必须使用不含空白字符的可打印 ASCII 字符');
  if (own(input,'clearApiKey') && typeof input.clearApiKey !== 'boolean') throw fail('INVALID_CONFIG', '清除密钥开关必须为布尔值');
  if (next.allowNoApiKey && (!url || !isLoopback(url))) throw fail('NO_KEY_REMOTE', '无密钥模式仅适用于本机 IP 地址上的模型服务');
  const explicitNoKey = own(input,'allowNoApiKey') && input.allowNoApiKey === true && url && isLoopback(url);
  if (identityChanged && previous.apiKey && !suppliedKey && !explicitNoKey) throw fail('API_KEY_REQUIRED', '已更换模型服务地址或协议，请重新输入 API Key；本机服务可明确选择无密钥模式');
  next.apiKey = suppliedKey || (!identityChanged && !input.clearApiKey ? previous.apiKey : '');
  if (explicitNoKey && !suppliedKey) next.apiKey = '';
  const configured = Boolean(url && next.model && (next.apiKey || next.allowNoApiKey));
  if (next.enabled && !configured && !allowIncomplete) throw fail('MODEL_NOT_CONFIGURED', '启用模型前请填写 API 地址、模型名称和 API Key；本机服务可选择无密钥模式');
  return { ...next, configured, ready:next.enabled && configured };
}
function envConfig(env) {
  const parseBoolean = (value, fallback) => value == null || value === '' ? fallback : !/^(?:false|0|no|off)$/i.test(String(value));
  const config = { ...DEFAULTS, provider:env.AI_PROVIDER || DEFAULTS.provider, baseUrl:env.AI_BASE_URL || '', model:env.AI_MODEL || '', apiKey:env.AI_API_KEY || '' };
  for (const [field,key] of [['includeAssets','AI_INCLUDE_ASSETS'],['rewriteQueries','AI_REWRITE_QUERIES'],['allowNoApiKey','AI_ALLOW_NO_API_KEY']]) config[field] = parseBoolean(env[key],DEFAULTS[field]);
  for (const [field,key] of [['topK','AI_TOP_K'],['temperature','AI_TEMPERATURE'],['timeoutMs','AI_TIMEOUT_MS']]) if (env[key] != null && env[key] !== '') config[field] = Number(env[key]);
  if (env.AI_LABEL) config.label = env.AI_LABEL;
  config.enabled = parseBoolean(env.AI_ENABLED,Boolean(config.baseUrl && config.model && (config.apiKey || config.allowNoApiKey)));
  return normalize(config,DEFAULTS,{allowIncomplete:true});
}
function abortable(promise, signal) {
  if (signal.aborted) { Promise.resolve(promise).catch(() => {}); return Promise.reject(signal.reason); }
  return new Promise((resolve,reject) => {
    const cleanup = () => signal.removeEventListener('abort',stop);
    const stop = () => { cleanup(); reject(signal.reason); };
    signal.addEventListener('abort',stop,{once:true});
    Promise.resolve(promise).then(value => {cleanup(); resolve(value);},error => {cleanup(); reject(error);});
  });
}
function safeUsage(value) {
  if (!value || typeof value !== 'object') return undefined;
  const usage = {};
  for (const field of ['prompt_tokens','completion_tokens','total_tokens','input_tokens','output_tokens']) if (Number.isSafeInteger(value[field]) && value[field] >= 0) usage[field] = value[field];
  return Object.keys(usage).length ? usage : undefined;
}
function responseText(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.filter(block => block && ['text','output_text'].includes(block.type) && typeof block.text === 'string').map(block => block.text).join('\n');
}

// The secret-bearing snapshot returned by getConfig is for server code only.
// OpenAI: https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
// Anthropic: https://platform.claude.com/docs/en/api/messages/create
export function createModelService({ dataDir, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  if (!dataDir) throw fail('INVALID_DATA_DIR','模型配置目录未设置');
  const configPath = join(dataDir,'model-config.json');
  const secrets = new Set();
  const remember = value => { if (typeof value === 'string' && value.trim()) secrets.add(value.trim()); };
  remember(env.AI_API_KEY);
  const redact = value => {
    let text = String(value ?? '');
    for (const secret of [...secrets].sort((a,b) => b.length-a.length)) {
      const variants = new Set([secret]);
      try { variants.add(encodeURIComponent(secret)); } catch {}
      for (const encoded of variants) text = text.split(encoded).join('[已隐藏密钥]');
    }
    return text;
  };
  let state, configError = '';
  try {
    const size = statSync(configPath).size;
    if (size > 32768) throw fail('CONFIG_TOO_LARGE','模型配置过大');
    const saved = JSON.parse(readFileSync(configPath,'utf8'));
    remember(saved.apiKey);
    state = normalize(saved);
  } catch (error) {
    if (error.code === 'ENOENT') {
      try { state = envConfig(env); } catch { configError = '环境变量中的模型配置无效，请在设置中重新保存。'; }
    } else configError = '本地模型配置无法读取或格式无效，请在设置中重新保存。';
    state ??= normalize(DEFAULTS);
  }
  const publicConfig = config => {
    const result = {};
    for (const field of FIELDS) if (field !== 'apiKey') result[field] = typeof config[field] === 'string' ? redact(config[field]) : config[field];
    return {...result,apiKeySet:Boolean(config.apiKey),configured:config.configured,ready:config.ready,configError};
  };
  const safeError = error => {
    if (error instanceof ModelError) return fail(error.code,redact(error.message),error.status);
    const code = error?.cause?.code ?? error?.code;
    if (/CERT|TLS|SSL|UNABLE_TO_VERIFY|SELF_SIGNED/.test(typeof code === 'string' ? code : '')) return fail('MODEL_TLS_ERROR','模型服务证书校验失败，请检查服务证书或代理设置',502);
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return fail('MODEL_DNS_ERROR','模型服务域名解析失败，请检查 API 地址与网络',502);
    if (code === 'ECONNREFUSED') return fail('MODEL_CONNECTION_REFUSED','无法连接模型服务，请确认服务已启动且端口正确',502);
    return fail('MODEL_NETWORK_ERROR','连接模型服务失败，请检查 API 地址、网络和代理设置',502);
  };
  let queue = Promise.resolve();
  async function updateConfig(input) {
    // Snapshot the caller's form before joining the serialized atomic-write queue.
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('INVALID_CONFIG','模型配置必须是一个对象');
    const form = { ...input }; remember(form.apiKey);
    const operation = queue.then(async () => {
      let next;
      try { next = normalize(form,state); } catch (error) { throw safeError(error); }
      const temporary = join(dataDir,`.model-config-${randomUUID()}.tmp`);
      try {
        await mkdir(dataDir,{recursive:true});
        const persisted = Object.fromEntries(FIELDS.map(field => [field,next[field]]));
        await writeFile(temporary,JSON.stringify(persisted,null,2)+'\n',{encoding:'utf8',mode:0o600,flag:'wx'});
        try { await chmod(temporary,0o600); } catch (error) { if (process.platform !== 'win32') throw error; }
        await rename(temporary,configPath);
      } catch {
        try { await rm(temporary,{force:true}); } catch {}
        throw fail('CONFIG_SAVE_FAILED','模型配置保存失败，请检查数据目录权限',500);
      }
      state = next; remember(next.apiKey); configError = '';
      return publicConfig(next);
    });
    queue = operation.catch(() => {});
    return operation;
  }
  async function complete({ system = '', messages, maxTokens = 1800, timeoutMs, config } = {}) {
    let selected, reader, response, timer;
    const started = Date.now();
    try {
      if (config?.apiKey) remember(config.apiKey);
      selected = config ? normalize(config) : {...state};
      if (!selected.enabled) throw fail('MODEL_DISABLED','大模型问答已关闭，请先在模型设置中启用');
      if (!selected.ready) throw fail('MODEL_NOT_CONFIGURED','大模型尚未配置完整');
      if (typeof system !== 'string' || system.length > 20000 || !Array.isArray(messages) || !messages.length || messages.length > 24 || messages.some(item => !item || !['user','assistant'].includes(item.role) || typeof item.content !== 'string' || item.content.length > 80000)) throw fail('INVALID_MESSAGES','模型输入消息无效或过长');
      if (!Number.isFinite(maxTokens) || maxTokens < 1 || maxTokens > 4096) throw fail('INVALID_TOKENS','模型输出长度必须在 1 到 4096 之间');
      if (timeoutMs != null && (!Number.isFinite(timeoutMs) || timeoutMs < 1)) throw fail('INVALID_TIMEOUT','模型请求时限无效');
      const url = endpoint(selected.baseUrl,selected.provider);
      const headers = new Headers({'Content-Type':'application/json','User-Agent':'Guanlan-Sentinel/1.0'});
      let body = {model:selected.model,max_tokens:Math.floor(maxTokens),stream:false,messages:messages.map(({role,content})=>({role,content}))};
      if (selected.provider === 'anthropic') {
        headers.set('anthropic-version','2023-06-01');
        if (selected.apiKey) headers.set('x-api-key',selected.apiKey);
        // New Claude models reject temperature overrides; omit this optional field.
        if (system) body.system = system;
      } else {
        if (selected.apiKey) headers.set('Authorization',`Bearer ${selected.apiKey}`);
        body.temperature = selected.temperature;
        if (system) body.messages.unshift({role:'system',content:system});
      }
      const payload = JSON.stringify(body);
      if (Buffer.byteLength(payload,'utf8') > 180000) throw fail('MODEL_INPUT_TOO_LARGE','模型输入上下文超过大小限制');
      const budget = Math.min(selected.timeoutMs,timeoutMs ?? selected.timeoutMs,45000);
      const deadline = Date.now()+budget;
      const controller = new AbortController();
      const expire = () => controller.abort(fail('MODEL_TIMEOUT','模型响应超时，请稍后重试或调高请求时限',504));
      const checkDeadline = () => { if (Date.now() >= deadline && !controller.signal.aborted) expire(); if (controller.signal.aborted) throw controller.signal.reason; };
      timer = setTimeout(expire,budget);
      const request = Promise.resolve(fetchImpl(url.href,{method:'POST',headers,body:payload,redirect:'manual',signal:controller.signal}));
      // A test adapter or nonstandard fetch may resolve after cancellation.
      request.then(late => { if (controller.signal.aborted) cancel(late?.body); },() => {});
      response = await abortable(request,controller.signal);
      checkDeadline();
      if (response.status >= 300 && response.status < 400 || response.redirected) throw fail('MODEL_REDIRECT_REFUSED','模型服务返回重定向，已阻止转发密钥；请填写最终 API 地址',502);
      if (!response.ok) {
        const status = Number(response.status);
        const hint = status === 401 || status === 403 ? '请检查 API Key 与模型访问权限' : status === 404 ? '请检查 API 地址与模型名称' : status === 429 ? '请求频率或额度受限，请稍后重试' : status >= 500 ? '上游模型服务暂时不可用' : '请检查所选协议、模型名称与请求参数';
        // Never return upstream error bodies, request URLs, headers, or raw errors.
        throw fail('MODEL_HTTP_ERROR',`模型服务返回 HTTP ${Number.isInteger(status) && status >= 100 && status <= 599 ? status : '错误'}，${hint}`,502);
      }
      if (Number(response.headers.get('content-length') ?? 0) > MAX_RESPONSE_BYTES) throw fail('MODEL_RESPONSE_TOO_LARGE','模型响应超过 256 KB 限制',502);
      const buffer = Buffer.allocUnsafe(MAX_RESPONSE_BYTES); let size = 0;
      if (response.body) {
        reader = response.body.getReader();
        while (true) {
          checkDeadline();
          const {value,done} = await abortable(reader.read(),controller.signal);
          if (done) break;
          if (size+value.byteLength > MAX_RESPONSE_BYTES) throw fail('MODEL_RESPONSE_TOO_LARGE','模型响应超过 256 KB 限制',502);
          buffer.set(value,size); size += value.byteLength;
        }
      }
      checkDeadline();
      let parsed;
      try { parsed = JSON.parse(buffer.subarray(0,size).toString('utf8')); } catch { throw fail('MODEL_INVALID_RESPONSE','模型服务未返回有效 JSON，请检查 API 地址与协议',502); }
      const content = selected.provider === 'anthropic' ? parsed?.content : parsed?.choices?.[0]?.message?.content;
      const text = redact(responseText(content)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g,'').trim().slice(0,24000);
      if (!text) throw fail('MODEL_EMPTY_RESPONSE','模型未返回可用回答，请检查模型是否支持文本问答',502);
      return {text,model:redact(selected.model),usage:safeUsage(parsed?.usage),latencyMs:Date.now()-started};
    } catch (error) {
      throw safeError(error);
    } finally {
      clearTimeout(timer);
      if (reader) { try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {} }
      else cancel(response?.body);
    }
  }
  async function testConnection(input) {
    let candidate;
    try {
      if (input != null && (typeof input !== 'object' || Array.isArray(input))) throw fail('INVALID_CONFIG','模型配置必须是一个对象');
      if (input != null) { remember(input?.apiKey); candidate = normalize({...input,enabled:true},state); }
      else candidate = normalize({...state,enabled:true});
      const result = await complete({system:'This is a connection test. Reply with OK.',messages:[{role:'user',content:'Reply OK.'}],maxTokens:16,config:candidate});
      return {ok:true,model:result.model,provider:candidate.provider,latencyMs:result.latencyMs,message:'模型连接成功，已收到文本响应。'};
    } catch (error) { throw safeError(error); }
  }
  return {getPublicConfig:() => publicConfig(state),getConfig:() => ({...state}),updateConfig,testConnection,complete};
}
