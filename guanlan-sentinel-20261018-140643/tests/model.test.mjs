import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rm, stat, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createModelService } from '../lib/model.mjs';

// All model responses are local fixtures; no live services or credentials are used.
const fixtureKey = 'fixture-secret-not-a-real-key';
const settings = {enabled:true,provider:'openai-compatible',baseUrl:'https://model.example/v1',model:'fixture-model',apiKey:fixtureKey};
const ask = {system:'Use supplied evidence.',messages:[{role:'user',content:'What is the finding?'}]};
const success = text => new Response(JSON.stringify({choices:[{message:{content:text}}],usage:{prompt_tokens:3,completion_tokens:4,total_tokens:7,secret:fixtureKey}}),{headers:{'Content-Type':'application/json'}});
async function fixture(t, options = {}) {
  const parent = join(process.cwd(),'tmp'); await mkdir(parent,{recursive:true});
  const dataDir = await mkdtemp(join(parent,'sentinel-model-'));
  t.after(() => rm(dataDir,{recursive:true,force:true}));
  return {dataDir,service:createModelService({dataDir,env:{},fetchImpl:async()=>success('Evidence [1].'),...options})};
}

test('model config is disabled by default and getters return independent snapshots without keys', async t => {
  const {service} = await fixture(t);
  assert.equal(service.getConfig().ready,false);
  const publicConfig = await service.updateConfig(settings);
  assert.equal(publicConfig.apiKeySet,true);
  assert.equal(publicConfig.baseUrl,'https://model.example/v1/chat/completions');
  assert.equal(publicConfig.ready,true);
  assert.equal(Object.hasOwn(publicConfig,'apiKey'),false);
  assert.equal(JSON.stringify(publicConfig).includes(fixtureKey),false);
  const snapshot = service.getConfig(); snapshot.apiKey = 'changed'; snapshot.enabled = false;
  assert.equal(service.getConfig().apiKey,fixtureKey);
  assert.equal(service.getConfig().enabled,true);
  await service.updateConfig({label:`echo ${fixtureKey}`});
  assert.equal(JSON.stringify(service.getPublicConfig()).includes(fixtureKey),false);
});

test('blank keys remain stored on the same service; new origins or protocols require a new key', async t => {
  const {service} = await fixture(t);
  await service.updateConfig(settings);
  await service.updateConfig({apiKey:'',model:'another-model'});
  assert.equal(service.getConfig().apiKey,fixtureKey);
  await assert.rejects(service.updateConfig({baseUrl:'https://other.example/v1',apiKey:''}),{code:'API_KEY_REQUIRED'});
  await assert.rejects(service.updateConfig({baseUrl:'https://model.example/v1/messages',provider:'anthropic',apiKey:''}),{code:'API_KEY_REQUIRED'});
  assert.equal(service.getConfig().provider,'openai-compatible');
  await service.updateConfig({baseUrl:'https://other.example/v1',apiKey:'replacement-fixture-key'});
  assert.equal(service.getConfig().apiKey,'replacement-fixture-key');
  await service.updateConfig({enabled:false,clearApiKey:true});
  assert.equal(service.getPublicConfig().apiKeySet,false);
  assert.equal(service.getConfig().ready,false);
});

test('unsecured services require explicit no-key mode on literal loopback IPs', async t => {
  const requests = [];
  const {service} = await fixture(t,{fetchImpl:async(url,options)=>{requests.push({url,headers:options.headers});return success('local');}});
  await service.updateConfig(settings);
  await service.updateConfig({baseUrl:'http://127.0.0.1:11434/v1',allowNoApiKey:true,apiKey:''});
  assert.equal(service.getPublicConfig().apiKeySet,false);
  assert.equal(service.getConfig().ready,true);
  await service.complete(ask);
  assert.equal(requests[0].headers.has('authorization'),false);
  assert.equal(requests[0].url,'http://127.0.0.1:11434/v1/chat/completions');
  await service.updateConfig({baseUrl:'http://[::1]:1234/v1',allowNoApiKey:true});
  await service.updateConfig({baseUrl:'http://localhost:11434/v1',allowNoApiKey:true});
  assert.equal(service.getConfig().baseUrl,'http://127.0.0.1:11434/v1/chat/completions');
  await assert.rejects(service.updateConfig({baseUrl:'https://remote.example/v1',allowNoApiKey:true}),{code:'NO_KEY_REMOTE'});
});

test('unsafe URLs are rejected without including submitted secrets in diagnostics', async t => {
  const {service} = await fixture(t);
  for (const baseUrl of ['http://remote.example/v1','http://2130706433/v1','http://127.1/v1','file:///tmp/model','https://user:password@model.example/v1',`https://model.example/v1?key=${fixtureKey}`,'https://model.example/v1#fragment']) {
    await assert.rejects(service.updateConfig({...settings,baseUrl}), error => {
      assert.equal(error.message.includes(fixtureKey),false);
      assert.equal(error.message.includes('password'),false);
      return ['UNSAFE_BASE_URL','INVALID_BASE_URL'].includes(error.code);
    });
  }
  await service.updateConfig({...settings,baseUrl:'https://192.168.1.10:8443/custom/v1'});
  assert.equal(service.getConfig().baseUrl,'https://192.168.1.10:8443/custom/v1/chat/completions');
  await assert.rejects(service.updateConfig({apiKey:'\ud800'}),{code:'INVALID_CONFIG'});
  await assert.rejects(service.testConnection('invalid form'),{code:'INVALID_CONFIG'});
});

test('atomic serialized persistence survives restart and a failed update does not poison the queue', async t => {
  const {service,dataDir} = await fixture(t);
  await service.updateConfig(settings);
  const first = service.updateConfig({label:'first'});
  const invalid = service.updateConfig({topK:100});
  const last = service.updateConfig({label:'last',enabled:false,topK:8});
  const results = await Promise.allSettled([first,invalid,last]);
  assert.deepEqual(results.map(result=>result.status),['fulfilled','rejected','fulfilled']);
  const saved = JSON.parse(await readFile(join(dataDir,'model-config.json'),'utf8'));
  assert.equal(saved.label,'last'); assert.equal(saved.apiKey,fixtureKey); assert.equal(saved.enabled,false);
  assert.deepEqual(await readdir(dataDir),['model-config.json']);
  if (process.platform !== 'win32') assert.equal((await stat(join(dataDir,'model-config.json'))).mode & 0o777,0o600);
  const restarted = createModelService({dataDir,env:{AI_BASE_URL:'https://env.example/v1',AI_MODEL:'env-model',AI_API_KEY:'environment-fixture'}});
  assert.equal(restarted.getConfig().apiKey,fixtureKey);
  assert.equal(restarted.getConfig().enabled,false);
  assert.equal(restarted.getConfig().ready,false);
  await assert.rejects(restarted.complete(ask),{code:'MODEL_DISABLED'});
});

test('environment settings are compatible while invalid files fail closed without replacing them', async t => {
  const {dataDir} = await fixture(t);
  const env = {AI_BASE_URL:'https://model.example/v1',AI_MODEL:'from-env',AI_API_KEY:fixtureKey,AI_ENABLED:'false'};
  const service = createModelService({dataDir,env});
  assert.equal(service.getConfig().configured,true); assert.equal(service.getConfig().ready,false);
  await writeFile(join(dataDir,'model-config.json'),`{broken: ${fixtureKey}`);
  const broken = createModelService({dataDir,env});
  assert.equal(broken.getConfig().enabled,false);
  assert.match(broken.getPublicConfig().configError,/重新保存/);
  assert.equal(JSON.stringify(broken.getPublicConfig()).includes(fixtureKey),false);
  assert.equal(await readFile(join(dataDir,'model-config.json'),'utf8'),`{broken: ${fixtureKey}`);
  await broken.updateConfig(settings);
  assert.equal(broken.getPublicConfig().configError,'');
  const invalidEnv = createModelService({dataDir:join(dataDir,'new'),env:{...env,AI_BASE_URL:'http://remote.example'}});
  assert.equal(invalidEnv.getConfig().enabled,false);
  assert.match(invalidEnv.getPublicConfig().configError,/环境变量/);
});

test('OpenAI requests use exact endpoint and response extraction redacts secrets and excludes non-text blocks', async t => {
  let request;
  const {service} = await fixture(t,{fetchImpl:async(url,options)=> {
    request = {url,...options};
    return success([{type:'thinking',text:'private reasoning'},{type:'text',text:`Evidence [1]. ${fixtureKey}`},{type:'output_text',text:'Second block.'}]);
  }});
  await service.updateConfig({...settings,baseUrl:'https://model.example/v1/chat/completions/'});
  const result = await service.complete({...ask,maxTokens:512});
  assert.equal(request.url,'https://model.example/v1/chat/completions');
  assert.equal(request.redirect,'manual');
  assert.equal(request.headers.get('Authorization'),`Bearer ${fixtureKey}`);
  const body = JSON.parse(request.body);
  assert.equal(body.model,'fixture-model'); assert.equal(body.max_tokens,512); assert.equal(body.temperature,0.1);
  assert.deepEqual(body.messages,[{role:'system',content:ask.system},...ask.messages]);
  assert.equal(request.body.includes(fixtureKey),false);
  assert.equal(result.text.includes(fixtureKey),false); assert.equal(result.text.includes('private reasoning'),false);
  assert.match(result.text,/Evidence \[1\]/); assert.match(result.text,/Second block/);
  assert.deepEqual(result.usage,{prompt_tokens:3,completion_tokens:4,total_tokens:7});
  assert.equal(typeof result.latencyMs,'number');
});

test('Anthropic Messages uses its headers and top-level system, and only returns text blocks', async t => {
  let request;
  const {service} = await fixture(t,{fetchImpl:async(url,options)=> {
    request = {url,...options};
    return new Response(JSON.stringify({content:[{type:'thinking',thinking:'do not return'},{type:'text',text:'Answer [2].'}],usage:{input_tokens:2,output_tokens:3}}));
  }});
  await service.updateConfig({...settings,provider:'anthropic',baseUrl:'https://api.anthropic.com'});
  const result = await service.complete(ask);
  assert.equal(request.url,'https://api.anthropic.com/v1/messages');
  assert.equal(request.headers.get('x-api-key'),fixtureKey);
  assert.equal(request.headers.get('anthropic-version'),'2023-06-01');
  assert.equal(request.headers.has('authorization'),false);
  const body = JSON.parse(request.body);
  assert.equal(body.system,ask.system); assert.deepEqual(body.messages,ask.messages);
  assert.equal(Object.hasOwn(body,'temperature'),false);
  assert.equal(result.text,'Answer [2].'); assert.deepEqual(result.usage,{input_tokens:2,output_tokens:3});
});

test('connection testing uses an unsaved fixed candidate and transmits only a generic ping', async t => {
  const requests = [];
  const {service,dataDir} = await fixture(t,{fetchImpl:async(url,options)=>{requests.push({url,...options});return success(`OK ${fixtureKey}`);}});
  const result = await service.testConnection(settings);
  assert.equal(result.ok,true); assert.equal(Object.hasOwn(result,'text'),false);
  assert.equal(JSON.stringify(result).includes(fixtureKey),false);
  assert.equal(service.getConfig().enabled,false);
  assert.deepEqual(await readdir(dataDir),[]);
  const payload = JSON.parse(requests[0].body);
  assert.match(payload.messages[1].content,/Reply OK/);
  assert.equal(payload.max_tokens,16);
  await service.updateConfig(settings);
  const snapshot = service.getConfig();
  await service.updateConfig({model:'changed-model',enabled:false});
  await service.complete({...ask,config:snapshot});
  assert.equal(JSON.parse(requests[1].body).model,'fixture-model');
});

test('redirects and HTTP errors never forward credentials or expose upstream error bodies', async t => {
  for (const status of [302,401,403,404,429,500]) await t.test(String(status), async child => {
    let calls = 0;
    const {service} = await fixture(child,{fetchImpl:async()=>{calls++;return new Response(`upstream raw ${fixtureKey}`,{status,headers:{Location:'https://other.example'}});}});
    await service.updateConfig(settings);
    await assert.rejects(service.complete(ask), error => {
      assert.equal(error.message.includes(fixtureKey),false); assert.equal(error.message.includes('upstream raw'),false);
      return error.code === (status === 302 ? 'MODEL_REDIRECT_REFUSED' : 'MODEL_HTTP_ERROR');
    });
    assert.equal(calls,1);
  });
});

test('network failures and invalid response bodies have bounded safe diagnostics', async t => {
  const cases = [
    [async()=>{throw new Error(`raw ${fixtureKey}`);},'MODEL_NETWORK_ERROR'],
    [async()=>{throw new TypeError(`raw ${fixtureKey}`,{cause:{code:'CERT_HAS_EXPIRED'}});},'MODEL_TLS_ERROR'],
    [async()=>new Response(`invalid ${fixtureKey}`),'MODEL_INVALID_RESPONSE'],
    [async()=>new Response(JSON.stringify({choices:[{message:{content:[]}}]})),'MODEL_EMPTY_RESPONSE'],
    [async()=>new Response('x',{headers:{'Content-Length':String(256*1024+1)}}),'MODEL_RESPONSE_TOO_LARGE'],
    [async()=>new Response('中'.repeat(90000)),'MODEL_RESPONSE_TOO_LARGE']
  ];
  for (const [fetchImpl,code] of cases) await t.test(code,async child=>{
    const {service} = await fixture(child,{fetchImpl}); await service.updateConfig(settings);
    await assert.rejects(service.complete(ask),error=>error.code===code&&!error.message.includes(fixtureKey));
  });
});

test('the request deadline includes fetches and body reads even when upstream ignores abort', async t => {
  await t.test('stalled fetch',async child=>{
    let signal;
    const {service} = await fixture(child,{fetchImpl:async(_url,options)=>{signal=options.signal;return new Promise(()=>{});}});
    await service.updateConfig(settings);
    const started = Date.now();
    await assert.rejects(service.complete({...ask,timeoutMs:30}),{code:'MODEL_TIMEOUT'});
    assert.equal(signal.aborted,true); assert.ok(Date.now()-started<1000);
  });
  for (const mode of ['stalled body','endless empty chunks']) await t.test(mode,async child=>{
    let cancelled = false;
    const stream = new ReadableStream(mode === 'stalled body' ? {start(controller){controller.enqueue(new Uint8Array([123]));},cancel(){cancelled=true;}} : {pull(controller){controller.enqueue(new Uint8Array(0));},cancel(){cancelled=true;}});
    const {service} = await fixture(child,{fetchImpl:async()=>new Response(stream)});
    await service.updateConfig(settings);
    const started = Date.now();
    await assert.rejects(service.complete({...ask,timeoutMs:30}),{code:'MODEL_TIMEOUT'});
    assert.equal(cancelled,true); assert.ok(Date.now()-started<1000);
  });
});
