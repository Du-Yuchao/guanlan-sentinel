import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { normalize, hash } from '../lib/intelligence.mjs';
import { mergeObservation } from '../lib/ingestion.mjs';
import { createApplication } from '../server.mjs';

const observation = (summary, at) => normalize({id:'TEST-OBSERVATION', title:'Upstream update', products:['Example AI'], summary, url:'https://example.org/advisory', dataMode:'live'}, at);

test('live ingestion preserves verified fixes and both kinds of evidence with a consistent content hash', () => {
  const at='2026-10-18T01:00:00.000Z';
  const prior=normalize({id:'TEST-OBSERVATION',title:'已核验标题',summary:'已核验摘要',fixed:'1.2.3',remediation:'升级到 1.2.3',verifiedAt:'2026-10-17',ranges:[{fixed:'1.2.3'}],url:'https://example.org/advisory',dataMode:'snapshot',evidence:[{excerpt:'核验摘要',kind:'paraphrase'}]},'2026-10-17T01:00:00.000Z');
  const result=mergeObservation(prior,observation('new upstream evidence',at),{mode:'live',runId:'run-1',at});
  assert.equal(result.fixed,'1.2.3');assert.equal(result.remediation,'升级到 1.2.3');
  assert.equal(result.summary,'已核验摘要');assert.equal(result.liveSummary,'new upstream evidence');
  assert.equal(result.evidence.length,2);assert.ok(result.evidence.some(e=>e.snapshot));assert.ok(result.evidence.some(e=>!e.snapshot));
  assert.equal(result.contentHash,hash({title:result.title,summary:result.summary,url:result.url,evidence:result.evidence.map(e=>e.hash)}));
  const updated=mergeObservation(result,observation('different current evidence',at),{mode:'live',runId:'run-2',at});
  assert.equal(updated.evidence.length,2,'previous automatic extracts are replaced instead of growing indefinitely');
  assert.equal(updated.liveSummary,'different current evidence');
});

test('discovery times stay immutable and offline replay cannot replace current live observations', () => {
  const first='2026-10-18T01:00:00.000Z', second='2026-10-18T02:00:00.000Z';
  const initial=mergeObservation(null,observation('first',first),{mode:'live',runId:'run-1',at:first});
  const repeated=mergeObservation(initial,observation('second',second),{mode:'live',runId:'run-2',at:second});
  assert.equal(repeated.firstSeenAt,first);assert.equal(repeated.firstLiveAt,first);assert.equal(repeated.lastLiveAt,second);
  assert.equal(repeated.discoveryRunId,'run-1');assert.equal(repeated.lastLiveRunId,'run-2');
  const replay=mergeObservation(repeated,{...observation('old snapshot',second),dataMode:'snapshot'},{mode:'demo',runId:'run-demo',at:second});
  assert.equal(replay.summary,'second');assert.equal(replay.dataMode,'live');assert.equal(replay.lastLiveRunId,'run-2');
  const old=mergeObservation(normalize({id:'OLD',summary:'snapshot',dataMode:'snapshot'},first),observation('now live',second),{mode:'live',runId:'run-3',at:second});
  assert.equal(old.firstSeenMode,'snapshot');assert.equal(old.discoveryRunId,null);assert.equal(old.firstSeenAt,first);
});

test('the verified seed repairs fields lost by older sparse-live merges without inventing live evidence', () => {
  const at='2026-10-18T01:00:00.000Z';
  const damaged=normalize({...observation('retained Chinese summary',at),verifiedAt:'2026-10-17',fixed:'待核验',remediation:'核验原文'},at);
  const verifiedSnapshot={id:damaged.id,title:'Verified',summary:'Verified context',fixed:'1.2.3',remediation:'Upgrade 1.2.3',verifiedAt:'2026-10-17',url:'https://example.org/advisory',evidence:[{url:'https://example.org/research',excerpt:'Confirmed fix',kind:'paraphrase'}]};
  const result=mergeObservation(damaged,observation('current live extract',at),{mode:'live',runId:'run-new',at,verifiedSnapshot});
  assert.equal(result.fixed,'1.2.3');assert.equal(result.remediation,'Upgrade 1.2.3');
  assert.ok(result.evidence.some(e=>e.url==='https://example.org/research'&&e.snapshot===true));
  assert.ok(result.evidence.some(e=>e.excerpt==='current live extract'&&e.snapshot===false));
  assert.equal(result.discoveryRunId,null,'migration of an old record must not be counted as a new discovery');
  const replay=mergeObservation(damaged,normalize(verifiedSnapshot,at),{mode:'demo',runId:'replay',at,verifiedSnapshot});
  assert.equal(replay.fixed,'1.2.3');assert.equal(replay.dataMode,'live');
  assert.ok(replay.evidence.some(e=>e.excerpt===damaged.summary&&!e.snapshot),'a repair replay must retain existing live extracts');
  assert.equal(replay.lastLiveAt,damaged.lastLiveAt);
  const newer={...result,verifiedAt:'2026-10-19',fixed:'1.2.4'};
  assert.equal(mergeObservation(newer,observation('new',at),{mode:'live',runId:'new',at,verifiedSnapshot}).fixed,'1.2.4','an older bundled verification must not overwrite a newer local review');
});

test('startup restores legacy verified records outside the current feed window without creating live discoveries', async () => {
  const dataDir=await mkdtemp(join(tmpdir(),'guanlan-legacy-repair-'));
  let app=createApplication({dataDir});
  try {
    const prior=app.store.get('intel','CVE-2024-34359');
    app.store.put('intel',{...prior,dataMode:'live',fixed:'待核验',remediation:'核验原文',evidence:observation('old live extract',prior.collectedAt).evidence,lastLiveAt:'2026-10-17T12:00:00Z',lastLiveRunId:'legacy'});
    await app.close();app=null;
    app=createApplication({dataDir});
    const restored=app.store.get('intel','CVE-2024-34359');
    assert.equal(restored.fixed,'0.2.72');assert.match(restored.remediation,/0\.2\.72/);
    assert.equal(restored.lastLiveRunId,'legacy');assert.equal(restored.lastLiveAt,'2026-10-17T12:00:00Z');
    assert.ok(restored.evidence.some(e=>e.excerpt==='old live extract'&&!e.snapshot));
    assert.equal(restored.discoveryRunId,undefined);
    assert.ok(app.store.audits().some(a=>a.action==='intel.verified-context-restored'));
  } finally { if(app)await app.close();await rm(dataDir,{recursive:true,force:true}); }
});

test('live pipeline records primary, mirror, total failure and recovery without erasing history or data', async () => {
  const dataDir=await mkdtemp(join(tmpdir(),'guanlan-live-regression-'));
  let scenario='healthy';
  const app=createApplication({dataDir,collector:async source=>{
    if(scenario==='failed'||(scenario==='mixed'&&source.id==='github'))throw Object.assign(new Error('DNS 解析失败'),{code:'ENOTFOUND'});
    const mirror=scenario==='mixed'&&source.id==='vendor';
    return {items:source.id==='nvd'?[{id:'LIVE-REGRESSION',title:'Controlled live item',summary:scenario,published:'2026-10-18T00:00:00Z',url:'https://example.org/test',products:['Example AI'],dataMode:'live'}]:[],hash:hash(source.id+scenario),detail:'Controlled collector for regression',transport:{url:mirror?'https://api.github.com/repos/huggingface/hub-docs/contents/docs/hub/security-pickle.md':source.url,mode:mirror?'official-mirror':'primary',...(mirror?{primaryError:'连接来源超时',primaryErrorCode:'UND_ERR_CONNECT_TIMEOUT'}:{})}};
  }});
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  const base=`http://127.0.0.1:${app.server.address().port}`;
  const fetchJson=async path=>(await fetch(base+path)).json();
  const execute=async()=>{
    const id=app.startRun('live').id;
    for(let n=0;n<100;n++){
      const run=app.store.get('run',id);if(run.status!=='running')return run;
      await delay(10);
    }
    throw new Error('Controlled run did not finish');
  };
  try {
    const healthy=await execute();assert.equal(healthy.status,'completed');assert.deepEqual(healthy.sourceStats,{total:7,primary:7,mirrored:0,failed:0});
    const item=app.store.get('intel','LIVE-REGRESSION');assert.equal(item.discoveryRunId,healthy.id);
    const vendorPrimary=app.store.get('source','vendor').lastPrimarySuccess;
    scenario='mixed';const mixed=await execute();assert.equal(mixed.status,'partial');assert.deepEqual(mixed.sourceStats,{total:7,primary:5,mirrored:1,failed:1});
    let source=(await fetchJson('/api/sources')).items.find(s=>s.id==='vendor');assert.equal(source.status,'degraded');assert.equal(source.lastPrimarySuccess,vendorPrimary);assert.match(source.transport.primaryError,/超时/);assert.equal(source.changed,null,'switching from HTML to Markdown is not evidence of a page content change');
    assert.equal(app.store.get('intel','LIVE-REGRESSION').firstSeenAt,item.firstSeenAt);
    scenario='failed';const failed=await execute();assert.equal(failed.status,'failed');assert.deepEqual(failed.sourceStats,{total:7,primary:0,mirrored:0,failed:7});
    assert.equal(app.store.get('intel','LIVE-REGRESSION').summary,'mixed');
    assert.equal(app.store.get('run',mixed.id).sourceResults.find(s=>s.id==='vendor').status,'degraded','historical source results must not change with the latest health state');
    scenario='healthy';await execute();source=(await fetchJson('/api/sources')).items.find(s=>s.id==='vendor');assert.equal(source.status,'healthy');assert.equal(source.error,null);assert.equal(source.transport.primaryError,undefined);
  } finally { await app.close(); await rm(dataDir,{recursive:true,force:true}); }
});
