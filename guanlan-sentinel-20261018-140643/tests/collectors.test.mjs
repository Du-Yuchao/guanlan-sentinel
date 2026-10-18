import { test } from 'node:test';
import assert from 'node:assert/strict';
import { boundedFetch, boundedFetchResult, collectSource, DEFAULT_SOURCES, HF_OFFICIAL_MIRROR } from '../lib/collectors.mjs';

// Every upstream is simulated. These tests never require DNS, credentials, or a live service.
const startUrl = 'https://source.example/start';
const page = '<h1>Official security document</h1><p>' + 'Evidence from the official source. '.repeat(15) + '</p>';
const markdown = '# Pickle Scanning\n\n' + 'Official Hugging Face documentation source. '.repeat(15);
const vendor = DEFAULT_SOURCES.find(source => source.id === 'vendor');
const networkError = code => new TypeError('fetch failed', {cause:{code}});
const noRetries = {maxRetries:0,backoffMs:0};

test('boundedFetch preserves its text API and sends a recognizable User-Agent', async () => {
  const text = await boundedFetch(startUrl,{fetchImpl:async (url,options) => {
    assert.equal(url,startUrl); assert.equal(options.redirect,'manual');
    assert.match(options.headers.get('user-agent'),/Guanlan-Sentinel/);
    return new Response('upstream text');
  }});
  assert.equal(text,'upstream text');
});

test('HTTPS relative redirects are bounded and the actual final URL is reported', async () => {
  const calls = [];
  const result = await boundedFetchResult(startUrl,{fetchImpl:async url => {
    calls.push(url);
    return calls.length === 1 ? new Response('',{status:302,headers:{Location:'/document'}}) : new Response('document');
  }});
  assert.deepEqual(calls,[startUrl,'https://source.example/document']);
  assert.deepEqual(result,{text:'document',url:'https://source.example/document',attempts:2,redirects:1,retries:0});
});

test('redirect policy rejects downgrade, credentials, unapproved origins, and loops without retry', async t => {
  for (const [location,code] of [
    ['http://source.example/document','UNSAFE_URL'],
    ['https://user:secret@source.example/document','UNSAFE_URL'],
    ['https://127.0.0.1/document','UNSAFE_REDIRECT'],
    ['https://source.example:8443/document','UNSAFE_URL'],
    [startUrl,'REDIRECT_LIMIT']
  ]) await t.test(code+' '+location,async () => {
    let calls = 0;
    await assert.rejects(boundedFetchResult(startUrl,{maxRedirects:2,backoffMs:0,fetchImpl:async () => {
      calls++; return new Response('',{status:302,headers:{Location:location}});
    }}),error => error.code === code && !error.retryable);
    assert.equal(calls,code === 'REDIRECT_LIMIT' ? 3 : 1);
  });
  let calls = 0;
  await assert.rejects(boundedFetch('http://source.example',{fetchImpl:async () => {calls++;}}),{code:'UNSAFE_URL'});
  assert.equal(calls,0);
});

test('audited cross-origin HTTPS redirects remove authorization and cookies', async () => {
  const result = await boundedFetchResult(startUrl,{
    allowedRedirectOrigins:['https://cdn.example'],headers:{Authorization:'Bearer test',Cookie:'test=value'},
    fetchImpl:async (url,options) => {
      if (url === startUrl) return new Response('',{status:307,headers:{Location:'https://cdn.example/document'}});
      assert.equal(options.headers.has('authorization'),false); assert.equal(options.headers.has('cookie'),false);
      return new Response('safe');
    }
  });
  assert.equal(result.url,'https://cdn.example/document');
});

test('the deadline covers a stalled fetch even when the fake upstream ignores abort', async () => {
  let requestSignal;
  const started = Date.now();
  await assert.rejects(boundedFetch(startUrl,{...noRetries,timeout:30,totalTimeout:200,fetchImpl:async (_,options) => {
    requestSignal = options.signal; return new Promise(() => {});
  }}),{code:'TIMEOUT'});
  assert.equal(requestSignal.aborted,true); assert.ok(Date.now()-started < 800);
});

test('the same deadline covers stalled response-body reads and cancels the reader', async () => {
  let cancelled = false;
  const body = new ReadableStream({start(controller){controller.enqueue(new Uint8Array([1,2,3]));},cancel(){cancelled=true;}});
  const started = Date.now();
  await assert.rejects(boundedFetch(startUrl,{...noRetries,timeout:30,fetchImpl:async () => new Response(body)}),{code:'TIMEOUT'});
  assert.equal(cancelled,true); assert.ok(Date.now()-started < 800);
});

test('an endless sequence of empty chunks cannot starve the timeout or accumulate chunk buffers', async () => {
  let cancelled = false; const started = Date.now();
  const stream = new ReadableStream({pull(controller){controller.enqueue(new Uint8Array(0));},cancel(){cancelled=true;}});
  await assert.rejects(boundedFetch(startUrl,{...noRetries,timeout:25,fetchImpl:async () => new Response(stream)}),{code:'TIMEOUT'});
  assert.equal(cancelled,true); assert.ok(Date.now()-started < 800);
});

test('both declared and streamed response sizes are limited in bytes without retry', async t => {
  await t.test('Content-Length',async () => {
    let calls = 0, cancelled = false;
    await assert.rejects(boundedFetch(startUrl,{maxBytes:4,fetchImpl:async () => {
      calls++;
      return new Response(new ReadableStream({cancel(){cancelled=true;}}),{headers:{'Content-Length':'5'}});
    }}),{code:'RESPONSE_TOO_LARGE'});
    assert.equal(calls,1); assert.equal(cancelled,true);
  });
  await t.test('streamed UTF-8 bytes',async () => {
    let calls = 0;
    await assert.rejects(boundedFetch(startUrl,{maxBytes:4,fetchImpl:async () => {calls++; return new Response('中文');}}),{code:'RESPONSE_TOO_LARGE'});
    assert.equal(calls,1);
  });
});

test('explicit transient network failures, 429, and 5xx receive at most two retries', async () => {
  let calls = 0;
  const result = await boundedFetchResult(startUrl,{backoffMs:0,fetchImpl:async () => {
    calls++;
    if (calls === 1) throw networkError('ECONNRESET');
    if (calls === 2) return new Response('',{status:429});
    return new Response('recovered');
  }});
  assert.equal(result.text,'recovered'); assert.equal(result.attempts,3); assert.equal(result.retries,2);
  calls = 0;
  await assert.rejects(boundedFetch(startUrl,{backoffMs:0,fetchImpl:async () => {calls++; return new Response('',{status:503});}}),
    error => error.code === 'HTTP_503' && error.retryable && error.status === 503 && error.attempts === 3);
  assert.equal(calls,3);
});

test('permanent failures have actionable error categories and are not retried', async t => {
  for (const [upstreamCode,expectedCode] of [['EACCES','NETWORK_PERMISSION'],['CERT_HAS_EXPIRED','TLS_ERROR'],['ENOTFOUND','DNS_ERROR'],['UNKNOWN','NETWORK_ERROR']]) {
    await t.test(upstreamCode,async () => {
      let calls = 0;
      await assert.rejects(boundedFetch(startUrl,{backoffMs:0,fetchImpl:async () => {calls++; throw networkError(upstreamCode);}}),
        error => error.code === expectedCode && !error.retryable && error.cause.cause.code === upstreamCode);
      assert.equal(calls,1);
    });
  }
  let calls = 0;
  await assert.rejects(boundedFetch(startUrl,{fetchImpl:async () => {calls++; return new Response('missing',{status:404});}}),{code:'HTTP_404'});
  assert.equal(calls,1);
});

test('Retry-After is respected within the bounded backoff and total request budget', async () => {
  let calls = 0; const started = Date.now();
  const result = await boundedFetchResult(startUrl,{backoffMs:1,maxBackoffMs:40,totalTimeout:500,fetchImpl:async () => {
    calls++; return calls === 1 ? new Response('',{status:503,headers:{'Retry-After':'0.04'}}) : new Response('ready');
  }});
  assert.equal(result.attempts,2); assert.ok(Date.now()-started >= 30); assert.ok(Date.now()-started < 800);
  calls = 0;
  await assert.rejects(boundedFetch(startUrl,{backoffMs:1,maxBackoffMs:40,fetchImpl:async () => {calls++; return new Response('',{status:429,headers:{'Retry-After':'3600'}});}}),{code:'HTTP_429'});
  assert.equal(calls,1,'a long Retry-After must stop this run rather than be shortened');
  calls = 0;
  await assert.rejects(boundedFetch(startUrl,{totalTimeout:25,backoffMs:100,fetchImpl:async () => {calls++; return new Response('',{status:503});}}),{code:'HTTP_503'});
  assert.equal(calls,1,'a retry must not begin after the total deadline');
});

test('Hugging Face fallback fetches the official current document and preserves primary failure evidence', async () => {
  const calls = [];
  const result = await collectSource(vendor,{backoffMs:0,fetchImpl:async (url,options) => {
    calls.push(url);
    if (url === vendor.url) throw networkError('UND_ERR_CONNECT_TIMEOUT');
    assert.equal(url,HF_OFFICIAL_MIRROR);
    assert.equal(options.headers.get('accept'),'application/vnd.github.raw+json');
    return new Response(markdown);
  }});
  assert.equal(calls.filter(url => url === vendor.url).length,3);
  assert.equal(result.transport.url,HF_OFFICIAL_MIRROR); assert.equal(result.transport.mode,'official-mirror');
  assert.equal(result.transport.primaryErrorCode,'TIMEOUT'); assert.equal(result.transport.primaryUrl,vendor.url);
  assert.equal(result.transport.mirrorStatus,'succeeded'); assert.equal(result.transport.attempts,4);
  assert.match(result.detail,/实时读取.*官方 GitHub/); assert.match(result.detail,/不代表主站恢复/);
  assert.match(result.pageExcerpt,/Pickle Scanning/); assert.deepEqual(result.items,[]); assert.ok(result.hash);
});

test('a successful primary check uses fresh primary metadata without stale fallback errors', async () => {
  const prior = {...vendor,transport:{mode:'official-mirror',primaryError:'old failure'}};
  let calls = 0;
  const result = await collectSource(prior,{fetchImpl:async url => {calls++; assert.equal(url,vendor.url); return new Response(page);}});
  assert.equal(calls,1); assert.equal(result.transport.mode,'primary'); assert.equal(result.transport.url,vendor.url);
  assert.equal('primaryError' in result.transport,false); assert.equal('mirrorStatus' in result.transport,false);
  assert.doesNotMatch(result.detail,/备用|快照/);
});

test('both upstream failures retain separate primary and mirror diagnostics', async () => {
  await assert.rejects(collectSource(vendor,{...noRetries,fetchImpl:async url => {
    if (url === vendor.url) throw networkError('UND_ERR_CONNECT_TIMEOUT');
    return new Response('unavailable',{status:503});
  }}),error => {
    assert.equal(error.code,'FALLBACK_FAILED'); assert.equal(error.primaryErrorCode,'TIMEOUT'); assert.equal(error.mirrorErrorCode,'HTTP_503');
    assert.equal(error.transport.mode,'official-mirror'); assert.equal(error.transport.mirrorStatus,'failed');
    assert.equal(error.transport.mirrorErrorCode,'HTTP_503'); assert.match(error.transport.mirrorError,/503/);
    assert.equal(error.transport.attempts,2); assert.equal(error.transport.retries,0); assert.equal(error.transport.redirects,0);
    assert.equal(error.transport.url,HF_OFFICIAL_MIRROR); assert.match(error.message,/主站失败.*官方备用失败/);
    return true;
  });
});

test('the official fallback rejects JSON envelopes or unexpected documents as live evidence', async () => {
  await assert.rejects(collectSource(vendor,{...noRetries,fetchImpl:async url => {
    if (url === vendor.url) throw networkError('UND_ERR_CONNECT_TIMEOUT');
    return new Response(JSON.stringify({content:markdown}));
  }}),error => error.code === 'FALLBACK_FAILED' && error.mirrorErrorCode === 'INVALID_RESPONSE');
});

test('fallback is limited to the audited built-in document and is not used for TLS or permission failures', async t => {
  for (const source of [{...vendor,url:'https://other.example/document'},vendor]) {
    for (const code of ['CERT_HAS_EXPIRED','EPERM']) await t.test(source.url+' '+code,async () => {
      let calls = 0;
      await assert.rejects(collectSource(source,{backoffMs:0,fetchImpl:async () => {calls++; throw networkError(code);}}));
      assert.equal(calls,1);
    });
  }
});

test('the whole source budget includes primary timeout and a stalled mirror body', async () => {
  const calls = [], started = Date.now();
  await assert.rejects(collectSource(vendor,{sourceTimeout:120,primaryTimeout:35,timeout:1000,maxRetries:0,fetchImpl:async url => {
    calls.push(url);
    if (url === vendor.url) return new Promise(() => {});
    return new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('# Pickle Scanning\n'));}}));
  }}),error => error.code === 'FALLBACK_FAILED' && ['SOURCE_TIMEOUT','TIMEOUT'].includes(error.mirrorErrorCode));
  assert.deepEqual(calls,[vendor.url,HF_OFFICIAL_MIRROR]); assert.ok(Date.now()-started < 800);
});

test('an already cancelled source makes no upstream requests', async () => {
  const controller = new AbortController(); controller.abort(); let calls = 0;
  await assert.rejects(collectSource(vendor,{signal:controller.signal,fetchImpl:async () => {calls++; return new Response(page);}}));
  assert.equal(calls,0);
});

test('all adapters preserve their existing result shape and expose actual transport metadata', async () => {
  const fixtures = {nvd:'{"vulnerabilities":[]}',github:'[]',arxiv:'<feed></feed>',blog:'<rss><channel></channel></rss>',page};
  for (const source of DEFAULT_SOURCES) {
    const result = await collectSource(source,{fetchImpl:async () => new Response(fixtures[source.adapter])});
    assert.deepEqual(result.items,[],source.id); assert.ok(result.hash,source.id); assert.ok(result.detail,source.id);
    assert.equal(result.transport.mode,'primary',source.id); assert.match(result.transport.url,/^https:\/\//);
  }
  await assert.rejects(collectSource(DEFAULT_SOURCES.find(source=>source.adapter==='github'),{fetchImpl:async () => new Response('not JSON')}),{code:'INVALID_RESPONSE'});
});
