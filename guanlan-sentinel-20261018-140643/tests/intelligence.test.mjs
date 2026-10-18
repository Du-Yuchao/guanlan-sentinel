import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, assetFinding, normalize, retrieve, hash } from '../lib/intelligence.mjs';

const intel=normalize({id:'CVE-TEST',title:'教学产品版本测试',type:'vulnerability',url:'https://example.org/advisory',products:['Example AI'],ranges:[{product:'Example AI',introduced:'1.0.0',fixed:'1.2.10'}],summary:'教学产品测试，不是真实漏洞公告。'});
test('numeric version comparison respects patch order and missing components',()=>{
  assert.equal(compareVersions('1.2.9','1.2.10'),-1);
  assert.equal(compareVersions('v1.2','1.2.0'),0);
  assert.equal(compareVersions('1.10','1.9.99'),1);
  assert.equal(compareVersions('latest','1.0'),null);
  assert.equal(compareVersions('1.2.0-rc1','1.2.0'),null);
});
test('version range boundaries are inclusive at start, exclusive at fixed',()=>{
  const result=version=>assetFinding({product:'Example AI',version},intel).status;
  assert.equal(result('0.9.9'),'not_affected');assert.equal(result('1.0.0'),'affected');
  assert.equal(result('1.2.9'),'affected');assert.equal(result('1.2.10'),'not_affected');
  assert.equal(result('latest'),'unknown');
});
test('missing ranges never assert safety and unrelated products do not match',()=>{
  assert.equal(assetFinding({product:'Example AI',version:'8.0'}, {...intel,ranges:[],fixed:'待核验'}).status,'unknown');
  assert.equal(assetFinding({product:'Different Product',version:'1.0'},intel),null);
});
test('multiple vulnerable release branches are evaluated independently',()=>{
  const branched={...intel,ranges:[{introduced:'1.0',fixed:'1.2'},{introduced:'2.0',fixed:'2.3'}]};
  assert.equal(assetFinding({product:'Example AI',version:'1.3'},branched).status,'not_affected');
  assert.equal(assetFinding({product:'Example AI',version:'2.1'},branched).status,'affected');
});
test('evidence hashes detect content changes and remain stable for same content',()=>{
  assert.equal(hash('evidence'),hash('evidence'));assert.notEqual(hash('evidence'),hash('changed evidence'));
  assert.equal(intel.evidence[0].hash,hash(intel.evidence[0].excerpt));
});
test('unknown explicit CVE is never replaced with a similar known identifier',()=>{
  const known=normalize({id:'CVE-2024-37032',title:'Ollama 安全公告',summary:'Ollama 漏洞与修复',products:['Ollama'],url:'https://nvd.nist.gov/vuln/detail/CVE-2024-37032'});
  assert.equal(retrieve('CVE-2099-999999 如何修复？',[known]).length,0);
  assert.equal(retrieve('CVE-2024-37032 如何修复？',[known])[0].item.id,known.id);
});

const retrievalFixture = (id, product, extra = {}) => normalize({
  id, title: `${product} vulnerability fixed`, summary: `${product} 漏洞和修复说明。`,
  products: [product], tags: ['漏洞', '修复'], url: `https://example.org/${id}`, ...extra
});

test('many high-scoring bulletins for one product cannot crowd a second named product out of the first five citations',()=>{
  const crowded = Array.from({length:20},(_,i)=>retrievalFixture(`ATLAS-LIVE-${i}`,'Atlas Engine'));
  const reviewed = retrievalFixture('ATLAS-REVIEWED','Atlas Engine',{verifiedAt:'2026-01-01'});
  const other = retrievalFixture('BEACON-ONLY','Beacon SDK',{title:'Beacon SDK advisory',summary:'Beacon SDK evidence',tags:[]});
  const items = [...crowded, reviewed, other];
  const found = retrieve('Atlas Engine 和 Beacon SDK 分别有什么漏洞，需要如何修复？',items);
  assert.equal(found.length,6);
  assert.equal(found[0].item.id,reviewed.id,'bounded preference should favor otherwise equivalent reviewed evidence');
  assert.equal(found[1].item.id,other.id,'coverage must be reserved before filling with more high-scoring Atlas bulletins');
  assert.ok(found.slice(0,5).some(row=>row.item.id===other.id));
  assert.ok(found.find(row=>row.item.id===other.id).score < found.at(-1).score,'coverage is deliberately allowed to outrank score-only filling');
  assert.equal(new Set(found.map(row=>row.item.id)).size,found.length);
  assert.deepEqual(items.map(row=>row.id),[...crowded,reviewed,other].map(row=>row.id),'retrieval must not reorder its input');
});

test('single-product questions respect word boundaries and do not treat Ollama as Llama or a similarly named SDK',()=>{
  const items = [retrievalFixture('BASE','Llama'),retrievalFixture('OLLAMA','Ollama'),
    retrievalFixture('SDK','OllamaSDK'),retrievalFixture('PYTHON','llama-cpp-python')];
  assert.deepEqual(retrieve('Ollama 的漏洞和修复建议是什么？',items).map(row=>row.item.id),['OLLAMA']);
  assert.deepEqual(retrieve('Llama 的漏洞和修复建议是什么？',items).map(row=>row.item.id),['BASE']);
  assert.deepEqual(retrieve('OllamaSDK 的漏洞和修复建议是什么？',items).map(row=>row.item.id),['SDK']);
  assert.deepEqual(retrieve('llama-cpp-python 的漏洞和修复建议是什么？',items).map(row=>row.item.id),['PYTHON']);
});

test('separator spelling variants retain compound product identity and suppress nested product-name mentions',()=>{
  const items = [retrievalFixture('SHORT','Llama'),retrievalFixture('COMPOUND','llama-cpp-python')];
  for(const name of ['llama cpp python','llama_cpp_python','llama.cpp.python']) {
    assert.deepEqual(retrieve(`${name} 有哪些漏洞及修复建议？`,items).map(row=>row.item.id),['COMPOUND'],name);
  }
  const named = [retrievalFixture('ENGINE','Example'),retrievalFixture('LONG','Example AI')];
  assert.deepEqual(retrieve('Example AI 有哪些漏洞？',named).map(row=>row.item.id),['LONG']);
  assert.deepEqual(retrieve('Example 和 Example AI 分别有哪些漏洞？',named).map(row=>row.item.id),['ENGINE','LONG']);
});

test('coverage anchors for up to five named products stay inside downstream top five and obey smaller limits',()=>{
  const names=['Alpha Engine','Beta Engine','Gamma Engine','Delta Engine','Epsilon Engine'];
  const items=[...Array.from({length:15},(_,i)=>retrievalFixture(`A-${i}`,names[0])),
    ...names.slice(1).map((name,i)=>retrievalFixture(`PRODUCT-${i+1}`,name,{summary:'Independent product evidence',tags:[]}))];
  const question=`${names.join(' 和 ')} 分别有哪些漏洞和修复建议？`;
  const found=retrieve(question,items);
  assert.deepEqual(new Set(found.slice(0,5).flatMap(row=>row.item.products)),new Set(names));
  assert.equal(retrieve(question,items,2).length,2);
  assert.equal(retrieve(question,items,0).length,0);
});

test('one joint-product source can cover two explicit products without duplicate citations',()=>{
  const joint=retrievalFixture('JOINT','Alpha Engine',{products:['Alpha Engine','Beta Engine'],title:'Alpha Engine and Beta Engine vulnerability fixed'});
  const items=[joint,retrievalFixture('ALPHA','Alpha Engine'),retrievalFixture('BETA','Beta Engine')];
  const found=retrieve('Alpha Engine 和 Beta Engine 的漏洞与修复？',items);
  assert.equal(found[0].item.id,'JOINT');
  assert.equal(found.filter(row=>row.item.id==='JOINT').length,1);
  assert.equal(found.length,3);
});

test('product coverage and reviewed metadata cannot defeat unknown-CVE refusal or create relevance alone',()=>{
  const known=retrievalFixture('CVE-2031-12345','Atlas Engine',{verifiedAt:'2026-01-01'});
  const items=[known,...Array.from({length:12},(_,i)=>retrievalFixture(`LIVE-${i}`,'Atlas Engine'))];
  assert.deepEqual(retrieve('Atlas Engine CVE-2031-1234 如何修复？',items),[],'identifier prefixes must not match a longer known CVE');
  assert.deepEqual(retrieve('Atlas Engine CVE-2031-12345 和 CVE-2098-998877 如何修复？',items),[]);
  assert.deepEqual(retrieve('unrelatedwordwithoutmatches',items),[],'verified evidence must still be relevant');
  assert.equal(retrieve('Atlas Engine CVE-2031-12345 修复建议？',items)[0].item.id,known.id);
});
