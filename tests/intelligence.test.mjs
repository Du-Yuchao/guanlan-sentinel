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
