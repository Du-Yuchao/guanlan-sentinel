import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { normalize, now } from './intelligence.mjs';

export function createStore(directory, seedPath) {
  mkdirSync(directory, { recursive: true });
  const db = new DatabaseSync(join(directory, 'sentinel.sqlite'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(kind,id));
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
  `);
  const allStmt = db.prepare('SELECT body FROM records WHERE kind=? ORDER BY updated_at DESC');
  const getStmt = db.prepare('SELECT body FROM records WHERE kind=? AND id=?');
  const upsert = db.prepare('INSERT INTO records(kind,id,body,updated_at) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at');
  const store = {
    all: kind => allStmt.all(kind).map(r => JSON.parse(r.body)),
    get: (kind, id) => { const r = getStmt.get(kind, id); return r ? JSON.parse(r.body) : null; },
    put: (kind, item) => { upsert.run(kind, String(item.id), JSON.stringify(item), now()); return item; },
    audit: (action, detail) => db.prepare('INSERT INTO audit(at,action,detail) VALUES(?,?,?)').run(now(), action, JSON.stringify(detail)),
    audits: () => db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 100').all().map(r => ({ ...r, detail: JSON.parse(r.detail) })),
    close: () => db.close(),
    seed: () => {
      if (!existsSync(seedPath)) return { count: 0 };
      const payload = JSON.parse(readFileSync(seedPath, 'utf8').replace(/^\uFEFF/, ''));
      const items = Array.isArray(payload) ? payload : payload.intel ?? payload.items ?? payload.records ?? [];
      let count = 0;
      for (const raw of items) {
        const item = normalize(raw);
        if (!store.get('intel', item.id)) { store.put('intel', item); count++; }
      }
      for (const source of payload.sources ?? []) if (!store.get('source', source.id)) store.put('source', { status: 'snapshot', count: items.filter(i => i.source === source.name).length, lastSync: null, ...source });
      for (const asset of payload.assets ?? []) if (!store.get('asset', asset.id)) store.put('asset', asset);
      return { count };
    },
    readSeed: () => {
      if (!existsSync(seedPath)) return [];
      const data = JSON.parse(readFileSync(seedPath, 'utf8').replace(/^\uFEFF/, ''));
      return Array.isArray(data) ? data : data.intel ?? data.items ?? data.records ?? [];
    }
  };
  store.seed();
  // Interrupted executions are never presented as completed after restart.
  for (const r of store.all('run')) if (r.status === 'running' || r.status === 'queued') {
    r.status = 'interrupted'; r.finishedAt = now(); r.summary = '服务重启，任务已中断，可重新运行';
    r.steps = (r.steps ?? []).map(s => s.status === 'running' ? { ...s, status: 'failed', detail: '服务重启导致中断' } : s);
    store.put('run', r);
  }
  return store;
}
