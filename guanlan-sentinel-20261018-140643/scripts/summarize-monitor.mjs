import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readEvidence, summarizeRecords } from './monitor-observation.mjs';

export async function main(args = process.argv.slice(2)) {
  if (args.includes('--help') || args.includes('-h')) { console.log('用法：node scripts/summarize-monitor.mjs [--file artifacts/monitoring/observations.jsonl]\n校验追加日志并输出 JSON 汇总；不修改证据文件。'); return; }
  if (args.length && (args.length !== 2 || args[0] !== '--file')) throw new Error('仅支持 --file <证据文件>');
  const records = await readEvidence(resolve(args[1] ?? 'artifacts/monitoring/observations.jsonl'));
  console.log(JSON.stringify(summarizeRecords(records), null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { console.error(error.message); process.exitCode = 1; });
