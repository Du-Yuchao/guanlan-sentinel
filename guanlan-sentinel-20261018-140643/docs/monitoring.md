# 实时观测证据

这套工具让已启动的本地服务持续执行实时采集，并把每轮可用性、失败原因、运行状态及新增情报时效保存为追加 JSONL。默认目标为 72 小时；仓库中的工具和测试不代表已经完成 72 小时实测。离线快照、假 API 测试和一次验收不能替代持续观测证据。

需要 Node.js 22.12 或以上版本，无额外依赖。先在项目目录运行 `npm start`，保持服务终端开启，再开一个 PowerShell 终端执行以下命令。

## 单次验收

```powershell
node scripts/monitor-observation.mjs --once --file artifacts/monitoring/acceptance.jsonl
```

该命令会真正通过本机 API 启动一次 `live` 任务，因此需要公开情报来源的网络连接；不会读取 `.env`、模型密钥或直接打开数据库。记录包括源 URL、主站错误和采集错误，均来自本地 HTTP API。CLI 仅接受无凭据、无附加路径的回环 HTTP 目标，默认 `http://127.0.0.1:8787`；拒绝重定向。`localhost` 固定连接至 `127.0.0.1`。

## 72 小时观测

```powershell
node scripts/monitor-observation.mjs --interval-minutes 30 --duration-hours 72 --file artifacts/monitoring/72h.jsonl
```

每轮先读取情报 ID 基线，再创建实时任务、轮询终态并记录结果。默认每 30 分钟尝试一轮，单次 HTTP 超时 15 秒、运行等待上限 180 秒。可用 `--poll-ms`、`--request-timeout-ms` 和 `--run-timeout-ms` 调整。本工具不会修改服务自身的后台监测配置；验收时应避免同时启动另一个自动采集进程，否则 HTTP 409 会记录为冲突失败。

运行期间保持电脑和服务开启，避免休眠。Ctrl+C 会保存中止事件并停止本工具。已触发的服务任务可能继续执行；下次使用同一个证据文件时，会先恢复原运行的轮询，避免重复提交。HTTP 超时和暂时断网也会保留待恢复周期。再次运行的 `--duration-hours` 表示该次进程的额外观测时长；暂停时间不会被悄悄填成成功样本。

若进程在 POST 请求后、运行 ID 写入前异常退出，恢复时会在 `/api/runs` 中寻找本周期开始后唯一的实时运行。无法唯一定位时会保留不确定记录，不猜测运行 ID；可先核对服务中的任务列表，再使用新文件开展新的观测，保留旧文件作为中断证据。不要手动改写旧 JSONL。正常中止会释放 `.lock`；进程崩溃遗留的锁会在确认原 PID 已结束后自动清理。不可读的锁或持续残留的 `.lock.recovery` 需要先确认没有监测进程后手动处理；锁恢复本身采用互斥，避免并发恢复删掉新进程的锁。

## 汇总和判读

```powershell
node scripts/summarize-monitor.mjs --file artifacts/monitoring/72h.jsonl
node scripts/summarize-monitor.mjs --file artifacts/monitoring/72h.jsonl > artifacts/monitoring/72h-summary.json
```

汇总命令只读取证据，不改写旧行，可随时重新计算增量结果。它先校验各行及前序哈希，再输出 JSON：

- `totals` 和 `sources` 分别统计主站成功、官方备用成功、全部失败及未知状态。备用成功不会算成主站恢复；`primaryRecoveries` 只在此前失败/备用后观察到实际主站成功时递增。
- `coverage.observationSpanHours` 是首轮开始至最后终态观察的跨度；`recordedSessionHours` 是已记录会话的时长，`maximumSampleGapHours` 是相邻终态样本的最大间隔。跨度不能独立证明连续覆盖，`gapExceedsSchedule` 为 true 时应检查间隙。
- `publicationLatency` 只统计本次运行之前不存在、由本轮真正新建的实时条目，要求 `firstSeenMode=live`、`discoveryRunId` 匹配且不可变 `firstSeenAt` 位于本轮开始之后。旧快照首次转为 live、重复抓取、其他运行入库均排除。
- 只有合法 `published` 且不晚于首次入库的样本进入延迟分布。无合格新增条目时 count 为 0、统计值为 null。仅日期的发布时间按 UTC 当日 00:00 估算，单列 `datePrecisionCount`，不能把它当成秒级精确时效。`timestampPrecisionCount` 给出具有时间及明确时区的样本数。

JSONL 保留基线 ID、运行 ID、开始/结束时间、步骤、summary、该轮 `sourceResults`、主/备用 URL、错误、内容哈希及每条时效样本。每行包含 `previousHash` 与 SHA-256 `hash`，并在写入后同步到磁盘。哈希链用于发现意外修改，不提供第三方签名或可信时间戳；应保留原文件和运行环境记录。尾行损坏、非法 JSON 或链不一致时工具拒绝续写，须保留原件并另建文件。

CLI 正常单次/到时结束返回 0；存在运行失败、运行中断（`interrupted`）、运行取消（`cancelled`）、请求失败或未恢复周期返回 1；Ctrl+C 优先返回 130。中断和取消各自保留为终态并分别计数，不作为成功退出。部分成功会如实记录为 `partial`，来源备用和失败需按明细判读。已在程序内实现记录流程；实际 72 小时证据必须由本机持续运行后生成，不应预填成功率、条数或时效达标结论。

## 本地验证

```powershell
node --test tests/monitor-observation.test.mjs
```

测试只启动回环假 API 并使用临时文件，覆盖主/备用/失败分类、新入库时效筛选、追加完整性、超时与中止恢复、HTTP 409 和坏 JSON。不会访问公网或修改运行数据库。
