# 导入冻结人工标注集并评测

`scripts/evaluate.mjs` 的 7 题用于开发验证，不能作为独立盲测或事实准确率证据。本工具不复制这些问题，也不自建几题就称为独立集。当前仓库只提供格式模板，没有独立人工标注集或正式准确率结果。

`scripts/evaluate-heldout.mjs` 使用 Node.js 内置模块。它逐题调用本机 `POST /api/ask`，保存完整输入、原始响应、答案、模式、耗时、引用、拒答标志、错误和文件哈希。它不会导入情报、操作数据库或修改应用配置；应用自身可能记录问答审计日志。

## 准备样本

复制 `data/evaluation/template.json` 后，用独立采样、人工核验的真实问题与金标准替换所有虚构示例。模板中的所有题均标记 `example: true` 和 `excludeFromMetrics: true`，即使修改集合状态也不会纳入正式统计。不要直接删除标志后把模板或开发集当作独立测试集。

建议由没有参与开发用例编写的人负责采样和标注。先确定采样范围和数量，再查看系统输出；覆盖版本边界、同名/近名产品区分、多文档比较及证据不足的拒答。保存每条标准答案依据的原始公告、归档时间、版本与哈希。冻结后不要依据本轮回答改题或修改标准；若修订，另存新版本并重新运行。工具只能记录提供者的独立性声明，无法证明采样独立、标注真实或未发生训练/开发泄漏。

输入文件是一个 JSON 对象：

|字段|含义|
|---|---|
|`schemaVersion`|固定为 `1`|
|`dataset.id`|数据集版本标识|
|`dataset.status`|`example` / `draft` / `frozen`；只有 `frozen` 的未排除题纳入正式统计|
|`dataset.frozenAt`|冻结时间，使用 ISO 8601；`frozen` 必填|
|`dataset.annotationSource`|标注来源/人员、流程或来源清单说明；`frozen` 必填|
|`dataset.sourceSnapshot`|证据与知识库快照的归档位置、时间、版本和哈希说明；`frozen` 必填|
|`dataset.notUsedForDevelopment`|正式集必须显式填写 `true`；这是提供者声明，不是工具核验结论|
|`samples[].id`|唯一、非空 ID|
|`samples[].category`|人工定义分层，例如 `version`、`product`、`multi-document`、`abstention`|
|`samples[].question`|1–4000 字符，原样提交为 `{ "question": "…" }`|
|`samples[].example` / `excludeFromMetrics`|任一为 `true` 时仅留存运行记录，不纳入正式统计|
|`samples[].gold.citationIds`|完整预期来源 ID 集合，必须与 API 返回的 `citations[].id` 对应；不使用标题/CVE 字符串包含匹配|
|`samples[].gold.abstained`|人工确定是否应拒答，布尔值|
|`samples[].gold.answerRubric`|人工核验的事实判定准则数组，明确版本边界、产品归属、逐项结论及允许的不确定性|

`gold` 及其子字段允许缺失，工具会明确计数，不能用缺失标准计算事实准确率。`citationIds: []` 表示确定应无引用；与缺失字段不同。预期答案可以正确拒答，同时具有拒答的事实判定准则。

## 运行并保存原始输出

先按项目现有方式启动本机服务，再执行：

```powershell
node scripts/evaluate-heldout.mjs --input data/evaluation/heldout-v1.json --base-url http://127.0.0.1:8787 --output artifacts/heldout-v1-run.json
```

默认地址是 `EVAL_BASE_URL` 或 `http://127.0.0.1:8787`。`--timeout-ms 60000` 可调整每题超时，范围 1–300000 ms。所有请求串行执行；超时和 HTTP/JSON 错误保留为失败题，继续后续题。输出 JSON 与同名 Markdown；输出不得覆盖输入样本、评分文件或 `--from-report` 的原报告。

评测器只允许 `http://localhost`、`http://127.0.0.0/8`、`http://[::1]` 及端口；`localhost` 固定改为 `127.0.0.1`。拒绝远程主机、HTTPS、URL 凭据、路径、查询和片段；不跟随重定向。评测器本身只请求回环 HTTP。若应用启用了远程模型，`/api/ask` 仍可能按应用配置调用模型；需在运行前按所测模式配置服务，并保持知识库和资产快照固定。不同运行模式不宜混合宣称同一个性能结果。

`--output` 默认 `artifacts/heldout-evaluation.json`。存在请求失败时仍写报告，进程退出码为 `1`；全部请求成功时为 `0`。退出码不表示问题事实正确，也不是自动通过门槛。

## 人工复核并导入 JSONL

先检查原报告的逐题 `input`、`response.answer`、`citations`、`gold`，逐项对照归档来源，判断答案是否满足完整准则。引用编号有效并不证明陈述有来源支持；引用 ID 命中也不证明产品、版本或结论正确。

人工评分文件每行一个 JSON 对象。下面仅演示字段，必须从原报告复制真实哈希、填写真实评分，不能直接使用占位符：

```json
{"sampleId":"真实题目ID","datasetSha256":"原报告input.sha256的64位小写十六进制值","responseSha256":"该题responseSha256的64位小写十六进制值","reviewer":"复核人或可追溯标识","reviewedAt":"2026-10-18T10:00:00+08:00","factualCorrect":true,"note":"逐项符合冻结准则，补充必要证据定位"}
```

`factualCorrect` 只允许 `true`、`false` 或 `null`。`null` 表示尚未给出分数，保留在未评分计数中。每个 `sampleId` 只能有一条记录；日期、审核者、两个哈希必填。评测器不会生成、猜测或代理人工评分。评分文件缺失的题、缺金标准的题、请求失败的题、哈希不匹配的题都保留在正式样本总数及人工覆盖率的分母中。

复核原运行时使用 `--from-report`，避免重新请求产生不同答案：

```powershell
node scripts/evaluate-heldout.mjs --input data/evaluation/heldout-v1.json --from-report artifacts/heldout-v1-run.json --reviews data/evaluation/heldout-v1-reviews.jsonl --output artifacts/heldout-v1-reviewed.json
```

该命令不请求 API。它核对样本文件 SHA-256、原始响应 SHA-256，再从原始响应重算自动检查；保留原 `runId`、运行时间与延迟。新报告另外记录原报告文件哈希、评分文件哈希和汇总时间。原样本的任何字节变化（包括空格或换行）都会改变哈希，禁止把旧报告套用于新样本。

`--reviews` 也可在首次请求时提供，但只有实际返回的响应哈希完全一致时评分才有效；人工复核通常应使用上述两阶段流程。

## 指标解释

- **引用 ID precision / recall**：逐题对预期和实际 ID 集合去重，做区分大小写的精确匹配，再汇总为微平均。precision = 匹配 ID 数 / 实际有效 ID 数；recall = 匹配 ID 数 / 预期 ID 数。没有 `gold.citationIds` 的题明确计数，不加入这两个指标。请求失败视为空预测，预期引用仍进入 recall 分母。分母为 0 时值为 `null`，不伪造 100%。这些指标不衡量引用相关性、证据蕴含或答案语义。
- **结构及引用编号检查**：检查响应对象、非空答案与模式、布尔拒答标志、引用数组及 ID/index、答案 `[n]` 是否指向本次引用。非拒答回答需有引用。检查不会验证来源 URL 的真实性或证明事实正确。
- **拒答预期匹配**：只在具有人工 `gold.abstained` 的题上比较布尔标志。返回 HTTP 错误或缺失标志计不匹配。同时显示预期拒答、实际拒答、缺金标准题数；它不评判拒答措辞和拒答原因是否合理。
- **P50 / P95**：正式纳入样本的端到端耗时，使用 nearest-rank，包含失败与超时。每题耗时和模式均保留；小样本分位数不宜推广为生产性能。
- **人工复核覆盖率**：有效、与本次响应哈希绑定的布尔评分数 / 全部正式样本数。缺失、无效或未打分记录不能从分母消失。
- **已复核子集事实正确计数**：正确评分数 / 有效布尔评分数。报告明确它只描述已复核子集，不能当作全样本准确率。
- **全样本事实准确率**：仅当正式样本非空、每题都存在事实金标准且每题都完成有效人工复核时提供。分子为正确题数，分母为全部正式样本数。任何一题缺标准、请求失败或缺有效评分时，此值为 `null` 并显示原因；不能用自动引用命中率替代。

报告保存输入文件原始字节 SHA-256、逐题响应哈希、评分文件哈希、完整答案和评分记录。它只能支持结果追溯，不能自动认证输入的独立性、源文件真实性或评分者身份。应保留报告及实际证据快照，交由复核者检查。

## 验证工具本身

```powershell
node --test tests/evaluation.test.mjs
```

测试只使用内存合成题与本地假 HTTP API，验证精确引用匹配、缺失评分分母、拒绝陈旧哈希、重放人工评分、超时、错误响应与禁止重定向等行为。不会启动应用、采集外网、读取真实运行数据库或提供独立集的效果数字。现有开发集验证可继续单独运行；两者的用途不能混淆。
