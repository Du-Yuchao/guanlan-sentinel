# 资料核验记录

核验日期：2026-10-17。以下为公开原始来源的结构化摘要。完整条目、来源 URL、核验时间和版本依据保存在 `data/verified_sources.json`。摘要为中文整理，不能当作原文直接引语。没有核验的 CVSS 或发布日期保持空值。

## 正式命题

学校官方网站发布页：<https://jwc.hdu.edu.cn/2026/0917/c13022a300465/page.htm>。已下载其赛题九附件并保存为 `source/赛题九-官方命题.pdf`。赛题要求与当前实现的差距见 `competition-plan.md`。

## 漏洞版本依据

|条目|核验来源|结构化事实|
|---|---|---|
|CVE-2024-37032|[Wiz 原始研究](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)|Ollama 的修复版本为 0.1.34；样例使用 0.1.33 与 0.1.34 对照|
|CVE-2024-34359|[GitHub 安全公告](https://github.com/advisories/GHSA-56xg-wfcc-g829)|llama-cpp-python 0.2.30 至 0.2.71 受影响，0.2.72 修复|

Ollama 条目的来源适配器类别为 NVD，但本次版本事实根据 Wiz 原始研究核验；证据中保留 Wiz URL，不能声称已从 NVD 核验 CVSS。版本命中只说明落入已知公告范围，实际影响仍与部署条件相关。

## 研究与指导资料

|来源|本地用途|
|---|---|
|[Hugging Face Pickle 安全说明](https://huggingface.co/docs/hub/security-pickle)|模型文件与反序列化风险|
|[Trail of Bits 智能体注入研究](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)|外部内容、工具执行权限及隔离|
|[间接提示词注入论文](https://arxiv.org/abs/2302.12173)|跨文档防护问题的研究证据|
|[提示词注入攻击与防御评测](https://arxiv.org/abs/2310.12815)|评测方法与研究关联|
|[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)|风险管理框架|
|[OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)|提示词注入|
|[OWASP LLM03](https://genai.owasp.org/llmrisk/llm032025-supply-chain/)|供应链风险|
|[OWASP LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)|过度代理权限|
|[OWASP LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)|系统提示词泄漏|
|[OWASP LLM08](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)|向量和嵌入弱点|
|[OWASP LLM09](https://genai.owasp.org/llmrisk/llm092025-misinformation/)|错误信息|
|[国家网信办政策原文](https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm)|生成式人工智能服务管理暂行办法的资料索引|

当前 14 条资料构成可复现的小型工程验证集，不代表完整、最新的 AI 安全情报库。七类联网适配器的实际范围和限制已列在技术报告中。历史资料不计作今日新增发现。
