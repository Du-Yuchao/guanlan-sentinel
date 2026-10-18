# 观澜开发集验证

生成时间：2026-10-17T16:42:56.790Z

开发集功能验证，7 个公开构造问题；非独立盲测，不代表领域问答准确率。引用命中仅验证检索，不验证答案语义正确性。

通过 7/7；指定来源召回率 100.0%。

|用例|结果|模式|耗时 ms|引用数|
|---|---|---|---:|---:|
|vuln-ollama|通过|retrieval|30|5|
|vuln-llama|通过|retrieval|8|1|
|prompt-injection|通过|retrieval|12|5|
|cross-document|通过|retrieval|14|5|
|missing-evidence|通过|retrieval|13|0|
|invented-cve|通过|retrieval|2|0|
|instruction-injection|通过|retrieval|12|0|

完整回答与来源见 evaluation.json。测试规模有限，禁止据此宣传生产级准确率。
