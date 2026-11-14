# cspaudit

`cspaudit` 用 Python 标准库解析 Content-Security-Policy 头，并对脚本请求做可解释的允许/拒绝评估。它不实现浏览器，也不依赖第三方 CSP 引擎；所有规则在本包内按 CSP source-list 语义计算。

## 指令解析规则

- CSP 头按 `;` 分割成指令，每条指令的第一个 token 是指令名，后续 token 构成 source-list。
- 指令名统一转小写，因此 `SCRIPT-SRC` 与 `script-src` 等价。
- 未知指令会被忽略，不影响同一条策略中的其它指令；拼写错误的 `scirpt-src` 不会变成 `script-src`。
- 同一策略中重复的已知指令保留第一条。
- `'none'` 单独出现时拒绝所有匹配；若与任何其它来源表达式共存，该指令整体无效，语义为禁止全部，并在 `reason` 中说明。
- 策略模式由 JSON 中的 `mode` 指定：`enforce` 参与拦截交集，`report-only` 只单独评估并列入 `report_only`。

## source-list 形态与语义

- `'self'`：只匹配与策略 `document_origin` 同 scheme、host、port 的 URL。
- `'none'`：拒绝全部；与其它表达式并存时触发该指令无效规则。
- host-source：支持 `https://cdn.example.com/app.js`、`cdn.example.com:443`、`*.example.com` 和端口通配。子域通配同时匹配裸域与更深子域。
- scheme-source：如 `https:`、`data:`、`blob:`，按请求 URL 的 scheme 匹配。
- `'nonce-<value>'`：请求携带的 nonce 必须与声明值逐字节一致；只匹配前缀会拒绝。
- `'sha256-<value>'`、`'sha384-<value>'`、`'sha512-<value>'`：对脚本 UTF-8 字节计算对应摘要，再做标准 Base64 无填充编码并完整比较。
- `'unsafe-inline'`：允许无匹配 nonce/hash 的内联脚本；当同指令存在 nonce 或 hash 时，该关键字对内联脚本不再放行。
- `'unsafe-eval'`：允许 `eval` 类型请求；普通外链和内联脚本不因它放行。
- `'strict-dynamic'`：生效时忽略 host-source、scheme-source 与 `'self'`；匹配 nonce 或由受信脚本动态传播的请求仍可允许。
- `'unsafe-hashes'`：允许事件处理器使用声明的脚本哈希；普通 `<script>` 内联块无需该关键字。

## nonce 与哈希比对

nonce 不使用前缀匹配：请求值和策略值都按 UTF-8 转成字节后做完整相等比较。任一缺失或长度不同都拒绝。

哈希以请求中的脚本文本为准，而不是信任请求自报的摘要。算法支持 SHA-256、SHA-384、SHA-512。输出值是标准 Base64，并移除末尾的 `=` 填充；比较时必须完整一致，因此改动一个字符也会拒绝。

## 多策略交集语义

拦截模式下，请求通过 `policy_ids` 显式声明适用的策略。评估器分别计算每条策略的结果，然后取交集：所有适用策略均允许才允许；任一策略拒绝，最终结果即拒绝。聚合结果仍只包含 `directive`、`request_id`、`allowed`、`reason` 四个字段，拒绝原因会列出触发拒绝的策略原因。

report-only 策略不进入拦截交集。每条 report-only 策略对每个请求生成一条独立结果，并在 `reason` 中带策略 ID。

## 输入格式

`demo/policies.json` 的顶层为 `policies` 数组，每项包含：

- `id`：策略 ID。
- `mode`：`enforce` 或 `report-only`。
- `document_origin`：用于解析 `'self'`。
- `header`：原始 CSP 头字符串。

`demo/requests.json` 的顶层为 `requests` 数组。外链请求使用 `type: external` 和 `url`；内联请求使用 `type: inline`、`inline_text` 和可选 `nonce`；动态求值使用 `type: eval`。`policy_ids` 写明该请求适用的拦截策略。

## 运行方式

```bash
python -m cspaudit.cli \
  --policies demo/policies.json \
  --requests demo/requests.json \
  --out out/report.json
```

命令会写出完整 JSON 报告，并在 stdout 打印一行摘要：策略数、请求数、允许数、拒绝数。

运行测试：

```bash
python -m unittest test_cspaudit -v
```
