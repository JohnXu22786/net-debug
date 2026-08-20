# dsh-http-debug

面向 DeepSeek Harness（`dsh`）的 HTTP 网络调试工具集。

> **English documentation: [README.md](README.md)**

`dsh-http-debug` 是一个 **bundle**（可分发插件），为 dsh 提供通用 HTTP 客户端 ——
内置 **SSRF / 私网防护**、会话内 **请求历史与重放**、响应**检查**能力，以及零依赖的
**CLI**。它刻意聚焦于**原始 HTTP 语义**（方法、头、体、状态、耗时、大小），而不是页面抽取：
`web_fetch`/`web_search` 把文档转成 markdown；本插件则给你真实的一次交互。

```
一切都是插件 —— 这里的一切都是插件。
```

> 本项目为全新原创实现。它遵循 dsh bundle 规范（`package.json` 声明 `dsh.bundle`
> 补丁、附带 `cordis.patch.yml`、暴露插件入口模块），但代码从零编写，与任何现有插件无源码交集。

---

## 目录

- [功能](#功能)
- [安装到 dsh](#安装到-dsh)
- [面向模型的三件工具](#面向模型的三件工具)
- [配置](#配置)
- [SSRF 防护](#ssrf-防护)
- [响应语义](#响应语义)
- [历史记录](#历史记录)
- [CLI](#cli)
- [编程接口](#编程接口)
- [示例](#示例)
- [开发](#开发)
- [许可证](#许可证)

---

## 功能

1. **通用 HTTP 客户端**
   - `method` / `headers` / `body`（UTF-8 文本或 Base64 二进制）/ `timeout` /
     重定向策略（`follow_redirects`、`max_redirects`）。
   - 结构化响应：`status`、`statusText`、`headers`、body（UTF-8 文本或 Base64）、耗时与捕获大小。
2. **SSRF / 私网防护**（默认安全）
   - 默认拦截环回、RFC 1918 私网、CGNAT、链路本地、组播及其余保留 IPv4/IPv6 网段 ——
     包括**解析后落在这类地址的主机**以及**每一跳重定向**。
   - 支持白名单（主机名、`*.通配符`、IP、CIDR）与逐项开关。
3. **请求历史** —— 内存环形缓冲保存每次请求/响应对（含耗时与大小）；可列出、查看并**重放**。
4. **防 WAF 友好** —— 可选地设置合理的默认 `User-Agent` / `Referer`。
5. **响应检查** —— JSON 校验、可选 HAR 1.2 导出，以及硬性的 body 大小上限，防止超大响应撑爆上下文。
6. **工具链** —— 三件 dsh 工具（`http_request`、`http_history`、`http_rules`）
   外加使用同一引擎的独立 CLI。

---

## 安装到 dsh

包自描述为 bundle：

```jsonc
// package.json（本包）
{
  "dsh": { "bundle": { "patch": "./cordis.patch.yml" } }
}
```

`cordis.patch.yml` 插入一行配置，把本包挂到 `ctx` 上。插件入口模块（`lib/index.js`）
导出 `name`、`inject: ['tools']` 与 `apply(ctx)`，并把三件工具注册到 `ctx.tools`。

### 方式 A —— 把 bundle 加入某个 profile（推荐）

dsh 通过 `dsh plugin` 管理 profile 的外部插件，它会在 profile 目录内转发给包管理器：

```sh
dsh plugin --profile <name> add dsh-http-debug
```

或直接从本仓库安装：

```sh
dsh plugin --profile <name> add github:JohnXu22786/net-debug
```

（profile 首次使用时会按内置模板自动初始化；自定义名字需先用 `dsh plugin` 创建。）
该 bundle 的 `cordis.patch.yml` 随后作为 profile 组合的一部分被应用。

需要手动/离线配置时，可编辑 profile 的清单（`package.json` → `dsh.profile.bundles`），
把 `dsh-http-debug` 加进 bundles 列表，并确保包已安装到 Loader 能解析的位置。

### 方式 B —— 手动在 profile 的 `cordis.patch.yml` 加行

在 profile 的 `cordis.patch.yml` 中加入（裸 `name` 由 Loader 解析；确保包已安装到 dsh 能导入的位置）：

```yaml
- insert:
  - id: http-debug
    name: 'dsh-http-debug'
```

若要对单个 profile 调参，请把你保留的字段全部重写（补丁会整体替换该行的 `config`）：

```yaml
- insert:
  - id: http-debug
    name: 'dsh-http-debug'
    config:
      ssrf:
        enabled: true
        blockPrivate: true
        blockLoopback: true
        blockLinkLocal: true
        blockReserved: true
        whitelist:
          - 'localhost'
          - '127.0.0.1'
      client:
        timeoutMs: 30000
        maxRedirects: 10
        maxBodyBytes: 131072
        wafHeaders: true
        userAgent: 'Mozilla/5.0 (compatible; dsh-http-debug/1.0.0)'
        referer: ''
      history:
        maxEntries: 200
      har:
        enabled: false
```

### 验证接入

启动 dsh 并询问它有哪些工具，或直接检查注册表：

- 问模型："你有哪些 HTTP 工具？"
- 或在 REPL/agent 中：`ctx.tools.schemas()` 应包含 `http_request`、
  `http_history`、`http_rules`。

> `dsh` 处于开发者预览期，内部迭代很快。若你所用版本的 profile 机制
> （`dsh.profile.bundles`、`loadProfile`）有变，只要 Loader 仍能导入本包，
> 方式 B（手写 `cordis.patch.yml` 行）就依然可用。

---

## 面向模型的三件工具

三件工具都注册在 `ctx.tools` 上，agent 自动即可用。

### `http_request`

执行（或重放）一次 HTTP 交互。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `url` | string | 绝对 `http(s)` URL。使用 `history_id` 重放时可省略。 |
| `history_id` | string | 重放已存储的请求；此时忽略 `url`/`method`/`headers`/`body`。 |
| `method` | enum | `GET`（默认）、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`。 |
| `headers` | object | 请求头（名 → 值）。 |
| `body` | string | UTF-8 请求体。与 `body_base64` 二选一。 |
| `body_base64` | string | Base64 请求体。与 `body` 二选一。 |
| `timeout_ms` | number | 单次请求超时（默认取配置，30000）。 |
| `follow_redirects` | boolean | 是否跟随 3xx（默认 `true`）；每一跳都会做 SSRF 检查。 |
| `max_redirects` | number | 重定向次数上限（默认取配置，10）。 |
| `max_body_bytes` | number | 响应体捕获上限（默认取配置，131072）。 |
| `validate_json` | boolean | 校验类 JSON 的响应体并给出合法性。 |
| `include_har` | boolean | 为本次交互附带 HAR 1.2 文档。 |
| `bypass_ssrf` | boolean | **危险**：仅对本次请求关闭 SSRF 检查。 |
| `waf_headers` | boolean | 缺省时补充默认 `User-Agent` / 可选 `Referer`（默认取配置）。 |

返回结构化对象（见[响应语义](#响应语义)）；传输级失败（超时、网络错误、SSRF 拦截、
重定向过多等）抛出带机器可读 `code` 的错误。

### `http_history`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `action` | enum（必填） | `list`（新到旧摘要）、`get`（完整条目）、`clear`、`stats`。 |
| `id` | string | 历史条目 id（`action` 为 `get` 时必填）。 |

### `http_rules`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `action` | enum（必填） | `list`、`add`、`remove`、`clear`。 |
| `rule` | string | 一条白名单规则（主机名、`*.通配符`、IP、CIDR）。 |

运行时规则仅当次会话有效；需要持久白名单请在插件配置里设置 `ssrf.whitelist`。

---

## 配置

所有字段均可选，默认即安全值。

| 键 | 默认 | 含义 |
| --- | --- | --- |
| `ssrf.enabled` | `true` | 所有 IP/DNS 检查的总开关。 |
| `ssrf.blockPrivate` | `true` | 拦截 `10/8`、`172.16/12`、`192.168/16`、CGNAT `100.64/10`、ULA `fc00::/7`。 |
| `ssrf.blockLoopback` | `true` | 拦截 `127.0.0.0/8` 与 `::1`。 |
| `ssrf.blockLinkLocal` | `true` | 拦截 `169.254/16` 与 `fe80::/10`（含云元数据地址）。 |
| `ssrf.blockReserved` | `true` | 拦截其余特殊用途网段（文档、组播、广播、基准测试、NAT64/6to4 前缀等）。 |
| `ssrf.whitelist` | `[]` | 始终放行的主机 / `*.通配符` / IP / CIDR。 |
| `client.timeoutMs` | `30000` | 单次请求超时（毫秒）。 |
| `client.maxRedirects` | `10` | 重定向上限。 |
| `client.maxBodyBytes` | `131072` | 捕获响应体的字节上限，超出即截断。 |
| `client.wafHeaders` | `true` | 调用方未传时补充合理默认 `User-Agent`（以及配置的 `Referer`）。 |
| `client.userAgent` | 一个 Chrome UA | 默认 `User-Agent`。 |
| `client.referer` | `''` | 默认 `Referer`；为空表示不设置。 |
| `history.maxEntries` | `200` | 环形缓冲容量。 |
| `har.enabled` | `false` | 默认给每次响应附带 HAR。 |

---

## SSRF 防护

守卫在**请求前**以及**每一跳重定向前**校验目标。对每一跳它：

1. 解析 URL（仅允许 `http`/`https`）。
2. 若主机是 IP 字面量（IPv4、IPv6、IPv4 映射 `::ffff:a.b.c.d`、以及已废弃的
   IPv4 兼容 `::a.b.c.d`），直接归类。
3. 否则解析**全部** A/AAAA 记录（`node:dns`，可注入），只要**任一**落入被禁类别即拦截；
   DNS 出错也拒绝请求。
4. 主机名先查白名单；扫描解析结果时跳过命中白名单的地址。

curl 类工具会接受的一些紧凑数字主机也被拦下：`2130706433`（十进制）与 `0x7f000001`
（十六进制）都会映射为 `127.0.0.1` 并被拒绝。

### 白名单规则形式

| 形式 | 示例 | 匹配 |
| --- | --- | --- |
| 主机名 | `api.example.com` | 该确切主机 |
| 主机名 | `localhost` | 单标签主机 |
| 通配符 | `*.example.com` | `example.com` 及其所有子域 |
| IP 字面量 | `127.0.0.1`、`::1` | 该地址 |
| CIDR | `10.42.0.0/16`、`fd00::/8` | 该网段（对字面量主机，也对**解析后落在段内**的主机） |

### 安全提示（部署前请读）

- **默认为安全。** 生产环境请保持四个 `block*` 开关全部开启。
- **`bypass_ssrf`（工具参数；CLI 里对应 `--allow-private`）是显式逃生门。**
  仅用于可信目标；它针对该次请求关闭私网/环回/链路本地/保留地址检查。
- **关闭 `ssrf.enabled` 等于关闭全部防护**（包括 DNS 拒绝）。
- 白名单是「每一跳目标」的放行名单，不是跳出名单的通行证：每一跳仍按当前规则独立评估。
- 本守卫是可靠的兜底，不是沙箱。请与你的抓取策略、出口网络控制以及对恶意内容的沙箱化搭配使用。
- **DNS 重绑定提示。** 守卫与真实的网络连接是先后独立解析同一主机名的：恶意 DNS 可能对守卫
  给出公网地址、对连接给出私网地址。对抗性部署场景下，请配合出口控制或沙箱，确保即便
  DNS 竞态被赢得，最终的连接也无法触达内网。

---

## 响应语义

一次成功的交互返回类似这样的对象：

```jsonc
{
  "ok": true,                 // 2xx
  "status": 200,
  "statusText": "OK",
  "httpVersion": "HTTP/1.x",
  "method": "GET",
  "url": "https://…",
  "headers": { "content-type": "application/json" },
  "contentType": "application/json",
  "body": "…",                // 文本时为 UTF-8；二进制时为 Base64
  "bodyEncoding": "utf8",     // "utf8" | "base64" | "none"
  "bodySizeBytes": 512,       // 实际捕获的字节数（已受上限约束）
  "bodyTruncated": false,     // body 被截断时为 true
  "durationMs": 1234,
  "redirected": false,
  "redirects": [],
  "json": { "valid": true },  // 仅当开启 validate_json
  "har": { "log": { … } },    // 仅当开启 include_har
  "historyId": "h7"
}
```

- **body 编码**：文本类 Content-Type（以及嗅探为干净 UTF-8 的无类型 body）解码为文本，
  其余一律 Base64；多字节字符不会被从中间切断。
- **截断**：捕获字节数受 `maxBodyBytes`（单次或配置）约束，并置 `bodyTruncated`；
  实际捕获量为 `bodySizeBytes`。这是防止上下文爆炸的第一道防线。
- **4xx/5xx 是真实响应**，以 `ok: false` 返回；只有传输级失败（URL 非法、SSRF 拦截、
  DNS 失败、超时、网络错误、重定向过多、被中止）才会抛错，且带稳定 `code`。
- **HAR** 输出为标准的单条目 HAR 1.2 `log` 文档（`buildHarLog`）。

### 错误码

`INVALID_URL` · `UNSUPPORTED_PROTOCOL` · `SSRF_BLOCKED` · `DNS_FAILED` ·
`TIMEOUT` · `ABORTED` · `NETWORK_ERROR` · `TOO_MANY_REDIRECTS` ·
`HISTORY_NOT_FOUND` · `INVALID_RULE` · `INVALID_BODY`

---

## 历史记录

会话内环形缓冲（容量 `history.maxEntries`）记录每一次 `http_request`：请求快照、
响应（已截断)、耗时、大小以及任何错误。`http_history` 负责列出/查看/清空；
`http_request` 通过 `history_id` 重放并记下一次全新尝试 —— 每一跳都会重新做 SSRF 检查。

---

## CLI

同一引擎的零依赖命令行前端，SSRF 防护完全一致：

```sh
npm link   # 或：node lib/cli.js …   或：npx tsx src/cli.ts …

dsh-http-debug <url> [options]
  -X, --method <m>          HTTP 方法
  -H, --header <n:v>        请求头（可重复；也接受 n=v）
  -d, --data <body>         UTF-8 body
      --data-base64 <b64>   base64 body
      --data-file <path>    从文本文件读 body
      --data-binary <path>  从文件原样读 body
      --timeout <ms>        超时（毫秒；0 表示不超时，默认 30000）
  -F/--follow | -N/--no-follow
      --max-redirects <n>   --max-body-bytes <n>
      --validate-json       --har <文件>
      --json                以 JSON 打印完整结构化结果（默认）
      --raw                 只打印 body
      --allow-private       本次请求绕过 SSRF（不安全）
      --rule <rule>         添加运行时白名单规则（可重复）
      --no-waf
      --ssrf-enabled        启用 SSRF 拦截（默认）
      --ssrf-disabled       关闭全部 SSRF 防护（不安全）
      --config-file <path>  JSON 配置文件（命令行参数优先）
  -v, --version             打印版本
  -h, --help                打印帮助
```

所有参数都映射到工具所使用的同一个 `HttpDebug` 服务。

---

## 编程接口

核心无依赖，可独立嵌入：

```ts
import { HttpDebug } from 'dsh-http-debug';

const http = new HttpDebug({
  config: { ssrf: { whitelist: ['127.0.0.1'] } },
});

const response = await http.request({ url: 'http://127.0.0.1:3000/', validateJson: true });
console.log(response.status, response.body, response.historyId);

http.rulesAdd('10.0.0.0/8');        // 运行时白名单
await http.request({ historyId: 'h1' }); // 重放
```

导出：`HttpDebug`、`HttpClient`、`SsrfGuard`、`HistoryStore`、`RuleStore`、
`buildHarLog`、各类配置/响应类型，以及带 `code` 的 `HttpDebugError`。

---

## 示例

- `examples/usage.mjs` —— 在纯 Node 脚本里调用核心。
- `examples/dsh-integration.mjs` —— 把 bundle 挂入真实 Cordis `Context` + `ToolRegistry`，
  并通过真实管线执行 `http_request`。
- `examples/generate-examples.mjs` —— 起一个本地服务器并写出 `examples/response.example.json`
  与 `examples/har.example.har`。
- `examples/response.example.json`、`examples/har.example.har` —— 生成的样例产物。

自行生成：

```sh
npm run build
npm run generate-examples
```

---

## 开发

```sh
npm install       # 开发依赖：typescript、tsx、@types/node 及 dsh 对等类型
npm run build     # tsc -> lib/（ESM，含 .d.ts）
npm run typecheck
npm test          # 先构建，再对编译产物跑 `node --test`
npm run cli -- <url> …   # 用 tsx 从源码运行 CLI
```

测试覆盖：IPv4/IPv6 各级地址族归类、SSRF 守卫（字面量、DNS 解析主机、IPv4 映射/兼容地址、
紧凑数字主机、重定向跳、白名单/开关/绕过、DNS 失败）、重定向追踪与方法降级、body 截断、
Base64 二进制 body、超时、网络错误、JSON 校验、HAR 结构、历史环形缓冲淘汰与重放、
工具定义、插件入口。

测试运行需要 Node ≥ 23.6（或 22.18 LTS 版），这些版本默认开启原生 TypeScript
类型剥离，`node --test` 可直接运行测试文件。**发布产物的运行时**（编译出的 `lib/`）
支持 Node 18+（使用内置 `fetch`）。唯一运行时依赖是 dsh 主宿提供的对等包
（`@deepseek-ai/cordis`、`@deepseek-ai/dsh-tools`）。

---

## 许可证

[MIT](LICENSE) — © 2026 dsh-http-debug 贡献者。
