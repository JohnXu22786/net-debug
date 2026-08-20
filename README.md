# dsh-http-debug

[![CI](https://github.com/JohnXu22786/net-debug/actions/workflows/ci.yml/badge.svg)](https://github.com/JohnXu22786/net-debug/actions/workflows/ci.yml)

HTTP network debugging toolset for DeepSeek Harness (`dsh`).

> **中文文档：[README.zh.md](README.zh.md)**

`dsh-http-debug` is a **bundle** (a distributable plugin) that adds a general-purpose
HTTP client to dsh — with **SSRF / private-network protection**, per-session
**request history with replay**, response **inspection**, and a zero-dependency
**CLI**. It deliberately focuses on *raw HTTP semantics* (method, headers, body,
status, timing, size) rather than page extraction: `web_fetch`/`web_search` turn
documents into markdown; this plugin gives you the actual exchange.

```
Everything is a plugin — everything here is a plugin.
```

> This project is an original implementation. It follows the dsh bundle
> specification (a npm package whose `package.json` declares a `dsh.bundle`
> patch, ships a `cordis.patch.yml`, and exposes a plugin entry module), but it
> is written from scratch and shares no code with any existing plugin.

---

## Table of contents

- [Features](#features)
- [Installation into dsh](#installation-into-dsh)
- [Model-facing tools](#model-facing-tools)
- [Configuration](#configuration)
- [SSRF protection](#ssrf-protection)
- [Response semantics](#response-semantics)
- [History](#history)
- [CLI](#cli)
- [Programmatic API](#programmatic-api)
- [Examples](#examples)
- [Development](#development)
- [License](#license)

---

## Features

1. **General HTTP client**
   - `method` / `headers` / `body` (UTF-8 text or Base64 binary) / `timeout` /
     redirect policy (`follow_redirects`, `max_redirects`).
   - Structured response: `status`, `statusText`, `headers`, body (UTF-8 text
     or Base64), timing, and captured size.
2. **SSRF / private-network protection** (secure by default)
   - Blocks loopback, RFC 1918 private, CGNAT, link-local, multicast, and other
     reserved IPv4/IPv6 ranges — including hosts that *resolve* to them and
     **every redirect hop**.
   - Whitelist (hosts, `*.wildcards`, IP literals, CIDRs) and config toggles.
3. **Request history** — an in-memory ring buffer keeps every request/response
   pair (with timing and size); entries can be listed, inspected, and **replayed**.
4. **WAF-friendly** — optional sane default `User-Agent` / `Referer`.
5. **Response inspection** — JSON validation, optional HAR 1.2 export, and a
   hard body-size cap so oversized responses never blow up the prompt/context.
6. **Tooling** — three dsh tools (`http_request`, `http_history`, `http_rules`)
   plus a standalone CLI with the same engine.

---

## Installation into dsh

The package self-describes as a bundle:

```jsonc
// package.json (this package)
{
  "dsh": { "bundle": { "patch": "./cordis.patch.yml" } }
}
```

`cordis.patch.yml` inserts one configuration row that mounts this package on
`ctx`. The plugin entry module (`lib/index.js`) exports `name`, `inject: ['tools']`
and `apply(ctx)` and registers the three tools on `ctx.tools`.

### Route A — add the bundle to a profile (recommended)

dsh manages a profile's out-of-tree plugins through `dsh plugin`, which
forwards to the package manager inside the profile directory:

```sh
dsh plugin --profile <name> add dsh-http-debug
```

or straight from this repository:

```sh
dsh plugin --profile <name> add github:JohnXu22786/net-debug
```

(The profile is auto-initialized from its shipped template on first use; a
custom name must be created via `dsh plugin` first.) The bundle's
`cordis.patch.yml` is then applied as part of the profile composition.

For a manual/offline setup, edit the profile's manifest
(`package.json` → `dsh.profile.bundles`) and add `dsh-http-debug` to the
bundles list, and ensure the package is installed where the Loader can resolve
it.

### Route B — patch a profile's `cordis.patch.yml` manually

Add this to your profile's `cordis.patch.yml` (a bare `name` resolves through
the Loader; make sure the package is installed where dsh can import it):

```yaml
- insert:
  - id: http-debug
    name: 'dsh-http-debug'
```

To tune configuration for one profile, restate the fields you keep (a patch
replaces the row's *whole* `config`):

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

### Verify the integration

Boot dsh and ask it which tools it has, or inspect the registry directly:

- Ask the model: *"which HTTP tools do you have?"*
- Or in a REPL/agent: `ctx.tools.schemas()` should include `http_request`,
  `http_history`, and `http_rules`.

> `dsh` is in developer preview and its internals move fast. If the exact
> profile mechanisms (`dsh.profile.bundles`, `loadProfile`) changed in your
> version, Route B (a hand-written `cordis.patch.yml` row) continues to work as
> long as the Loader can import the package.

---

## Model-facing tools

All three tools are registered on `ctx.tools` and become available to agents
automatically.

### `http_request`

Perform (or replay) one HTTP exchange.

| Parameter | Type | Description |
| --- | --- | --- |
| `url` | string | Absolute `http(s)` URL. Omit when replaying via `history_id`. |
| `history_id` | string | Replay a stored request; `url`/`method`/`headers`/`body` are ignored. |
| `method` | enum | `GET` (default), `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`. |
| `headers` | object | Request headers (name → value). |
| `body` | string | UTF-8 request body. Mutually exclusive with `body_base64`. |
| `body_base64` | string | Base64 request body. Mutually exclusive with `body`. |
| `timeout_ms` | number | Per-request timeout (default from config, 30000). |
| `follow_redirects` | boolean | Follow 3xx (default `true`); every hop is SSRF-checked. |
| `max_redirects` | number | Redirect cap (default from config, 10). |
| `max_body_bytes` | number | Captured-body cap (default from config, 131072). |
| `validate_json` | boolean | Validate a JSON-looking body and report validity. |
| `include_har` | boolean | Attach a HAR 1.2 document for this exchange. |
| `bypass_ssrf` | boolean | **Danger**: disable SSRF checks for this one request. |
| `waf_headers` | boolean | Add default `User-Agent` / optional `Referer` when absent (default from config). |

Returns a structured object (see [Response semantics](#response-semantics));
transport failures (timeout, network, SSRF block, too many redirects) raise
errors with a machine-readable `code`.

### `http_history`

| Parameter | Type | Description |
| --- | --- | --- |
| `action` | enum (required) | `list` (newest-first summaries), `get` (full entry), `clear`, `stats`. |
| `id` | string | History id (required when `action` is `get`). |

### `http_rules`

| Parameter | Type | Description |
| --- | --- | --- |
| `action` | enum (required) | `list`, `add`, `remove`, `clear`. |
| `rule` | string | A whitelist rule (hostname, `*.wildcard`, IP literal, or CIDR). |

Runtime rules last only for the current session; for a durable whitelist set
`ssrf.whitelist` in the plugin config.

---

## Configuration

All fields are optional; defaults are the safe ones.

| Key | Default | Meaning |
| --- | --- | --- |
| `ssrf.enabled` | `true` | Master switch for all IP/DNS checks. |
| `ssrf.blockPrivate` | `true` | Block `10/8`, `172.16/12`, `192.168/16`, CGNAT `100.64/10`, ULA `fc00::/7`. |
| `ssrf.blockLoopback` | `true` | Block `127.0.0.0/8` and `::1`. |
| `ssrf.blockLinkLocal` | `true` | Block `169.254/16` and `fe80::/10` (covers cloud metadata). |
| `ssrf.blockReserved` | `true` | Block the remaining special-use ranges (documentation, multicast, broadcast, benchmarking, NAT64/6to4 prefixes, …). |
| `ssrf.whitelist` | `[]` | Hosts / `*.wildcards` / IPs / CIDRs that always pass. |
| `client.timeoutMs` | `30000` | Per-request timeout in ms. |
| `client.maxRedirects` | `10` | Redirect cap. |
| `client.maxBodyBytes` | `131072` | Captured body bytes; larger bodies are truncated. |
| `client.wafHeaders` | `true` | Add sane default `User-Agent` (and `Referer` if configured) when the caller doesn't send one. |
| `client.userAgent` | a Chrome UA | Default `User-Agent`. |
| `client.referer` | `''` | Default `Referer`; empty means none. |
| `history.maxEntries` | `200` | Ring-buffer capacity. |
| `har.enabled` | `false` | Attach HAR to every response by default. |

---

## SSRF protection

The guard verifies a target **before** the request and **before every redirect
hop**. For each hop it:

1. Parses the URL (`http`/`https` only).
2. If the host is an IP literal (IPv4, IPv6, IPv4-mapped `::ffff:a.b.c.d`, or
   the deprecated IPv4-compatible `::a.b.c.d`), classifies it directly.
3. Otherwise resolves **all** A/AAAA records (`node:dns`, injectable) and blocks
   if **any** resolves to a disallowed address. DNS errors refuse the request.
4. Consults the whitelist first for hostnames, and skips whitelisted resolved
   addresses while scanning.

Compact numeric hosts that `curl`-style tools accept are also caught:
`2130706433` (decimal) and `0x7f000001` (hex) map to `127.0.0.1` and are
refused.

### Whitelist rule forms

| Form | Example | Matches |
| --- | --- | --- |
| hostname | `api.example.com` | that exact host |
| hostname | `localhost` | a single-label host |
| wildcard | `*.example.com` | `example.com` and every sub-domain |
| IP literal | `127.0.0.1`, `::1` | that address |
| CIDR | `10.42.0.0/16`, `fd00::/8` | the range (for literal hosts and for hosts *resolving* inside it) |

### Security notes (read before deploying)

- **Secure by default.** In production leave all four `block*` switches on.
- **`bypass_ssrf` (tool parameter, `--allow-private` in the CLI) is an explicit
  escape hatch.** Only use it for trusted targets; it disables, for that
  request, the private/loopback/link-local/reserved checks.
- **Disabling `ssrf.enabled` turns off all protection** (including DNS refusal).
- The whitelist is an *allowlist for hop targets*, not a free pass for
  redirects that leave it: every hop is evaluated against the current rules.
- This guard is a strong safety net, not a sandbox. Pair it with your fetch
  policy, network egress controls, and sandboxing for hostile content.
- **DNS-rebinding note.** The guard and the actual connection resolve the
  hostname separately, so a hostile name server could in principle answer the
  guard with a public address and the connection with a private one. For
  adversarial deployments, combine this guard with egress controls or a
  sandbox so the final connection cannot reach internal networks even if the
  DNS race is won.

---

## Response semantics

A successful exchange returns an object like:

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
  "body": "…",                // UTF-8 text, or Base64 when binary
  "bodyEncoding": "utf8",     // "utf8" | "base64" | "none"
  "bodySizeBytes": 512,       // bytes captured (after any cap)
  "bodyTruncated": false,     // true when the body was capped
  "durationMs": 1234,
  "redirected": false,
  "redirects": [],
  "json": { "valid": true },  // only when validate_json
  "har": { "log": { … } },    // only when include_har
  "historyId": "h7"
}
```

- **Body encoding**: textual Content-Types (plus untyped bodies that sniff as
  clean UTF-8) are decoded to text; everything else is Base64. Multi-byte
  characters are never cut mid-sequence.
- **Truncation** caps captured bytes at `maxBodyBytes` (per-call or config) and
  flags `bodyTruncated`; the amount actually captured is `bodySizeBytes`. This
  is the primary guard against context explosion.
- **4xx/5xx are real responses**, returned with `ok: false`. Only transport
  failures (invalid URL, SSRF block, DNS failure, timeout, network error, too
  many redirects, abort) raise errors, each with a stable `code`.
- **HAR** output is a standard HAR 1.2 `log` document with one entry
  (`buildHarLog`).

### Error codes

`INVALID_URL` · `UNSUPPORTED_PROTOCOL` · `SSRF_BLOCKED` · `DNS_FAILED` ·
`TIMEOUT` · `ABORTED` · `NETWORK_ERROR` · `TOO_MANY_REDIRECTS` ·
`HISTORY_NOT_FOUND` · `INVALID_RULE` · `INVALID_BODY`

### CLI exit codes

The CLI maps results and failures onto a small, stable set of process exit
codes, so it can be composed in scripts:

- `0` — the exchange completed (any HTTP status, including 4xx/5xx, is a
  completed exchange).
- `2` — usage error: bad flags, an invalid `--rule`, an `INVALID_URL`, or an
  `UNSUPPORTED_PROTOCOL`.
- `3` — the request was refused or failed: `SSRF_BLOCKED`, `DNS_FAILED`,
  `TIMEOUT`, `TOO_MANY_REDIRECTS`, `NETWORK_ERROR`, or the HAR file could not
  be written.

---

## History

A per-session ring buffer (capacity `history.maxEntries`) records every
`http_request`: its request snapshot, response (already capped), timing, size,
and any error. `http_history` lists/get/clears entries; `http_request` replays
one via `history_id` and records a brand-new attempt — including a fresh SSRF
check on every hop.

---

## CLI

A zero-dependency CLI front-end for the same engine, with the same SSRF
protection:

```sh
npm link   # or: node lib/cli.js …  or: npx tsx src/cli.ts …

dsh-http-debug <url> [options]
  -X, --method <m>          HTTP method
  -H, --header <n:v>        header (repeatable; also accepts n=v)
  -d, --data <body>         UTF-8 body
      --data-base64 <b64>   base64 body
      --data-file <path>    body from a text file
      --data-binary <path>  body from a file, verbatim
      --timeout <ms>        timeout in ms (0 = no timeout; default 30000)
  -F/--follow | -N/--no-follow
      --max-redirects <n>   --max-body-bytes <n>
      --validate-json       --har <file>
      --json                print the full structured result as JSON (default)
      --raw                 print only the body
      --allow-private       bypass SSRF for this request (unsafe)
      --rule <rule>         add a runtime whitelist rule (repeatable)
      --no-waf
      --ssrf-enabled        enable SSRF blocking (default)
      --ssrf-disabled       disable all SSRF protection (unsafe)
      --config-file <path>  JSON config file (flags override it)
  -v, --version             print the version
  -h, --help                print this help
```

All flags map onto the same `HttpDebug` service the tools use.

---

## Programmatic API

The core is dependency-free and exported for embedding elsewhere:

```ts
import { HttpDebug } from 'dsh-http-debug';

const http = new HttpDebug({
  config: { ssrf: { whitelist: ['127.0.0.1'] } },
});

const response = await http.request({ url: 'http://127.0.0.1:3000/', validateJson: true });
console.log(response.status, response.body, response.historyId);

http.rulesAdd('10.0.0.0/8');      // runtime whitelist
await http.request({ historyId: 'h1' }); // replay
```

Exports: `HttpDebug`, `HttpClient`, `SsrfGuard`, `HistoryStore`, `RuleStore`,
`buildHarLog`, the config/response types, and `HttpDebugError` (with `code`).

---

## Examples

- `examples/usage.mjs` — calling the core from a plain Node script.
- `examples/dsh-integration.mjs` — mounts the bundle into a real Cordis
  `Context` + `ToolRegistry` and runs `http_request` through the real pipeline.
- `examples/generate-examples.mjs` — spins up a local server and writes
  `examples/response.example.json` and `examples/har.example.har`.
- `examples/response.example.json`, `examples/har.example.har` — generated
  sample artifacts.

Generate them yourself with:

```sh
npm run build
npm run generate-examples
```

---

## Development

```sh
npm install       # dev deps: typescript, tsx, @types/node + dsh peer types
npm run build     # tsc -> lib/ (ESM, .d.ts)
npm run typecheck
npm test          # builds first, then `node --test` on the compiled lib
npm run cli -- <url> …   # run the CLI from source via tsx
```

The test runner needs Node ≥ 23.6 (or the 22.18 LTS release), where native
TypeScript type stripping is enabled by default so `node --test` can run the
test files directly. The **shipped runtime** (the compiled `lib/`) runs on
Node 18+.

Tests cover: IPv4/IPv6 classification across every category family, the SSRF
guard (literals, DNS-resolved hosts, IPv4-mapped/compatible addresses, compact
numeric hosts, redirect hops, whitelist/toggles/bypass, DNS failures), redirect
chasing and method downgrades, body truncation, base64 binary bodies, timeouts,
network errors, JSON validation, HAR structure, history ring-buffer eviction
and replay, the tool definitions, and the plugin entry.

Compatibility: Node ≥ 18 (uses the built-in `fetch`). The only runtime
dependencies are the dsh peer packages (`@deepseek-ai/cordis`,
`@deepseek-ai/dsh-tools`) provided by the host at load time.

---

## License

[MIT](LICENSE) — © 2026 dsh-http-debug contributors.
