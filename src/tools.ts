/**
 * The model-facing tools this plugin registers on `ctx.tools`:
 *   - `http_request`  perform or replay an HTTP exchange,
 *   - `http_history`  list / inspect / clear the session request history,
 *   - `http_rules`    inspect / edit the effective SSRF whitelist.
 *
 * Each is a thin adapter over {@link HttpDebug}; all policy (SSRF, caps,
 * history) lives in the core.
 */
import { defineTool } from '@deepseek-ai/dsh-tools';
import type { JsonValue } from '@deepseek-ai/dsh-tools';
import { HttpDebugError, type HttpResponse } from './types.js';
import { HttpDebug } from './service.js';

const RESPONSE_SCHEMA = { type: 'object', additionalProperties: true } as const;

// http_history returns an array for `list` and an object otherwise.
const HISTORY_SCHEMA = {
  oneOf: [
    { type: 'array', items: { type: 'object', additionalProperties: true } },
    { type: 'object', additionalProperties: true },
  ],
} as const;

export function defineHttpRequestTool(service: HttpDebug) {
  return defineTool({
    name: 'http_request',
    description:
      'Perform a raw HTTP request with full control over method, headers, body, timeout, and redirects. ' +
      'Returns the structured response (status, reason, headers, body, timing, size). ' +
      'Protected against SSRF by default: private/loopback/link-local/reserved addresses and hosts that ' +
      'resolve to them are refused unless whitelisted or bypassed. Every response is recorded in the ' +
      'session history; pass an id from http_history to replay a previous request.',
    parameters: {
      url: { type: 'string', description: 'Absolute http(s) URL to request (omit when replaying via history_id).' },
      history_id: {
        type: 'string',
        description: 'Replay a previous request. When set, url/method/headers/body are ignored.',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
        description: 'HTTP method (default GET).',
      },
      headers: {
        type: 'object',
        additionalProperties: true,
        description: 'Request headers as a name/value map.',
      },
      body: { type: 'string', description: 'UTF-8 request body (mutually exclusive with body_base64).' },
      body_base64: {
        type: 'string',
        description: 'Base64-encoded binary request body (mutually exclusive with body).',
      },
      timeout_ms: { type: 'number', description: 'Per-request timeout in milliseconds (default from config, 30000).' },
      follow_redirects: {
        type: 'boolean',
        description: 'Follow 3xx redirects (default true). Each hop is SSRF-checked.',
      },
      max_redirects: { type: 'number', description: 'Redirect cap (default from config, 10).' },
      max_body_bytes: { type: 'number', description: 'Cap on captured body bytes (default from config, 128 KiB).' },
      validate_json: {
        type: 'boolean',
        description: 'Validate a JSON body and report validity (default false).',
      },
      include_har: {
        type: 'boolean',
        description: 'Attach a HAR 1.2 document for this exchange to the result.',
      },
      bypass_ssrf: {
        type: 'boolean',
        description:
          'DANGER: bypass SSRF guard for this one request. Only use for trusted/known hosts; ' +
          'it disables private-network, loopback, and reserved-address blocking.',
      },
      waf_headers: {
        type: 'boolean',
        description: 'Add a default User-Agent (and optional Referer) when absent (default true).',
      },
    },
    output: {
      schema: RESPONSE_SCHEMA,
      render: (args, value) => [
        { type: 'text', text: renderHttpRequest(args as Record<string, unknown>, value as unknown as HttpResponse) },
      ],
      presentationMeta: (args, value) => presentationMetaOf(value as unknown as HttpResponse),
    },
    execute: async (args, exec) => {
      const result = await service.request({
        url: args.url,
        historyId: args.history_id,
        method: args.method,
        headers: stringifyHeaders(args.headers),
        body: args.body,
        bodyBase64: args.body_base64,
        timeoutMs: args.timeout_ms,
        followRedirects: args.follow_redirects,
        maxRedirects: args.max_redirects,
        maxBodyBytes: args.max_body_bytes,
        validateJson: args.validate_json,
        includeHar: args.include_har,
        bypassSsfr: args.bypass_ssrf,
        wafHeaders: args.waf_headers,
        signal: exec.signal,
      });
      return result as never;
    },
  });
}

export function defineHttpHistoryTool(service: HttpDebug) {
  return defineTool({
    name: 'http_history',
    description:
      'Inspect the in-memory session request history. Every http_request call is recorded with its ' +
      'request/response, timing, size, and any error. Use get to fetch a full entry (including the body) ' +
      'or clear to reset the ring buffer.',
    parameters: {
      action: {
        type: 'string',
        required: true,
        enum: ['list', 'get', 'clear', 'stats'],
        description: 'list: newest-first summaries; get: full entry by id; clear: empty the history; stats: counts.',
      },
      id: { type: 'string', description: 'History entry id (required when action is get).' },
    },
    output: {
      schema: HISTORY_SCHEMA,
      render: (args, value) => [{ type: 'text', text: renderHistory(args as Record<string, unknown>, value as Record<string, unknown>) }],
    },
    execute: async (args) => {
      switch (args.action) {
        case 'list':
          return service.historyList() as never;
        case 'get': {
          if (!args.id) throw new Error('http_history get requires an id');
          const entry = service.historyGet(args.id);
          if (!entry) throw new Error(`no history entry with id "${args.id}"`);
          return { found: true, entry } as never;
        }
        case 'clear':
          return { cleared: service.historyClear() } as never;
        case 'stats':
          return service.historyStats() as never;
        default:
          throw new Error(`unknown action "${String(args.action)}"`);
      }
    },
  });
}

export function defineHttpRulesTool(service: HttpDebug) {
  return defineTool({
    name: 'http_rules',
    description:
      'Inspect or edit the effective SSRF whitelist for this session. Rules may be hostnames, *.wildcards, ' +
      'IP literals, or CIDRs. Runtime rules only last for this session; set ssrf.whitelist in the plugin ' +
      'config for a durable whitelist.',
    parameters: {
      action: {
        type: 'string',
        required: true,
        enum: ['list', 'add', 'remove', 'clear'],
        description: 'list: show base/runtime/effective rules; add/remove/clear: edit the runtime rules.',
      },
      rule: { type: 'string', description: 'Rule to add or remove (hostname, *.wildcard, IP, or CIDR).' },
    },
    output: {
      schema: RESPONSE_SCHEMA,
      render: (args, value) => [{ type: 'text', text: renderRules(args as Record<string, unknown>, value as Record<string, unknown>) }],
    },
    execute: async (args) => {
      switch (args.action) {
        case 'list':
          return service.rulesView() as never;
        case 'add': {
          if (!args.rule) throw new Error('http_rules add requires a rule');
          const outcome = service.rulesAdd(args.rule);
          if (!outcome.ok) {
            throw new HttpDebugError('INVALID_RULE', `cannot add rule "${args.rule}": ${outcome.error}`, { rule: args.rule });
          }
          return { added: outcome.rule, ...service.rulesView() } as never;
        }
        case 'remove': {
          if (!args.rule) throw new Error('http_rules remove requires a rule');
          const removed = service.rulesRemove(args.rule);
          return { removed, rule: args.rule, ...service.rulesView() } as never;
        }
        case 'clear':
          return { cleared: service.rulesClear(), ...service.rulesView() } as never;
        default:
          throw new Error(`unknown action "${String(args.action)}"`);
      }
    },
  });
}

export function defineHttpDebugTools(service: HttpDebug) {
  return [defineHttpRequestTool(service), defineHttpHistoryTool(service), defineHttpRulesTool(service)];
}

/* ------------------------------------------------------------------ */
/* render helpers (pure model-facing prose)                            */
/* ------------------------------------------------------------------ */

function stringifyHeaders(headers: Record<string, unknown> | undefined): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || value === null) continue;
    out[key] = String(value);
  }
  return out;
}

const PREVIEW_CHARS = 2000;

function renderHttpRequest(args: Record<string, unknown>, value: HttpResponse): string {
  const lines: string[] = [];
  const status = `${value.status} ${value.statusText}`.trim();
  lines.push(`[${value.method}] ${value.url}`);
  lines.push(`Status: ${status} (${value.ok ? '2xx' : 'http error'}) in ${value.durationMs} ms`);
  lines.push(`Encoding: ${value.bodyEncoding} | Captured: ${value.bodySizeBytes} bytes${value.bodyTruncated ? ' (TRUNCATED)' : ''}`);
  if (value.redirected) lines.push(`Redirects (${value.redirects.length}): ${value.redirects.map((hop) => `${hop.from} -> ${hop.to}`).join(' ; ')}`);
  if (value.json) lines.push(`JSON: ${value.json.valid ? 'valid' : `INVALID (${value.json.error})`}`);
  if (value.har) lines.push('HAR: attached (see result.har)');
  const body = previewBody(value);
  if (body) {
    lines.push('Body:');
    lines.push(body);
  } else {
    lines.push('Body: (empty)');
  }
  void args;
  return lines.join('\n');
}

function previewBody(value: HttpResponse): string {
  if (!value.body) return '';
  if (value.bodyEncoding === 'base64') {
    const shown = value.body.length > PREVIEW_CHARS ? `${value.body.slice(0, PREVIEW_CHARS)}... [truncated preview]` : value.body;
    return `[base64] ${shown}`;
  }
  return value.body.length > PREVIEW_CHARS ? `${value.body.slice(0, PREVIEW_CHARS)}... [truncated preview]` : value.body;
}

/** Durable replay metadata for UI cards (no body copy). */
function presentationMetaOf(value: HttpResponse): Record<string, JsonValue> {
  return {
    ok: value.ok,
    status: value.status,
    statusText: value.statusText,
    method: value.method,
    url: value.url,
    durationMs: value.durationMs,
    bodySizeBytes: value.bodySizeBytes,
    bodyTruncated: value.bodyTruncated,
    redirected: value.redirected,
    historyId: value.historyId,
  };
}

function renderHistory(args: Record<string, unknown>, value: Record<string, unknown>): string {
  void args;
  const summary = (items: unknown[]) =>
    items
      .map((item) => {
        const row = item as {
          id?: unknown;
          method?: unknown;
          url?: unknown;
          status?: unknown;
          outcome?: unknown;
          durationMs?: unknown;
          bodySizeBytes?: unknown;
          errorCode?: unknown;
        };
        const status = row.status === undefined ? '' : ` -> ${String(row.status)}`;
        const error = row.errorCode ? ` [err:${String(row.errorCode)}]` : '';
        return `${String(row.id)} ${String(row.method)} ${String(row.url)}${status} ${String(row.durationMs)}ms (${String(row.bodySizeBytes)}B)${error}`;
      })
      .join('\n');
  if (Array.isArray(value)) return summary(value);
  return JSON.stringify(value, null, 2);
}

function renderRules(args: Record<string, unknown>, value: Record<string, unknown>): string {
  void args;
  return JSON.stringify(value, null, 2);
}
