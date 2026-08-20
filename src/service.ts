/**
 * {@link HttpDebug} -- the orchestrating service that wires the SSRF guard,
 * the HTTP client, the session history, and the runtime rule store together,
 * and exposes the entry points the tools and the CLI share.
 */
import { Buffer } from 'node:buffer';
import { HttpClient } from './http.js';
import { HistoryStore, type HistoryStats } from './history.js';
import { RuleStore } from './rule-store.js';
import { SsrfGuard, type HostResolver } from './ssrf.js';
import {
  HttpDebugError,
  HTTP_METHODS,
  normalizeConfig,
  type HistoryEntry,
  type HttpResponse,
  type HttpDebugConfig,
  type NormalizedConfig,
  type RequestOptions,
} from './types.js';

/**
 * The raw tool-facing request description (mirrors the `http_request` schema
 * argument shape before it is normalized into {@link RequestOptions}).
 */
export interface ToolRequestInput {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  /** UTF-8 text body. Mutually exclusive with `body_base64`. */
  body?: string;
  /** Base64-encoded binary body. Mutually exclusive with `body`. */
  bodyBase64?: string;
  timeoutMs?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  maxBodyBytes?: number;
  validateJson?: boolean;
  includeHar?: boolean;
  bypassSsfr?: boolean;
  wafHeaders?: boolean;
  /** When set, replays the stored request instead of using the other fields. */
  historyId?: string;
  /** External cancellation signal (the dsh tool execution signal). */
  signal?: AbortSignal;
}

/** Runtime rule view returned by the `http_rules` tool. */
export interface RulesView {
  base: string[];
  runtime: string[];
  effective: string[];
}

export interface HttpDebugInit {
  config?: HttpDebugConfig | Partial<HttpDebugConfig>;
  /** Override the DNS resolver (used by tests and by advanced deployments). */
  resolver?: HostResolver;
}

export class HttpDebug {
  readonly config: NormalizedConfig;
  readonly guard: SsrfGuard;
  readonly client: HttpClient;
  readonly history: HistoryStore;
  readonly rules: RuleStore;
  private counter = 0;

  constructor(init: HttpDebugInit = {}) {
    this.config = normalizeConfig(init.config);
    this.rules = new RuleStore(this.config.ssrf.whitelist);
    this.guard = new SsrfGuard({ config: this.config.ssrf, whitelist: this.rules, resolver: init.resolver });
    this.client = new HttpClient({
      guard: this.guard,
      config: this.config.client,
      defaultIncludeHar: this.config.har.enabled,
    });
    this.history = new HistoryStore(this.config.history.maxEntries);
  }

  /** Run one exchange (or replay one from history) and record it. */
  async request(input: ToolRequestInput): Promise<HttpResponse> {
    if (input.historyId) {
      const stored = this.history.get(input.historyId);
      if (!stored) {
        throw new HttpDebugError('HISTORY_NOT_FOUND', `No history entry with id "${input.historyId}"`, { id: input.historyId });
      }
      // Rebuild the stored request, allowing only timing/cap overrides.
      const replay: RequestOptions & { signal?: AbortSignal } = {
        url: stored.request.url,
        method: stored.request.method.toUpperCase() as RequestOptions['method'],
        headers: stored.request.headers,
        body: decodeRequestBody(stored.request.bodyEncoding, stored.request.body),
        signal: input.signal,
      };
      if (input.timeoutMs !== undefined) replay.timeoutMs = input.timeoutMs;
      if (input.maxBodyBytes !== undefined) replay.maxBodyBytes = input.maxBodyBytes;
      if (input.followRedirects !== undefined) replay.followRedirects = input.followRedirects;
      if (input.maxRedirects !== undefined) replay.maxRedirects = input.maxRedirects;
      if (input.bypassSsfr !== undefined) replay.bypassSsfr = input.bypassSsfr;
      return this.runAndRecord(replay, input.validateJson, input.includeHar);
    }
    return this.runAndRecord(this.normalizeRequestInput(input), input.validateJson, input.includeHar);
  }

  /** Turn a tool-style input into client options. */
  normalizeRequestInput(input: ToolRequestInput): RequestOptions {
    if (!input.url) throw new HttpDebugError('INVALID_URL', 'A URL is required (or pass history_id to replay a stored request)');
    const method = (input.method ?? 'GET').toUpperCase();
    if (!HTTP_METHODS.includes(method as (typeof HTTP_METHODS)[number])) {
      throw new HttpDebugError('INVALID_URL', `Unsupported HTTP method "${input.method}"`, { method });
    }
    if (input.body !== undefined && input.bodyBase64 !== undefined) {
      throw new HttpDebugError('INVALID_BODY', 'Pass either `body` or `body_base64`, not both');
    }
    let body: RequestOptions['body'];
    if (input.bodyBase64 !== undefined) {
      if (!isStrictBase64(input.bodyBase64)) {
        throw new HttpDebugError('INVALID_BODY', '`body_base64` is not valid base64');
      }
      body = Buffer.from(input.bodyBase64, 'base64');
    } else if (input.body !== undefined) {
      body = input.body;
    }
    return {
      url: input.url,
      method: method as RequestOptions['method'],
      headers: input.headers,
      body,
      timeoutMs: input.timeoutMs,
      followRedirects: input.followRedirects,
      maxRedirects: input.maxRedirects,
      maxBodyBytes: input.maxBodyBytes,
      validateJson: input.validateJson,
      includeHar: input.includeHar,
      bypassSsfr: input.bypassSsfr,
      wafHeaders: input.wafHeaders,
      signal: input.signal,
    };
  }

  private async runAndRecord(
    options: RequestOptions & { validateJson?: boolean; includeHar?: boolean },
    validateJsonDefault?: boolean,
    includeHarDefault?: boolean,
  ): Promise<HttpResponse> {
    const id = `h${++this.counter}`;
    const startedAt = new Date();
    const initialMethod = (options.method ?? 'GET').toUpperCase();
    try {
      const result = await this.client.request({
        ...options,
        validateJson: options.validateJson ?? validateJsonDefault,
        includeHar: options.includeHar ?? includeHarDefault,
      });
      const now = Date.now();
      this.history.push({
        id,
        startedAt: startedAt.toISOString(),
        durationMs: result.durationMs,
        outcome: 'ok',
        request: {
          method: initialMethod,
          url: options.url ?? result.url,
          headers: options.headers ?? {},
          hasBody: options.body !== undefined,
          body: requestBodyText(options.body),
          bodyEncoding: requestBodyEncoding(options.body),
          bodySizeBytes: requestBodyBytes(options.body),
        },
        response: {
          status: result.status,
          statusText: result.statusText,
          headers: result.headers,
          body: result.body,
          bodyEncoding: result.bodyEncoding,
          bodySizeBytes: result.bodySizeBytes,
          bodyTruncated: result.bodyTruncated,
          contentType: result.contentType,
          redirects: result.redirects,
          json: result.json,
        },
        recordedBytes: requestBodyBytes(options.body) + result.bodySizeBytes,
      });
      result.historyId = id;
      return result;
    } catch (error) {
      const code = error instanceof HttpDebugError ? error.code : 'NETWORK_ERROR';
      const message = error instanceof Error ? error.message : String(error);
      this.history.push({
        id,
        startedAt: startedAt.toISOString(),
        durationMs: Date.now() - startedAt.getTime(),
        outcome: 'error',
        request: {
          method: initialMethod,
          url: options.url ?? '',
          headers: options.headers ?? {},
          hasBody: options.body !== undefined,
          body: requestBodyText(options.body),
          bodyEncoding: requestBodyEncoding(options.body),
          bodySizeBytes: requestBodyBytes(options.body),
        },
        error: { code, message },
        recordedBytes: requestBodyBytes(options.body),
      });
      throw error;
    }
  }

  historyList(): ReturnType<HistoryStore['list']> {
    return this.history.list();
  }

  historyGet(id: string): HistoryEntry | undefined {
    return this.history.get(id);
  }

  historyClear(): number {
    return this.history.clear();
  }

  historyStats(): HistoryStats {
    return this.history.stats();
  }

  rulesView(): RulesView {
    return {
      base: [...this.config.ssrf.whitelist],
      runtime: this.rules.runtimeRules(),
      effective: this.rules.list(),
    };
  }

  rulesAdd(rule: string): { ok: boolean; rule?: string; error?: string } {
    return this.rules.add(rule);
  }

  rulesRemove(rule: string): boolean {
    return this.rules.remove(rule);
  }

  rulesClear(): number {
    return this.rules.clear();
  }
}

function requestBodyText(body: RequestOptions['body']): string | undefined {
  if (body === undefined) return undefined;
  if (typeof body === 'string') return body;
  return Buffer.from(body).toString('base64');
}

/** Strict base64 check: canonical alphabet, 4-character alignment, correct padding. */
function isStrictBase64(value: string): boolean {
  if (value.length % 4 !== 0) return false;
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

function requestBodyEncoding(body: RequestOptions['body']): 'text' | 'base64' {
  return typeof body === 'string' ? 'text' : 'base64';
}

function requestBodyBytes(body: RequestOptions['body']): number {
  if (body === undefined) return 0;
  if (typeof body === 'string') return Buffer.byteLength(body, 'utf8');
  return body.byteLength;
}

function decodeRequestBody(encoding: 'text' | 'base64', body: string | undefined): RequestOptions['body'] {
  if (body === undefined) return undefined;
  if (encoding === 'base64') return Buffer.from(body, 'base64');
  return body;
}
