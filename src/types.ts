/**
 * Shared types for dsh-http-debug.
 */

/** Error codes thrown by the HTTP debugging core. */
export type HttpDebugErrorCode =
  | 'INVALID_URL'
  | 'UNSUPPORTED_PROTOCOL'
  | 'SSRF_BLOCKED'
  | 'DNS_FAILED'
  | 'TIMEOUT'
  | 'ABORTED'
  | 'NETWORK_ERROR'
  | 'TOO_MANY_REDIRECTS'
  | 'HISTORY_NOT_FOUND'
  | 'INVALID_RULE'
  | 'INVALID_BODY';

/** Structured error used across the core, the tools, and the CLI. */
export class HttpDebugError extends Error {
  readonly code: HttpDebugErrorCode;
  readonly details: Record<string, unknown>;

  constructor(code: HttpDebugErrorCode, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'HttpDebugError';
    this.code = code;
    this.details = details;
  }
}

/* ---------------------------------------------------------------------- */
/* Configuration                                                           */
/* ---------------------------------------------------------------------- */

/**
 * SSRF / network-safety switches.
 *
 * Every category is a separate toggle; all four default to `true`, so the
 * safest configuration is also the default ("secure by default").
 *
 * Categories and their owning toggles:
 *   - {@link SsrfConfig.blockLoopback}: 127.0.0.0/8, ::1
 *   - {@link SsrfConfig.blockPrivate}:  10/8, 172.16/12, 192.168/16,
 *     100.64/10 (CGNAT), ULA fc00::/7 (and matches embedded in IPv4-mapped)
 *   - {@link SsrfConfig.blockLinkLocal}: 169.254/16, fe80::/10
 *   - {@link SsrfConfig.blockReserved}:  everything else special (0/8,
 *     documentation TEST-NET ranges, multicast, broadcast, 198.18/15,
 *     benchmarking, NAT64/6to4 prefixes, IPv6 documentation/multicast, ...)
 */
export interface SsrfConfig {
  /** Master switch. When false, all IP checks and DNS checks are skipped. */
  enabled: boolean;
  /** Block RFC 1918 / private networks (IPv4 + Unique Local IPv6). */
  blockPrivate: boolean;
  /** Block the loopback addresses. */
  blockLoopback: boolean;
  /** Block link-local addresses. */
  blockLinkLocal: boolean;
  /** Block every other reserved / special-use address. */
  blockReserved: boolean;
  /**
   * Addresses that are always permitted. Each entry may be:
   *   - an exact hostname           -> `api.example.com`
   *   - a wildcard hostname         -> `*.example.com` (matches the apex and
   *     every sub-domain)
   *   - an IP literal               -> `127.0.0.1`, `::1`
   *   - a CIDR range                -> `10.42.0.0/16`, `fd00::/8`
   *
   * A whitelisted target escapes the IP/DNS classification for that hop.
   */
  whitelist: string[];
}

/** Client-side behaviour that is local to this plugin. */
export interface ClientConfig {
  /** Per-request timeout in milliseconds. */
  timeoutMs: number;
  /** Maximum redirect hops followed before failing. */
  maxRedirects: number;
  /**
   * Hard cap on how many body bytes are captured (and therefore stored in the
   * session history). Responses larger than this are truncated. This is the
   * primary guard against blowing up the prompt / session context.
   */
  maxBodyBytes: number;
  /**
   * When true and no `User-Agent` / `Referer` header is supplied by the
   * caller, a reasonable default is added (WAF-friendly).
   */
  wafHeaders: boolean;
  /** Default `User-Agent` used when {@link ClientConfig.wafHeaders} is on. */
  userAgent: string;
  /**
   * Default `Referer` used when {@link ClientConfig.wafHeaders} is on and no
   * `Referer` is supplied. Empty string disables the default Referer.
   */
  referer: string;
}

/** Per-session request/response history settings. */
export interface HistoryConfig {
  /** Ring-buffer capacity: how many exchanges are kept in memory at most. */
  maxEntries: number;
}

/** Response inspection settings. */
export interface HarConfig {
  /** Include a HAR 1.2 document in every response by default. */
  enabled: boolean;
}

/** The full, user-facing configuration object (all fields optional). */
export interface HttpDebugConfig {
  ssrf: Partial<SsrfConfig>;
  client: Partial<ClientConfig>;
  history: Partial<HistoryConfig>;
  har: Partial<HarConfig>;
}

/** The fully-merged, runtime-normalized configuration. */
export interface NormalizedConfig {
  ssrf: SsrfConfig;
  client: ClientConfig;
  history: HistoryConfig;
  har: HarConfig;
}

export const DEFAULT_CONFIG: NormalizedConfig = {
  ssrf: {
    enabled: true,
    blockPrivate: true,
    blockLoopback: true,
    blockLinkLocal: true,
    blockReserved: true,
    whitelist: [],
  },
  client: {
    timeoutMs: 30_000,
    maxRedirects: 10,
    maxBodyBytes: 128 * 1024,
    wafHeaders: true,
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    referer: '',
  },
  history: {
    maxEntries: 200,
  },
  har: {
    enabled: false,
  },
};

/** Normalize a partial configuration over the defaults. */
export function normalizeConfig(partial: HttpDebugConfig | Partial<HttpDebugConfig> | undefined): NormalizedConfig {
  const cfg: Partial<HttpDebugConfig> = partial ?? {};
  const base = DEFAULT_CONFIG;
  return {
    ssrf: {
      ...base.ssrf,
      ...cfg.ssrf,
      whitelist: cfg.ssrf?.whitelist ?? base.ssrf.whitelist,
    },
    client: {
      ...base.client,
      ...cfg.client,
    },
    history: {
      ...base.history,
      ...cfg.history,
    },
    har: {
      ...base.har,
      ...cfg.har,
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Requests                                                                */
/* ---------------------------------------------------------------------- */

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Body payload accepted by the client. `string` is UTF-8 text. */
export type RequestBody = string | Uint8Array;

export interface RequestOptions {
  /** Target URL. Required unless `historyId` replays a stored request. */
  url: string;
  /** HTTP method; defaults to GET. */
  method?: HttpMethod;
  /** Extra headers (lower-cased by the client before sending). */
  headers?: Record<string, string>;
  /** Request body: UTF-8 text string or raw bytes. */
  body?: RequestBody;
  /** Per-request timeout override. */
  timeoutMs?: number;
  /** Follow 3xx redirects (default: true). */
  followRedirects?: boolean;
  /** Per-request redirect cap override. */
  maxRedirects?: number;
  /** Per-request body cap override. */
  maxBodyBytes?: number;
  /** Validate a JSON-looking text body. */
  validateJson?: boolean;
  /** Attach a HAR 1.2 document for this exchange. */
  includeHar?: boolean;
  /** Explicitly bypass SSRF protection for this one request (unsafe). */
  bypassSsfr?: boolean;
  /** Override {@link ClientConfig.wafHeaders} for this request. */
  wafHeaders?: boolean;
  /** External cancellation signal (e.g. the dsh tool `exec.signal`). */
  signal?: AbortSignal;
}

/* ---------------------------------------------------------------------- */
/* Responses                                                               */
/* ---------------------------------------------------------------------- */

/** One hop actually followed during a redirect chain. */
export interface RedirectHop {
  /** Status that triggered the hop (301/302/303/307/308). */
  status: number;
  /** The URL the hop left from. */
  from: string;
  /** The URL the hop resolved to. */
  to: string;
}

/** Result of the optional JSON validation of a text body. */
export interface JsonCheck {
  valid: boolean;
  /** Parse error message when `valid` is false. */
  error?: string;
}

/**
 * The structured outcome of one HTTP exchange. This is the canonical value the
 * `http_request` tool returns; it is always JSON-serializable.
 */
export interface HttpResponse {
  /** `true` when the final status is 2xx; `false` for any other final status. */
  ok: boolean;
  /** Final status code after redirects. */
  status: number;
  /** Reason phrase returned by the server. */
  statusText: string;
  /** HTTP version of the final response. */
  httpVersion: string;
  /** Method actually issued to produce the final response. */
  method: string;
  /** Final URL after the redirect chain (or the original URL). */
  url: string;
  /** Final response headers, lower-cased, multi-values joined with `, `. */
  headers: Record<string, string>;
  /** Content-Type of the final response (may be empty). */
  contentType: string;
  /**
   * Body as UTF-8 text (for textual payloads) or Base64 (for binary). May be
   * truncated per {@link ClientConfig.maxBodyBytes}.
   */
  body: string;
  /** How `body` is encoded. */
  bodyEncoding: 'utf8' | 'base64' | 'none';
  /** Number of body bytes captured after any cap. */
  bodySizeBytes: number;
  /** Whether the body was truncated at {@link ClientConfig.maxBodyBytes}. */
  bodyTruncated: boolean;
  /** Total wall time of the exchange in milliseconds. */
  durationMs: number;
  /** Whether at least one redirect was followed. */
  redirected: boolean;
  /** Every redirect hop followed, in order. */
  redirects: RedirectHop[];
  /** JSON validation result, when requested. */
  json?: JsonCheck;
  /** HAR 1.2 log for this exchange, when requested. */
  har?: unknown;
  /** History id this exchange was recorded under. */
  historyId: string;
}

/* ---------------------------------------------------------------------- */
/* History                                                                 */
/* ---------------------------------------------------------------------- */

/** Minimal reproducible request snapshot stored in history. */
export interface HistoryRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  /** Whether a body was sent. */
  hasBody: boolean;
  /** Request body text (must be re-encoded when `bodyEncoding` is base64). */
  body?: string;
  bodyEncoding: 'text' | 'base64';
  /** Request body size in bytes. */
  bodySizeBytes: number;
}

/** Response snapshot stored in history. */
export interface HistoryResponse {
  status?: number;
  statusText?: string;
  headers: Record<string, string>;
  /** Response body (already capped/truncated). */
  body?: string;
  bodyEncoding: 'utf8' | 'base64' | 'none';
  bodySizeBytes: number;
  bodyTruncated: boolean;
  contentType?: string;
  redirects: RedirectHop[];
  json?: JsonCheck;
}

export type HistoryOutcome = 'ok' | 'error';

/** One recorded exchange (a request plus its outcome). */
export interface HistoryEntry {
  /** Monotonic id assigned by the history store (e.g. `h42`). */
  id: string;
  /** ISO-8601 timestamp when the exchange started. */
  startedAt: string;
  /** Wall time of the exchange in milliseconds. */
  durationMs: number;
  outcome: HistoryOutcome;
  request: HistoryRequest;
  /** Present when `outcome` is `'ok'`. */
  response?: HistoryResponse;
  /** Present when `outcome` is `'error'`. */
  error?: { code: string; message: string };
  /** Approximate recorded bytes (request body + captured response body). */
  recordedBytes: number;
}

/** Lightweight view used by `http_history list`. */
export interface HistorySummary {
  id: string;
  startedAt: string;
  method: string;
  url: string;
  status?: number;
  outcome: HistoryOutcome;
  errorCode?: string;
  durationMs: number;
  bodySizeBytes: number;
  recordedBytes: number;
}

/* ---------------------------------------------------------------------- */
/* SSRF                                                                    */
/* ---------------------------------------------------------------------- */

/**
 * Decide whether a response body should be rendered as UTF-8 text (vs Base64),
 * based on its Content-Type. Untyped bodies are decided by sniffing in
 * {@link http.ts}.
 */
export function isTextualContentType(contentType: string): boolean {
  const primary = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  if (!primary) return false;
  if (primary.startsWith('text/')) return true;
  if (
    primary.endsWith('+json') ||
    primary.endsWith('+xml') ||
    primary.endsWith('+javascript') ||
    primary === 'application/json' ||
    primary === 'application/xml' ||
    primary === 'application/javascript' ||
    primary === 'application/x-www-form-urlencoded' ||
    primary === 'application/xhtml+xml' ||
    primary === 'application/atom+xml' ||
    primary === 'application/rss+xml' ||
    primary === 'application/manifest+json' ||
    primary === 'application/problem+json' ||
    primary === 'application/vnd.api+json' ||
    primary === 'image/svg+xml'
  ) {
    return true;
  }
  return false;
}
