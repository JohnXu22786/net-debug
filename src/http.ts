/**
 * The HTTP client core.
 *
 * A {@link HttpClient} runs one exchange with:
 *   - an SSRF check before the request AND before every redirect hop
 *     (the guard is applied to each resolved Location),
 *   - a wall-clock timeout,
 *   - a hard cap on captured body bytes,
 *   - text (UTF-8) / Base64 body selection,
 *   - optional JSON validation,
 *   - optional HAR 1.2 capture.
 */
import { performance } from 'node:perf_hooks';
import {
  HttpDebugError,
  isTextualContentType,
  type ClientConfig,
  type HttpMethod,
  type HttpResponse,
  type JsonCheck,
  type RedirectHop,
  type RequestBody,
  type RequestOptions,
} from './types.js';
import { SsrfGuard } from './ssrf.js';
import { buildHarLog, type HarLog } from './har.js';

/** A 3xx status that fetch's default redirect would normally follow. */
export function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/** RFC 7231-ish method transition across a redirect hop. */
function redirectMethod(method: HttpMethod, status: number): HttpMethod {
  if (status === 303) return 'GET';
  if ((status === 301 || status === 302) && method === 'POST') return 'GET';
  return method;
}

/** Content headers dropped when a redirect switches the method to GET. */
const CONTENT_HEADERS = new Set([
  'content-type',
  'content-length',
  'content-encoding',
  'content-language',
  'content-md5',
  'transfer-encoding',
]);

function dropContentHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!CONTENT_HEADERS.has(key.toLowerCase())) out[key] = value;
  }
  return out;
}

/** Trim a buffer so it ends on a complete UTF-8 sequence (no lone continuation). */
export function trimToValidUtf8(buffer: Buffer): Buffer {
  let end = buffer.length;
  // Walk back while the previous byte is a continuation byte (0b10xxxxxx).
  while (end > 0 && (buffer[end - 1]! & 0xc0) === 0x80) end -= 1;
  if (end === 0) return Buffer.alloc(0);
  const lead = buffer[end - 1]!;
  const trailing = buffer.length - end; // continuation bytes present after the lead
  let expected: number;
  if (lead >= 0xc0 && lead <= 0xdf) expected = 1;
  else if (lead >= 0xe0 && lead <= 0xef) expected = 2;
  else if (lead >= 0xf0 && lead <= 0xf7) expected = 3;
  else return buffer; // ASCII byte; nothing incomplete
  if (trailing < expected) end -= 1;
  return buffer.subarray(0, end);
}

/** Map a Content-Type charset to a Node Buffer encoding (best effort). */
function charsetEncoding(contentType: string): BufferEncoding {
  const match = contentType.match(/charset\s*=\s*["']?([a-zA-Z0-9_\-]+)/i);
  const charset = (match?.[1] ?? '').replace(/^["']|["']$/g, '').toLowerCase();
  if (!charset) return 'utf8'; // no explicit charset -> UTF-8 by default
  switch (charset) {
    case 'utf-8':
    case 'utf8':
      return 'utf8';
    case 'us-ascii':
    case 'ascii':
      return 'ascii';
    case 'latin1':
    case 'iso-8859-1':
    case 'iso8859-1':
    case 'windows-1252':
    case 'cp1252':
      return 'latin1';
    case 'utf-16le':
    case 'utf-16':
    case 'ucs-2':
    case 'ucs2':
      return 'utf16le';
    case 'base64':
      return 'base64';
    default:
      // Unknown/legacy charset: decode 1-byte-safe (latin1) rather than
      // producing mojibake through a wrong UTF-8 interpretation.
      return 'latin1';
  }
}

/** Decide whether a raw body should be surfaced as text or Base64. */
function chooseBodyEncoding(buffer: Buffer, contentType: string): 'utf8' | 'base64' {
  if (buffer.byteLength === 0) return 'utf8';
  if (contentType) {
    if (!isTextualContentType(contentType)) return 'base64';
    return charsetEncoding(contentType) === 'base64' ? 'base64' : 'utf8';
  }
  // No content type: sniff. Valid UTF-8 (after trimming) without replacement
  // chars is text; anything else is treated as binary.
  if (trimToValidUtf8(buffer).toString('utf8').includes('\uFFFD')) return 'base64';
  return 'utf8';
}

export interface HttpClientOptions {
  guard: SsrfGuard;
  config: ClientConfig;
  /** Whether HAR capture is on unless overridden per request. */
  defaultIncludeHar: boolean;
}

/**
 * Runs an HTTP exchange against the supplied config, applying the SSRF guard
 * on the initial URL and on every redirect hop.
 */
export class HttpClient {
  readonly guard: SsrfGuard;
  readonly config: ClientConfig;
  readonly defaultIncludeHar: boolean;

  constructor(options: HttpClientOptions) {
    this.guard = options.guard;
    this.config = options.config;
    this.defaultIncludeHar = options.defaultIncludeHar;
  }

  async request(opts: RequestOptions): Promise<HttpResponse> {
    if (!opts.url) {
      throw new HttpDebugError('INVALID_URL', 'A URL is required');
    }
    const timeoutMs = opts.timeoutMs ?? this.config.timeoutMs;
    const maxRedirects = opts.maxRedirects ?? this.config.maxRedirects;
    const maxBodyBytes = opts.maxBodyBytes ?? this.config.maxBodyBytes;
    const followRedirects = opts.followRedirects ?? true;
    const wafHeaders = opts.wafHeaders ?? this.config.wafHeaders;

    let method: HttpMethod = opts.method ?? 'GET';
    let body: RequestBody | undefined = opts.body;
    let headers = { ...(opts.headers ?? {}) };

    if (wafHeaders) {
      if (this.config.userAgent && !hasHeader(headers, 'user-agent')) headers['User-Agent'] = this.config.userAgent;
      if (this.config.referer && !hasHeader(headers, 'referer')) headers['Referer'] = this.config.referer;
    }

    const started = performance.now();
    const redirects: RedirectHop[] = [];
    let currentUrl = opts.url;

    let timedOut = false;
    const controller = new AbortController();
    const externalSignal = opts.signal;
    if (externalSignal?.aborted) {
      controller.abort(externalSignal.reason);
    } else if (externalSignal) {
      externalSignal.addEventListener('abort', () => controller.abort(externalSignal.reason), { once: true });
    }
    // `timeoutMs <= 0` means "no timeout".
    const timer = timeoutMs > 0
      ? setTimeout(() => {
          timedOut = true;
          controller.abort(Object.assign(new Error(`timeout after ${timeoutMs}ms`), { code: 'TIMEOUT' }));
        }, timeoutMs)
      : undefined;

    try {
      for (let hop = 0; ; hop++) {
        // SSRF check for this exact hop (the destination URL being opened).
        await this.guard.verify(currentUrl, { bypass: opts.bypassSsfr === true });

        const response = await this.fetchOnce(currentUrl, method, headers, body, controller.signal);
        const status = response.status;
        const isRedirect = isRedirectStatus(status);

        if (isRedirect && followRedirects) {
          const location = getHeader(response.headers, 'location');
          // 3xx without a Location header cannot be followed -- final response.
          if (!location) {
            return await this.settle(response, currentUrl, method, started, redirects, opts, maxBodyBytes);
          }
          if (hop >= maxRedirects) {
            throw new HttpDebugError('TOO_MANY_REDIRECTS', `Too many redirects (limit ${maxRedirects})`, {
              url: currentUrl,
              maxRedirects,
              redirects,
            });
          }
          const nextUrl = new URL(location, currentUrl).toString();
          redirects.push({ status, from: currentUrl, to: nextUrl });
          await consumeHopBody(response);
          const previousMethod = method;
          method = redirectMethod(method, status);
          // 303 always switches to GET with no body; 301/302 do too when they
          // change the method. 307/308 keep method and body.
          if (status === 303 || previousMethod !== method) {
            body = undefined;
            headers = dropContentHeaders(headers);
          }
          currentUrl = nextUrl;
          continue;
        }

        return await this.settle(response, currentUrl, method, started, redirects, opts, maxBodyBytes);
      }
    } catch (error) {
      if (timedOut) {
        throw new HttpDebugError('TIMEOUT', `Request timed out after ${timeoutMs}ms`, { url: currentUrl, timeoutMs });
      }
      if (controller.signal.aborted) {
        throw new HttpDebugError('ABORTED', 'Request aborted', { url: currentUrl });
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async fetchOnce(
    url: string,
    method: HttpMethod,
    headers: Record<string, string>,
    body: RequestBody | undefined,
    signal: AbortSignal,
  ): Promise<Response> {
    const init: RequestInit = { method, headers, redirect: 'manual', signal };
    if (body !== undefined) init.body = body;
    try {
      return await fetch(url, init);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // undici rejects bodies on GET/HEAD connections.
      if (body !== undefined && (method === 'GET' || method === 'HEAD') && /cannot have body/i.test(message)) {
        throw new HttpDebugError('INVALID_BODY', `HTTP ${method} requests cannot carry a body`, { method, url });
      }
      throw new HttpDebugError('NETWORK_ERROR', `Request failed: ${message}`, { url });
    }
  }

  /** Turn the CSS-finally response into the structured result with body capture. */
  private async settle(
    response: Response,
    url: string,
    method: HttpMethod,
    started: number,
    redirects: RedirectHop[],
    opts: RequestOptions,
    maxBodyBytes: number,
  ): Promise<HttpResponse> {
    const headers = flattenHeaders(response.headers);
    const contentType = headers['content-type'] ?? '';
    const { buf, truncated } = await readCappedBody(response, maxBodyBytes);

    const encoding = chooseBodyEncoding(buf, contentType);
    let body: string;
    let bodyEncoding: HttpResponse['bodyEncoding'];
    if (buf.byteLength === 0) {
      body = '';
      bodyEncoding = 'none';
    } else if (encoding === 'base64') {
      body = buf.toString('base64');
      bodyEncoding = 'base64';
    } else {
      const enc = charsetEncoding(contentType);
      // Only UTF-8 needs the valid-boundary trim; latin1/ascii are 1-byte-safe.
      const safe = enc === 'utf8' ? trimToValidUtf8(buf) : buf;
      body = safe.toString(enc);
      bodyEncoding = 'utf8';
    }

    let json: JsonCheck | undefined;
    if (opts.validateJson && body.length > 0 && bodyEncoding !== 'base64') {
      json = tryParseJson(body);
    }

    const durationMs = Math.round(performance.now() - started);
    const responseAny = response as unknown as { httpVersion?: unknown };
    const httpVersion =
      typeof responseAny.httpVersion === 'string' ? (responseAny.httpVersion as string) : 'HTTP/1.x';

    const result: HttpResponse = {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.statusText,
      httpVersion,
      method,
      url,
      headers,
      contentType,
      body,
      bodyEncoding,
      bodySizeBytes: buf.byteLength,
      bodyTruncated: truncated,
      durationMs,
      redirected: redirects.length > 0,
      redirects,
      historyId: '',
    };
    if (opts.validateJson) result.json = json;
    if (opts.includeHar ?? this.defaultIncludeHar) {
      result.har = buildHarLog(
        {
          method,
          url,
          headers,
        },
        {
          status: response.status,
          statusText: response.statusText,
          headers,
          contentType,
          body,
          bodyEncoding,
          bodySizeBytes: buf.byteLength,
        },
        { durationMs },
      );
    }
    return result;
  }
}

/** Read a body, keeping at most `maxBytes`, recording truncation. */
export async function readCappedBody(response: Response, maxBytes: number): Promise<{ buf: Buffer; truncated: boolean }> {
  if (!response.body) return { buf: Buffer.alloc(0), truncated: false };
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        chunks.push(Buffer.from(value));
      }
      if (total > maxBytes) {
        truncated = true;
        try {
          await reader.cancel();
        } catch {
          // The stream may already be mid-teardown; best-effort release.
        }
        break;
      }
    }
  } catch {
    // A broken/aborted stream only loses the unread trailing bytes.
  }
  const all = Buffer.concat(chunks);
  return truncated ? { buf: all.subarray(0, maxBytes), truncated: true } : { buf: all, truncated: false };
}

/** Cancel an unread hop body early to release the connection. */
async function consumeHopBody(response: Response): Promise<void> {
  if (!response.body) return;
  try {
    await response.body.cancel();
  } catch {
    // Best-effort release.
  }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === lower);
}

function getHeader(headers: Headers, name: string): string {
  return headers.get(name) ?? '';
}

/** Flatten a Headers object into a lower-cased record (multi-values joined). */
function flattenHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (out[lower] === undefined) out[lower] = value;
    else out[lower] = `${out[lower]}, ${value}`;
  });
  return out;
}

function tryParseJson(text: string): JsonCheck {
  try {
    JSON.parse(text);
    return { valid: true };
  } catch (error) {
    return { valid: false, error: error instanceof Error ? error.message : String(error) };
  }
}
