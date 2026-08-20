/**
 * HAR 1.2 (HTTP Archive) export.
 *
 * The builder produces a standard `.har` document wrapping one exchange. The
 * same builder is used by the tools (embedded `har` field), by the CLI
 * (`--har file`), and by the examples.
 */

export const HAR_VERSION = '1.2';

/** Minimal creator metadata for the archive. */
export interface HarCreator {
  name: string;
  version: string;
  comment?: string;
}

interface HarRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  httpVersion?: string;
  body?: string;
  bodyEncoding?: 'text' | 'base64' | 'none';
}

interface HarResponse {
  status: number;
  statusText: string;
  headers?: Record<string, string>;
  contentType: string;
  body: string;
  bodyEncoding: 'utf8' | 'base64' | 'none';
  bodySizeBytes: number;
}

interface HarMeta {
  durationMs: number;
  startedAt?: string;
}

function headerList(headers: Record<string, string> | undefined): Array<{ name: string; value: string }> {
  return Object.entries(headers ?? {}).map(([name, value]) => ({ name, value }));
}

function queryString(url: string): Array<{ name: string; value: string }> {
  const parsed = new URL(url);
  const out: Array<{ name: string; value: string }> = [];
  for (const [key, value] of parsed.searchParams.entries()) {
    out.push({ name: key, value });
  }
  return out;
}

/** Build a HAR 1.2 `log` document for a single exchange. */
export function buildHarLog(
  request: HarRequest,
  response: HarResponse,
  meta: HarMeta,
  creator: HarCreator = { name: 'dsh-http-debug', version: '1.0.0' },
): { log: HarLog } {
  return {
    log: {
      version: HAR_VERSION,
      creator,
      entries: [
        {
          startedDateTime: meta.startedAt ?? new Date().toISOString(),
          time: meta.durationMs,
          request: {
            method: request.method,
            url: request.url,
            httpVersion: request.httpVersion ?? 'HTTP/1.1',
            cookies: [],
            headers: headerList(request.headers),
            queryString: queryString(request.url),
            ...buildPostData(request),
            headersSize: -1,
            bodySize: estimateBodySize(request.body, request.bodyEncoding),
          },
          response: {
            status: response.status,
            statusText: response.statusText,
            httpVersion: 'HTTP/1.1',
            cookies: [],
            headers: headerList(response.headers),
            content: {
              size: response.bodySizeBytes,
              compression: 0,
              mimeType: response.contentType || 'application/octet-stream',
              ...buildContent(response),
            },
            redirectURL: '',
            headersSize: -1,
            bodySize: response.bodySizeBytes,
          },
          cache: {},
          timings: {
            send: 0,
            wait: meta.durationMs,
            receive: 0,
          },
        },
      ],
    },
  };
}

function buildPostData(request: HarRequest): { postData?: { mimeType: string; text?: string; encoding?: string } } {
  if (request.body === undefined || request.body.length === 0) return {};
  const mimeType = request.headers?.['content-type'] ?? 'application/octet-stream';
  if (request.bodyEncoding === 'base64') {
    return { postData: { mimeType, text: request.body, encoding: 'base64' } };
  }
  return { postData: { mimeType, text: request.body } };
}

function buildContent(response: HarResponse): { text?: string; encoding?: string } {
  if (response.body.length === 0) return {};
  if (response.bodyEncoding === 'base64') {
    return { text: response.body, encoding: 'base64' };
  }
  return { text: response.body };
}

function estimateBodySize(body: string | undefined, encoding: string | undefined): number {
  if (!body) return 0;
  if (encoding === 'base64') {
    // Base64 length -> approximate decoded byte count.
    return Math.floor(body.length * 0.75);
  }
  return Buffer.byteLength(body, 'utf8');
}

/** HAR 1.2 log document shape (structural subset). */
export interface HarLog {
  version: string;
  creator: HarCreator;
  entries: Array<{
    startedDateTime: string;
    time: number;
    request: Record<string, unknown>;
    response: Record<string, unknown>;
    cache: Record<string, unknown>;
    timings: Record<string, unknown>;
  }>;
}
