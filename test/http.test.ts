import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { SsrfGuard } from '../lib/ssrf.js';
import { HttpDebugError, DEFAULT_CONFIG, type SsrfConfig } from '../lib/types.js';
import { HttpClient, isRedirectStatus } from '../lib/http.js';

const WHITELIST = ['127.0.0.1', '::1', 'localhost'];

function localGuard(overrides: Partial<SsrfConfig> = {}): SsrfGuard {
  const config: SsrfConfig = { ...DEFAULT_CONFIG.ssrf, ...overrides, whitelist: overrides.whitelist ?? WHITELIST };
  return new SsrfGuard({ config });
}

function clientFor(guardInstance: SsrfGuard, overrides: Partial<typeof DEFAULT_CONFIG.client> = {}): HttpClient {
  return new HttpClient({
    guard: guardInstance,
    config: { ...DEFAULT_CONFIG.client, ...overrides },
    defaultIncludeHar: false,
  });
}

interface TestServer {
  base: string;
  close: () => Promise<void>;
}

function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<TestServer> {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      // Tell undici not to keep the socket pooled so test teardown exits cleanly.
      res.setHeader('connection', 'close');
      handler(req, res);
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('failed to bind'));
        return;
      }
      resolve({
        base: `http://127.0.0.1:${address.port}`,
        close: async () => {
          if (!server.listening) return;
          // Stop accepting, destroy pooled connections, then wait for 'close'.
          server.closeAllConnections?.();
          await new Promise<void>((resolveClose) => {
            server.close(() => resolveClose());
            server.once('error', () => resolveClose());
          });
        },
      });
    });
  });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

let echo: TestServer;

before(async () => {
  echo = await startServer(async (req, res) => {
    const body = await readBody(req);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ path: req.url, method: req.method, body, ua: req.headers['user-agent'] ?? null }));
  });
});

after(async () => {
  await echo?.close();
  // Give undici's global agent a moment to release the keep-alive socket.
  await new Promise((resolve) => setTimeout(resolve, 100));
});

test('basic GET returns a structured response', async () => {
  const client = clientFor(localGuard());
  const result = await client.request({ url: `${echo.base}/hello` });
  assert.equal(result.status, 200);
  assert.equal(result.statusText, 'OK');
  assert.equal(result.ok, true);
  assert.equal(result.bodyEncoding, 'utf8');
  const parsed = JSON.parse(result.body) as { path: string; method: string; body: string };
  assert.equal(parsed.path, '/hello');
  assert.equal(parsed.method, 'GET');
  assert.equal(result.headers['content-type'], 'application/json');
  assert.ok(result.durationMs >= 0);
  assert.equal(result.redirected, false);
});

test('default WAF headers add a User-Agent unless overridden', async () => {
  const client = clientFor(localGuard());
  const result = await client.request({ url: `${echo.base}/ua` });
  const parsed = JSON.parse(result.body) as { ua: string };
  assert.ok(parsed.ua && parsed.ua.length > 0, 'user-agent should be set by default');

  const explicit = await client.request({ url: `${echo.base}/ua2`, headers: { 'user-agent': 'custom-agent' } });
  const parsed2 = JSON.parse(explicit.body) as { ua: string };
  assert.equal(parsed2.ua, 'custom-agent');

  const off = await client.request({ url: `${echo.base}/ua3`, wafHeaders: false });
  const parsed3 = JSON.parse(off.body) as { ua: string | null };
  // wafHeaders off must NOT inject OUR default UA. (undici still sends its own
  // `node` default, so only refuse the dsh default here.)
  assert.notEqual(parsed3.ua, DEFAULT_CONFIG.client.userAgent);
});

test('POST with a JSON body echoes method, path, and body', async () => {
  const client = clientFor(localGuard());
  const result = await client.request({
    url: `${echo.base}/api/posts`,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'hi', id: 1 }),
    validateJson: true,
  });
  const parsed = JSON.parse(result.body) as { method: string; body: string };
  assert.equal(parsed.method, 'POST');
  assert.equal(parsed.body, JSON.stringify({ title: 'hi', id: 1 }));
  assert.deepEqual(result.json, { valid: true });
});

test('redirect chains are followed hop-by-hop and sanitized by SSRF', async () => {
  const server = await startServer((req, res) => {
    if (req.url === '/a') {
      res.writeHead(302, { location: '/b' });
      res.end();
    } else if (req.url === '/b') {
      res.writeHead(301, { location: `${server.base}/c` });
      res.end();
    } else if (req.url === '/c') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('done');
    } else {
      res.writeHead(404);
      res.end('nope');
    }
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/a` });
    assert.equal(result.status, 200);
    assert.equal(result.body, 'done');
    assert.equal(result.redirected, true);
    assert.equal(result.redirects.length, 2);
    assert.equal(result.redirects[0]?.from, `${server.base}/a`);
    assert.equal(result.redirects[0]?.to, `${server.base}/b`);
    assert.equal(result.redirects[1]?.to, `${server.base}/c`);
  } finally {
    await server.close();
  }
});

test('a redirect hop into a private literal is refused', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(302, { location: 'http://10.0.0.1/inside' });
    res.end();
  });
  try {
    const client = clientFor(localGuard());
    await assert.rejects(client.request({ url: `${server.base}/hop` }), (err: unknown) => {
      assert.ok(err instanceof HttpDebugError);
      assert.equal(err.code, 'SSRF_BLOCKED');
      return true;
    });
  } finally {
    await server.close();
  }
});

test('a redirect hop into a host that resolves privately is refused', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(302, { location: 'http://evil.local/steal' });
    res.end();
  });
  try {
    const guardInstance = new SsrfGuard({
      config: { ...DEFAULT_CONFIG.ssrf, whitelist: WHITELIST },
      resolver: async (host) => (host === 'evil.local' ? ['10.9.9.9'] : []),
    });
    const client = clientFor(guardInstance);
    await assert.rejects(client.request({ url: `${server.base}/hop` }), (err: unknown) => {
      assert.ok(err instanceof HttpDebugError);
      assert.equal(err.code, 'SSRF_BLOCKED');
      return true;
    });
  } finally {
    await server.close();
  }
});

test('redirect cap is enforced', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(302, { location: '/next' });
    res.end();
  });
  try {
    const client = clientFor(localGuard());
    await assert.rejects(client.request({ url: `${server.base}/x`, maxRedirects: 2 }), (err: unknown) => {
      assert.ok(err instanceof HttpDebugError);
      assert.equal(err.code, 'TOO_MANY_REDIRECTS');
      return true;
    });
  } finally {
    await server.close();
  }
});

test('follow_redirects=false returns the 3xx as the final response', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(302, { location: '/elsewhere' });
    res.end('go away');
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/x`, followRedirects: false });
    assert.equal(result.status, 302);
    assert.equal(result.redirected, false);
    assert.equal(result.redirects.length, 0);
  } finally {
    await server.close();
  }
});

test('POST redirected with 302 becomes GET with no body', async () => {
  const server = await startServer((req, res) => {
    if (req.url === '/submit') {
      res.writeHead(302, { location: '/result' });
      res.end();
      return;
    }
    if (req.url === '/result') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ method: req.method, bodyLength: 0 }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({
      url: `${server.base}/submit`,
      method: 'POST',
      body: 'payload',
      headers: { 'content-type': 'text/plain' },
    });
    const parsed = JSON.parse(result.body) as { method: string };
    assert.equal(parsed.method, 'GET');
    assert.equal(result.method, 'GET');
  } finally {
    await server.close();
  }
});

test('body truncation caps captured bytes and flags truncation', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('x'.repeat(64 * 1024));
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/big`, maxBodyBytes: 4096 });
    assert.equal(result.bodyTruncated, true);
    assert.equal(result.bodySizeBytes, 4096);
    assert.ok(result.body.length <= 4096);
  } finally {
    await server.close();
  }
});

test('binary bodies are base64-encoded and lossless within the cap', async () => {
  const server = await startServer((req, res) => {
    const buf = Buffer.from([0, 255, 1, 2, 3, 4, 0, 128]);
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(buf);
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/bin` });
    assert.equal(result.bodyEncoding, 'base64');
    const decoded = Buffer.from(result.body, 'base64');
    assert.deepEqual([...decoded], [0, 255, 1, 2, 3, 4, 0, 128]);
  } finally {
    await server.close();
  }
});

test('timeout raises a TIMEOUT error', async () => {
  const server = await startServer((req, res) => {
    // Never respond.
    void res;
  });
  try {
    const client = clientFor(localGuard());
    await assert.rejects(client.request({ url: `${server.base}/hang`, timeoutMs: 80 }), (err: unknown) => {
      assert.ok(err instanceof HttpDebugError);
      assert.equal(err.code, 'TIMEOUT');
      return true;
    });
  } finally {
    await server.close();
  }
});

test('network errors surface as NETWORK_ERROR', async () => {
  const client = clientFor(localGuard());
  await assert.rejects(client.request({ url: 'http://127.0.0.1:1/nope', timeoutMs: 800 }), (err: unknown) => {
    assert.ok(err instanceof HttpDebugError);
    assert.equal(err.code, 'NETWORK_ERROR');
    return true;
  });
});

test('JSON validation reports invalid JSON', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{ not json');
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/bad`, validateJson: true });
    assert.equal(result.json?.valid, false);
    assert.ok(result.json?.error && result.json.error.length > 0);
  } finally {
    await server.close();
  }
});

test('HAR document is attached when requested', async () => {
  const client = clientFor(localGuard());
  const result = await client.request({ url: `${echo.base}/har`, includeHar: true });
  assert.ok(result.har);
  const har = result.har as { log: { version: string; entries: unknown[] } };
  assert.equal(har.log.version, '1.2');
  assert.equal(har.log.entries.length, 1);
});

test('isRedirectStatus recognises the six followable codes only', () => {
  assert.equal(isRedirectStatus(301), true);
  assert.equal(isRedirectStatus(302), true);
  assert.equal(isRedirectStatus(303), true);
  assert.equal(isRedirectStatus(307), true);
  assert.equal(isRedirectStatus(308), true);
  assert.equal(isRedirectStatus(200), false);
  assert.equal(isRedirectStatus(300), false);
  assert.equal(isRedirectStatus(304), false);
  assert.equal(isRedirectStatus(404), false);
});

test('recognisable 4xx is returned as a real response, not an error', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(418, { 'content-type': 'text/plain' });
    res.end('teapot');
  });
  try {
    const client = clientFor(localGuard());
    const result = await client.request({ url: `${server.base}/teapot` });
    assert.equal(result.status, 418);
    assert.equal(result.ok, false);
    assert.equal(result.body, 'teapot');
  } finally {
    await server.close();
  }
});

test('an already-aborted external signal yields ABORTED', async () => {
  const client = clientFor(localGuard());
  const controller = new AbortController();
  controller.abort(new Error('operator cancelled'));
  await assert.rejects(client.request({ url: `${echo.base}/cancel`, signal: controller.signal }), (err: unknown) => {
    assert.ok(err instanceof HttpDebugError);
    assert.equal(err.code, 'ABORTED');
    return true;
  });
});

test('3xx without a Location header is a final response, never a redirect-cap error', async () => {
  const server = await startServer((req, res) => {
    res.writeHead(302);
    res.end('nowhere to go');
  });
  try {
    const client = clientFor(localGuard());
    // Even with maxRedirects: 0, a 3xx that cannot be followed is final.
    const result = await client.request({ url: `${server.base}/r`, maxRedirects: 0 });
    assert.equal(result.status, 302);
    assert.equal(result.redirected, false);
    assert.equal(result.redirects.length, 0);
    assert.equal(result.body, 'nowhere to go');
  } finally {
    await server.close();
  }
});

test('untyped bodies are sniffed as text or binary', async () => {
  const server = await startServer((req, res) => {
    if (req.url === '/text') {
      res.end('plain ascii body'); // never sets a Content-Type
    } else {
      res.end(Buffer.from([0xff, 0x00, 0xab, 0x40])); // invalid UTF-8 -> binary
    }
  });
  try {
    const client = clientFor(localGuard());
    const text = await client.request({ url: `${server.base}/text` });
    assert.equal(text.bodyEncoding, 'utf8');
    assert.equal(text.body, 'plain ascii body');
    const bin = await client.request({ url: `${server.base}/bin` });
    assert.equal(bin.bodyEncoding, 'base64');
    assert.deepEqual([...Buffer.from(bin.body, 'base64')], [0xff, 0x00, 0xab, 0x40]);
  } finally {
    await server.close();
  }
});
