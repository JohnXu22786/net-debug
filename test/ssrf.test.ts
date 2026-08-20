import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SsrfGuard, StaticWhitelist, parseWhitelistRule } from '../lib/ssrf.js';
import { HttpDebugError, DEFAULT_CONFIG, type SsrfConfig } from '../lib/types.js';

/** Deterministic resolver used to avoid external DNS in tests. */
const resolver: Record<string, string[]> = {
  'public.example': ['93.184.216.34'],
  'evil.example': ['10.0.0.5'],
  'mixed.example': ['93.184.216.34', '192.168.1.1'],
  'local.example': ['127.0.0.1'],
  'meta.example': ['169.254.169.254'],
  'doc.example': ['203.0.113.5'],
  'ok6.example': ['2606:2800:220:1:248:1893:25c8:1946'],
  'ulav6.example': ['fd00::1'],
  'corp.example': ['192.168.42.7'],
};

function fakeResolver(hostname: string): Promise<string[]> {
  return Promise.resolve(resolver[hostname] ?? []);
}

function guard(config: Partial<SsrfConfig> = {}): SsrfGuard {
  const merged: SsrfConfig = { ...DEFAULT_CONFIG.ssrf, ...config, whitelist: config.whitelist ?? [] };
  return new SsrfGuard({ config: merged, resolver: fakeResolver });
}

async function expectBlocked(guardInstance: SsrfGuard, url: string, code = 'SSRF_BLOCKED'): Promise<void> {
  await assert.rejects(guardInstance.verify(url), (error: unknown) => {
    assert.ok(error instanceof HttpDebugError);
    assert.equal(error.code, code);
    return true;
  });
}

test('literal IPv4 blocking across category switches', async () => {
  const g = guard();
  await expectBlocked(g, 'http://10.0.0.1/');
  await expectBlocked(g, 'http://127.0.0.1/');
  await expectBlocked(g, 'http://169.254.169.254/latest/meta-data');
  await expectBlocked(g, 'http://100.64.0.1/');
  await expectBlocked(g, 'http://192.0.2.1/');
  await expectBlocked(g, 'http://224.0.0.1/');
  // public is allowed
  const ok = await g.verify('http://8.8.8.8/');
  assert.equal(ok.verdict.allowed, true);
  assert.equal(ok.verdict.match, 'allowed-public');
});

test('compact numeric IPv4 hostnames are caught', async () => {
  const g = guard();
  await expectBlocked(g, 'http://2130706433/'); // 127.0.0.1 in decimal
  await expectBlocked(g, 'http://0x7f000001/'); // 127.0.0.1 in hex
  await expectBlocked(g, 'http://0x0A000001/'); // 10.0.0.1 in hex
});

test('IPv6 and IPv4-mapped.-IPv6 literals are caught', async () => {
  const g = guard();
  await expectBlocked(g, 'http://[::1]/');
  await expectBlocked(g, 'http://[fd00::1]/');
  await expectBlocked(g, 'http://[fe80::1]/');
  await expectBlocked(g, 'http://[::ffff:127.0.0.1]/');
  await expectBlocked(g, 'http://[::ffff:10.0.0.1]/');
  await expectBlocked(g, 'http://[::10.0.0.1]/');
  const ok = await g.verify('http://[2606:2800:220:1:248:1893:25c8:1946]/');
  assert.equal(ok.verdict.allowed, true);
});

test('DNS-resolved hostnames inherit classification of every resolved address', async () => {
  const g = guard();
  // public host allowed
  let ok = await g.verify('http://public.example/');
  assert.equal(ok.verdict.allowed, true);
  assert.deepEqual(ok.verdict.addresses, ['93.184.216.34']);
  // private host blocked
  await expectBlocked(g, 'http://evil.example/');
  // metadata link-local blocked
  await expectBlocked(g, 'http://meta.example/');
  // documentation blocked
  await expectBlocked(g, 'http://doc.example/');
  // IPv6 ULA via hostname blocked
  await expectBlocked(g, 'http://ulav6.example/');
  // IPv6 public allowed
  ok = await g.verify('http://ok6.example/');
  assert.equal(ok.verdict.allowed, true);
  // one private address among several blocked the whole host
  await expectBlocked(g, 'http://mixed.example/');
});

test('localhost resolves to loopback and is blocked by default', async () => {
  const resolverLocal = { ...resolver, localhost: ['127.0.0.1'] };
  const g = new SsrfGuard({
    config: { ...DEFAULT_CONFIG.ssrf, whitelist: [] },
    resolver: (host) => Promise.resolve(resolverLocal[host] ?? []),
  });
  await expectBlocked(g, 'http://localhost/');
});

test('whitelist escapes blocking (host, wildcard, IP, CIDR)', async () => {
  // Exact hostname
  let g = guard({ whitelist: ['evil.example'] });
  let ok = await g.verify('http://evil.example/');
  assert.equal(ok.verdict.allowed, true);
  assert.equal(ok.verdict.match, 'whitelist');

  // Wildcard sub-domain matches the apex and children
  g = guard({ whitelist: ['*.corp.example'] });
  ok = await g.verify('http://corp.example/');
  assert.equal(ok.verdict.allowed, true);
  ok = await g.verify('http://api.corp.example/');
  assert.equal(ok.verdict.allowed, true);
  await expectBlocked(g, 'http://evil.example/');

  // CIDR for a literal and for a resolved host
  g = guard({ whitelist: ['10.0.0.0/8'] });
  ok = await g.verify('http://10.0.0.5/');
  assert.equal(ok.verdict.allowed, true);
  g = guard({ whitelist: ['192.168.0.0/16'] });
  ok = await g.verify('http://corp.example/');
  assert.equal(ok.verdict.allowed, true);

  // Single IP literal
  g = guard({ whitelist: ['127.0.0.1'] });
  ok = await g.verify('http://127.0.0.1/');
  assert.equal(ok.verdict.allowed, true);

  // IPv6 CIDR
  g = guard({ whitelist: ['fd00::/8'] });
  ok = await g.verify('http://[fd00::1]/');
  assert.equal(ok.verdict.allowed, true);
});

test('per-category toggles selectively disable blocking', async () => {
  let g = guard({ blockLoopback: false });
  let ok = await g.verify('http://127.0.0.1/');
  assert.equal(ok.verdict.allowed, true);
  await expectBlocked(g, 'http://10.0.0.1/'); // private still blocked

  g = guard({ blockPrivate: false });
  ok = await g.verify('http://10.0.0.1/');
  assert.equal(ok.verdict.allowed, true);
  await expectBlocked(g, 'http://127.0.0.1/'); // loopback still blocked

  g = guard({ blockLinkLocal: false });
  ok = await g.verify('http://169.254.169.254/');
  assert.equal(ok.verdict.allowed, true);

  g = guard({ blockReserved: false });
  ok = await g.verify('http://192.0.2.1/');
  assert.equal(ok.verdict.allowed, true);
  await expectBlocked(g, 'http://10.0.0.1/');
});

test('master switch and per-call bypass disable all checks', async () => {
  let g = guard({ enabled: false });
  let ok = await g.verify('http://10.0.0.1/');
  assert.equal(ok.verdict.allowed, true);
  assert.equal(ok.verdict.match, 'bypassed');

  g = guard();
  ok = await g.verify('http://10.0.0.1/', { bypass: true });
  assert.equal(ok.verdict.allowed, true);
  assert.equal(ok.verdict.match, 'bypassed');
});

test('protocol and URL validation', async () => {
  const g = guard();
  await expectBlocked(g, 'ftp://example.com/', 'UNSUPPORTED_PROTOCOL');
  await expectBlocked(g, 'file:///etc/passwd', 'UNSUPPORTED_PROTOCOL');
  await expectBlocked(g, '::not-a-url', 'INVALID_URL');
});

test('DNS failures refuse the request', async () => {
  const g = guard();
  // unknown.example resolves to [] -> no addresses
  await expectBlocked(g, 'http://missing.example/', 'DNS_FAILED');
});

test('DNS resolver errors surface as DNS_FAILED', async () => {
  const failing = new SsrfGuard({
    config: { ...DEFAULT_CONFIG.ssrf, whitelist: [] },
    resolver: async () => {
      throw new Error('ENOTFOUND');
    },
  });
  await expectBlocked(failing, 'http://anyhost.example/', 'DNS_FAILED');
});

test('whitelist provider is consulted dynamically (runtime rules)', async () => {
  const runtime: string[] = [];
  const g = new SsrfGuard({
    config: { ...DEFAULT_CONFIG.ssrf, whitelist: [] },
    whitelist: new StaticWhitelist(runtime),
    resolver: fakeResolver,
  });
  await expectBlocked(g, 'http://corp.example/');
  runtime.push('192.168.0.0/16');
  const ok = await g.verify('http://corp.example/');
  assert.equal(ok.verdict.allowed, true);
});

test('single-label hostnames are valid whitelist rules (e.g. localhost)', async () => {
  assert.equal(parseWhitelistRule('localhost')?.kind, 'host');
  const g = guard({ whitelist: ['localhost'] });
  const ok = await g.verify('http://localhost/');
  assert.equal(ok.verdict.allowed, true);
  assert.equal(ok.verdict.match, 'whitelist');
});

test('whitelist rule validation rejects unsupported forms', async () => {
  assert.ok(parseWhitelistRule('10.0.0.0/8'));
  assert.ok(parseWhitelistRule('fd00::/8'));
  assert.ok(parseWhitelistRule('*.example.com'));
  assert.ok(parseWhitelistRule('example.com'));
  assert.ok(parseWhitelistRule('127.0.0.1'));
  // A dotted-numeric string without a valid IP is accepted as a hostname.
  assert.equal(parseWhitelistRule('500.1.1.1')?.kind, 'host');
  // Compact-numeric single labels are reclassified as IPs by the guard, so
  // they are refused as rules rather than silently accepted as dead hostnames.
  assert.equal(parseWhitelistRule('2130706433'), null);
  assert.equal(parseWhitelistRule('0x7f000001'), null);
  assert.equal(parseWhitelistRule('http://example.com'), null);
  assert.equal(parseWhitelistRule(''), null);
  assert.equal(parseWhitelistRule('example..com'), null);
  assert.equal(parseWhitelistRule('.example.com'), null);
  assert.equal(parseWhitelistRule('exa mple.com'), null);
});

test('port is preserved in the verdict', async () => {
  const g = guard();
  const ok = await g.verify('http://8.8.8.8:8123/path');
  assert.equal(ok.verdict.port, 8123);
});
