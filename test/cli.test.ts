import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileP = promisify(execFile);
const CLI = fileURLToPath(new URL('../lib/cli.js', import.meta.url));

let base: string;
let closeServer: () => Promise<void>;

before(async () => {
  const server = createServer((req, res) => {
    if (req.url?.startsWith('/json')) {
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end('{"hello":"world"}');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });
    res.end('ok');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  closeServer = async () => {
    if (!server.listening) return;
    server.closeAllConnections?.();
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  };
});

after(async () => {
  await closeServer?.();
});

test('CLI refuses loopback by default (exit 3, SSRF_BLOCKED)', async () => {
  await assert.rejects(execFileP(process.execPath, [CLI, `${base}/x`]), (error: unknown) => {
    const e = error as { code?: number; stderr?: string };
    assert.equal(e.code, 3);
    assert.ok(String(e.stderr).includes('SSRF_BLOCKED'));
    return true;
  });
});

test('CLI --rule whitelists the target (exit 0, structured output)', async () => {
  const { stdout } = await execFileP(process.execPath, [CLI, `${base}/y`, '--rule', '127.0.0.1']);
  const parsed = JSON.parse(stdout) as { status: number; ok: boolean };
  assert.equal(parsed.status, 200);
  assert.equal(parsed.ok, true);
});

test('CLI rejects an invalid --rule (exit 2)', async () => {
  await assert.rejects(execFileP(process.execPath, [CLI, `${base}/z`, '--rule', '0x7f000001']), (error: unknown) => {
    const e = error as { code?: number };
    assert.equal(e.code, 2);
    return true;
  });
});

test('CLI --raw prints only the body', async () => {
  const { stdout } = await execFileP(process.execPath, [CLI, `${base}/raw`, '--rule', '127.0.0.1', '--raw']);
  assert.equal(stdout.trim(), 'ok');
});

test('CLI rejects non-numeric --max-body-bytes (exit 2)', async () => {
  await assert.rejects(execFileP(process.execPath, [CLI, `${base}/n`, '--max-body-bytes', 'abc']), (error: unknown) => {
    const e = error as { code?: number };
    assert.equal(e.code, 2);
    return true;
  });
});

test('CLI --version prints the tool name and a semver, --help exits 0', async () => {
  const { stdout: version } = await execFileP(process.execPath, [CLI, '--version']);
  assert.match(version.trim(), /^dsh-http-debug \d+\.\d+\.\d+/);

  const { stdout: help } = await execFileP(process.execPath, [CLI, '--help']);
  assert.match(help, /Usage:/);
  assert.match(help, /--rule/);
});

test('CLI --har writes the HAR into a newly-created nested directory', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-net-'));
  try {
    const har = join(dir, 'nested', 'deep', 'out.har');
    await execFileP(process.execPath, [CLI, `${base}/har`, '--rule', '127.0.0.1', '--har', har]);
    assert.equal(existsSync(har), true, `expected HAR at ${har}`);
    const parsed = JSON.parse(readFileSync(har, 'utf8')) as { log: { entries: unknown[] } };
    assert.ok(Array.isArray(parsed.log.entries));
    assert.ok(parsed.log.entries.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI --validate-json reports json.valid for both valid and invalid bodies', async () => {
  const valid = JSON.parse(
    (
      await execFileP(process.execPath, [CLI, `${base}/json`, '--rule', '127.0.0.1', '--validate-json'])
    ).stdout,
  ) as { json: { valid: boolean } };
  assert.equal(valid.json.valid, true);

  const invalid = JSON.parse(
    (await execFileP(process.execPath, [CLI, `${base}/x`, '--rule', '127.0.0.1', '--validate-json'])).stdout,
  ) as { json: { valid: boolean; error?: string } };
  assert.equal(invalid.json.valid, false);
  assert.ok(typeof invalid.json.error === 'string' && invalid.json.error.length > 0);
});
