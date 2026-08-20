import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';

const execFileP = promisify(execFile);
const CLI = fileURLToPath(new URL('../lib/cli.js', import.meta.url));

let base: string;
let closeServer: () => Promise<void>;

before(async () => {
  const server = createServer((req, res) => {
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
