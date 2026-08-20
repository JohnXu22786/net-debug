import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { HttpDebug } from '../lib/service.js';
import { defineHttpDebugTools } from '../lib/tools.js';
import { HttpDebugError } from '../lib/types.js';
import type { HttpResponse } from '../lib/types.js';

/** Minimal execution context: the tools only read `exec.signal`. */
function execContext(): { signal: AbortSignal } {
  return { signal: new AbortController().signal };
}

function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{
  base: string;
  close: () => Promise<void>;
}> {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('bind failed')));
        return;
      }
      resolve({
        base: `http://127.0.0.1:${address.port}`,
        close: async () => {
          if (!server.listening) return;
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

let base: string;
let closeServer: () => Promise<void>;
let service: HttpDebug;
let tools: ReturnType<typeof defineHttpDebugTools>;

before(async () => {
  const server = await startServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({ echo: true, path: req.url, method: req.method, body: Buffer.concat(chunks).toString('utf8') }),
      );
    });
  });
  base = server.base;
  closeServer = server.close;
  service = new HttpDebug({ config: { ssrf: { whitelist: ['127.0.0.1', 'localhost'] }, history: { maxEntries: 5 } } });
  tools = defineHttpDebugTools(service);
});

after(async () => {
  await closeServer?.();
});

test('three tools are defined with the expected names', () => {
  assert.equal(tools[0]!.name, 'http_request');
  assert.equal(tools[1]!.name, 'http_history');
  assert.equal(tools[2]!.name, 'http_rules');
  for (const tool of tools) {
    assert.ok(tool.description && tool.description.length > 10);
    assert.ok(tool.output && typeof tool.output.render === 'function');
  }
});

test('http_request executes end-to-end and records history', async () => {
  const requestTool = tools[0]!;
  const result = (await requestTool.execute({ url: `${base}/one`, validate_json: true }, execContext() as never)) as HttpResponse;
  assert.equal(result.status, 200);
  assert.equal(result.ok, true);
  assert.ok(result.historyId.length > 0);
  assert.deepEqual(result.json, { valid: true });

  const historyTool = tools[1]!;
  const list = (await historyTool.execute({ action: 'list' }, execContext() as never)) as Array<{ id: string }>;
  assert.ok(list.some((item) => item.id === result.historyId));
});

test('http_history get returns the stored entry, clear resets the store', async () => {
  const historyTool = tools[1]!;
  const list = (await historyTool.execute({ action: 'list' }, execContext() as never)) as Array<{ id: string }>;
  const first = list[0] as { id: string };
  const got = (await historyTool.execute({ action: 'get', id: first.id }, execContext() as never)) as { entry: { id: string; request: { method: string } } };
  assert.equal(got.entry.id, first.id);
  assert.equal(got.entry.request.method, 'GET');

  const cleared = (await historyTool.execute({ action: 'clear' }, execContext() as never)) as { cleared: number };
  assert.ok(cleared.cleared >= 1);
  const afterClear = (await historyTool.execute({ action: 'list' }, execContext() as never)) as unknown[];
  assert.equal(afterClear.length, 0);
});

test('http_request can replay a stored request by history id', async () => {
  const requestTool = tools[0]!;
  const historyTool = tools[1]!;
  const first = (await requestTool.execute({ url: `${base}/replay-me` }, execContext() as never)) as HttpResponse;
  const replayed = (await requestTool.execute({ history_id: first.historyId }, execContext() as never)) as HttpResponse;
  assert.equal(replayed.status, 200);
  assert.notEqual(replayed.historyId, first.historyId); // a brand-new attempt
  const list = (await historyTool.execute({ action: 'list' }, execContext() as never)) as Array<{ id: string }>;
  assert.ok(list.some((item) => item.id === replayed.historyId));
});

test('http_rules add/remove gates request reachability', async () => {
  const rulesTool = tools[2]!;
  const requestTool = tools[0]!;

  // This service blocks loopback by default outside the whitelist -- build one
  // with an empty whitelist to prove rules open access at runtime.
  const strictEnvironment = new HttpDebug({ config: { ssrf: { whitelist: [] } } });
  const strictTools = defineHttpDebugTools(strictEnvironment);

  const blocked = await assert.rejects(
    strictTools[0]!.execute({ url: `${base}/guarded` }, execContext() as never),
    (err: unknown) => err instanceof HttpDebugError && err.code === 'SSRF_BLOCKED',
  );
  void blocked;

  const added = (await strictTools[2]!.execute({ action: 'add', rule: '127.0.0.1' }, execContext() as never)) as { added: string };
  assert.equal(added.added, '127.0.0.1');

  const ok = (await strictTools[0]!.execute({ url: `${base}/guarded` }, execContext() as never)) as HttpResponse;
  assert.equal(ok.status, 200);

  const removed = (await strictTools[2]!.execute({ action: 'remove', rule: '127.0.0.1' }, execContext() as never)) as { removed: boolean };
  assert.equal(removed.removed, true);

  await assert.rejects(strictTools[0]!.execute({ url: `${base}/guarded` }, execContext() as never), (err: unknown) =>
    err instanceof HttpDebugError && err.code === 'SSRF_BLOCKED');

  void rulesTool;
  void requestTool;
});

test('http_rules list reports base + runtime + effective rules', async () => {
  const rulesTool = tools[2]!;
  const view = (await rulesTool.execute({ action: 'list' }, execContext() as never)) as {
    base: string[];
    runtime: string[];
    effective: string[];
  };
  assert.deepEqual(view.base, ['127.0.0.1', 'localhost']);
  assert.ok(Array.isArray(view.runtime));
  assert.deepEqual(view.effective, [...view.base, ...view.runtime]);
});

test('http_rules add surfaces invalid rules as INVALID_RULE', async () => {
  const rulesTool = tools[2]!;
  await assert.rejects(rulesTool.execute({ action: 'add', rule: 'http://example.com' }, execContext() as never), (err: unknown) => {
    assert.ok(err instanceof HttpDebugError);
    assert.equal(err.code, 'INVALID_RULE');
    return true;
  });
  // Duplicates are idempotent, not errors.
  const again = (await rulesTool.execute({ action: 'add', rule: '127.0.0.1' }, execContext() as never)) as { added: string; alreadyPresent?: boolean };
  assert.equal(again.added, '127.0.0.1');
});

test('http_request sends base64 binary bodies and rejects invalid base64', async () => {
  const requestTool = tools[0]!;
  const payload = 'hello \u0000 world';
  const b64 = Buffer.from(payload, 'utf8').toString('base64');
  const result = (await requestTool.execute(
    { url: `${base}/b64`, method: 'POST', body_base64: b64 },
    execContext() as never,
  )) as HttpResponse;
  const echoed = JSON.parse(result.body) as { body: string };
  assert.equal(echoed.body, payload);

  await assert.rejects(service.request({ url: `${base}/bad`, bodyBase64: '!!!not-base64!!!' }), (err: unknown) => {
    assert.ok(err instanceof HttpDebugError);
    assert.equal(err.code, 'INVALID_BODY');
    return true;
  });
});

test('request parameters are validated (unknown method is rejected)', async () => {
  const requestTool = tools[0]!;
  // defineTool validates the method enum before execute runs, so an unknown
  // method must reject.
  await assert.rejects(requestTool.execute({ url: `${base}/x`, method: 'BREW' }, execContext() as never));

  // The service itself also rejects unsupported methods with a structured error.
  await assert.rejects(service.request({ url: `${base}/y`, method: 'BREW' }), (err: unknown) => {
    assert.ok(err instanceof HttpDebugError);
    assert.equal(err.code, 'INVALID_URL');
    return true;
  });
});
