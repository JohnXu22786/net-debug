/**
 * dsh-http-debug — end-to-end bundle integration proof.
 *
 * Mounts the plugin exactly as the dsh Loader would: a real Cordis Context, a
 * real ToolRegistry (provided as the `tools` service the plugin injects), then
 * `ctx.plugin(plugin)` — and finally runs `http_request` through the real
 * registry pipeline.
 *
 * Run after `npm run build`:
 *   node examples/dsh-integration.mjs
 */
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { Context } from '@deepseek-ai/cordis';
import { ToolRegistry } from '@deepseek-ai/dsh-tools';
import * as plugin from '../lib/index.js';

// A local echo server the (whitelisted) request will hit.
const server = createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
  res.end(JSON.stringify({ echo: true, path: req.url }));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const ctx = new Context();
// Give the ToolRegistry the services it needs, then mount it as `tools`.
ctx.provide('systemPrompt', { tools() {}, sections() {}, assemble() {} });
const tools = new ToolRegistry(ctx);

// The plugin entry (name/inject/apply) — this is what the bundle loads.
await ctx.plugin(plugin, { ssrf: { whitelist: ['127.0.0.1'] } });

console.log('registered:', ctx.tools.schemas().map((s) => s.name).join(', '));

// Run http_request through the real execution pipeline.
const exec = { callId: randomUUID(), name: 'http_request', arguments: { url: `${base}/ping`, validate_json: true }, signal: new AbortController().signal };
const result = await ctx.tools.execute(exec);
console.log('isError:', result.isError);
if (!result.isError) {
  console.log('status:', result.value.status, '| ok:', result.value.ok, '| json.valid:', result.value.json.valid);
  console.log('historyId:', result.value.historyId);
}

server.close();
process.exit(0);
