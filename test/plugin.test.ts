import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as plugin from '../lib/index.js';

test('the plugin entry exposes the bundle contract', () => {
  assert.equal(plugin.name, 'dsh-http-debug');
  assert.ok(plugin.inject?.includes('tools'), 'plugin injects the tools service');
  assert.equal(typeof plugin.apply, 'function');
});

test('apply registers the three tools through ctx.tools', () => {
  const registered: Array<{ name: string }> = [];
  const fakeCtx = {
    tools: {
      register(def: { name: string }) {
        registered.push(def);
        return () => undefined;
      },
    },
    on() {},
    logger: () => ({}),
  };

  plugin.apply(fakeCtx as never, {});

  const names = registered.map((t) => t.name).sort();
  assert.deepEqual(names, ['http_history', 'http_request', 'http_rules']);
});

test('apply accepts partial configuration without throwing', () => {
  const registered: Array<{ name: string }> = [];
  const fakeCtx = {
    tools: {
      register(def: { name: string }) {
        registered.push(def);
        return () => undefined;
      },
    },
    on() {},
    logger: () => ({}),
  };
  plugin.apply(fakeCtx as never, { ssrf: { enabled: false }, history: { maxEntries: 3 } });
  assert.equal(registered.length, 3);
});
