import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HistoryStore } from '../lib/history.js';
import type { HistoryEntry } from '../lib/types.js';

function entry(id: string, partial: Partial<HistoryEntry> = {}): HistoryEntry {
  return {
    id,
    startedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 10,
    outcome: 'ok',
    request: {
      method: 'GET',
      url: 'http://example.com/',
      headers: {},
      hasBody: false,
      bodyEncoding: 'text',
      bodySizeBytes: 0,
    },
    response: {
      status: 200,
      statusText: 'OK',
      headers: {},
      body: 'ok',
      bodyEncoding: 'utf8',
      bodySizeBytes: 2,
      bodyTruncated: false,
      redirects: [],
    },
    recordedBytes: 2,
    ...partial,
  };
}

test('storing and retrieving entries round-trips', () => {
  const store = new HistoryStore(10);
  store.push(entry('a'));
  const got = store.get('a');
  assert.ok(got);
  assert.equal(got.id, 'a');
  assert.equal(got.outcome, 'ok');
});

test('ring buffer keeps the newest maxEntries and evicts the oldest', () => {
  const store = new HistoryStore(3);
  for (let i = 1; i <= 5; i += 1) store.push(entry(`h${i}`));
  assert.equal(store.stats().count, 3);
  assert.equal(store.get('h1'), undefined);
  assert.equal(store.get('h2'), undefined);
  assert.ok(store.get('h3'));
  assert.ok(store.get('h4'));
  assert.ok(store.get('h5'));
});

test('list returns newest-first summaries with the key fields', () => {
  const store = new HistoryStore(5);
  store.push(entry('a', { request: { ...entry('a').request, method: 'GET', url: 'http://a.example' } }));
  store.push(entry('b', { request: { ...entry('b').request, method: 'POST', url: 'http://b.example' } }));
  const list = store.list();
  assert.equal(list.length, 2);
  assert.equal(list[0]?.id, 'b');
  assert.equal(list[1]?.id, 'a');
  assert.equal(list[0]?.method, 'POST');
  assert.equal(list[0]?.url, 'http://b.example');
  assert.equal(list[0]?.status, 200);
  assert.equal(list[0]?.outcome, 'ok');
});

test('error entries carry their error and no response', () => {
  const store = new HistoryStore(5);
  store.push(entry('x', { outcome: 'error', error: { code: 'SSRF_BLOCKED', message: 'nope' }, response: undefined, recordedBytes: 0 }));
  const got = store.get('x');
  assert.equal(got?.outcome, 'error');
  assert.equal(got?.error?.code, 'SSRF_BLOCKED');
  assert.equal(got?.response, undefined);
});

test('clear empties the store and returns the count', () => {
  const store = new HistoryStore(5);
  store.push(entry('a'));
  store.push(entry('b'));
  assert.equal(store.clear(), 2);
  assert.equal(store.stats().count, 0);
  assert.equal(store.get('a'), undefined);
  assert.equal(store.clear(), 0);
});

test('stats track capacity and cumulative recorded bytes', () => {
  const store = new HistoryStore(4);
  store.push(entry('1', { recordedBytes: 100 }));
  store.push(entry('2', { recordedBytes: 50 }));
  assert.equal(store.stats().totalBytes, 150);
  store.push(entry('3', { recordedBytes: 30 }));
  store.push(entry('4', { recordedBytes: 20 }));
  store.push(entry('5', { recordedBytes: 10 })); // evicts entry 1
  assert.equal(store.stats().count, 4);
  assert.equal(store.stats().capacity, 4);
  assert.equal(store.stats().totalBytes, 110); // 50 + 30 + 20 + 10
});

test('capacity zero stores nothing (holds at most capacity)', () => {
  const store = new HistoryStore(0);
  assert.equal(store.stats().capacity, 0);
  store.push(entry('a'));
  store.push(entry('b'));
  assert.equal(store.stats().count, 0);
  assert.equal(store.get('a'), undefined);
  assert.equal(store.list().length, 0);
});
