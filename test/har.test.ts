import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHarLog } from '../lib/har.js';

const REQUEST = { method: 'POST', url: 'https://api.example.com/v1/items?page=2&tag=a' };
const RESPONSE = {
  status: 201,
  statusText: 'Created',
  headers: { 'content-type': 'text/plain', 'x-trace': 't1' },
  contentType: 'text/plain',
  body: 'hello',
  bodyEncoding: 'utf8' as const,
  bodySizeBytes: 5,
};
const META = { durationMs: 123, startedAt: '2026-01-01T00:00:00.000Z' };

test('HAR log has the required top-level structure', () => {
  const har = buildHarLog(REQUEST, RESPONSE, META);
  assert.equal(har.log.version, '1.2');
  assert.equal(har.log.creator.name, 'dsh-http-debug');
  assert.ok(har.log.entries.length === 1);
  const entry = har.log.entries[0]!;
  assert.equal(entry.startedDateTime, META.startedAt);
  assert.equal(entry.time, 123);
});

test('HAR request captures method, URL, query string, and headers', () => {
  const har = buildHarLog(REQUEST, RESPONSE, META);
  const request = har.log.entries[0]!.request as {
    method: string;
    url: string;
    queryString: Array<{ name: string; value: string }>;
    headers: Array<{ name: string; value: string }>;
  };
  assert.equal(request.method, 'POST');
  assert.equal(request.url, REQUEST.url);
  assert.deepEqual(
    request.queryString.map((q) => [q.name, q.value]).sort(),
    [
      ['page', '2'],
      ['tag', 'a'],
    ],
  );
  assert.ok(request.headers.length >= 0);
});

test('HAR response captures status, headers, and content', () => {
  const har = buildHarLog(REQUEST, RESPONSE, META);
  const response = har.log.entries[0]!.response as {
    status: number;
    statusText: string;
    headers: Array<{ name: string; value: string }>;
    content: { size: number; mimeType: string; text?: string };
    redirectURL: string;
  };
  assert.equal(response.status, 201);
  assert.equal(response.statusText, 'Created');
  assert.deepEqual(response.headers.find((h) => h.name === 'x-trace'), { name: 'x-trace', value: 't1' });
  assert.equal(response.content.size, 5);
  assert.equal(response.content.mimeType, 'text/plain');
  assert.equal(response.content.text, 'hello');
  assert.equal(response.redirectURL, '');
});

test('binary content is base64-encoded in the archive', () => {
  const har = buildHarLog(REQUEST, { ...RESPONSE, body: 'AAH/', bodyEncoding: 'base64', contentType: 'application/octet-stream' }, META);
  const content = (har.log.entries[0]!.response as { content: { encoding?: string; text?: string } }).content;
  assert.equal(content.encoding, 'base64');
  assert.equal(content.text, 'AAH/');
});

test('request bodies become HAR postData', () => {
  const har = buildHarLog(
    { ...REQUEST, body: 'raw=1', headers: { 'content-type': 'application/x-www-form-urlencoded' } },
    RESPONSE,
    META,
  );
  const request = har.log.entries[0]!.request as { postData: { mimeType: string; text?: string; encoding?: string } };
  assert.equal(request.postData.mimeType, 'application/x-www-form-urlencoded');
  assert.equal(request.postData.text, 'raw=1');
});

test('cache and timings objects are present', () => {
  const har = buildHarLog(REQUEST, RESPONSE, META);
  const entry = har.log.entries[0]!;
  assert.deepEqual(entry.cache, {});
  assert.equal((entry.timings as { send: number; wait: number; receive: number }).wait, 123);
});
