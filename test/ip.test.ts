import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCompactIpv4Host, classifyIp, classifyIpv4Text, classifyIpv6Text, ipv4ToInt } from '../lib/ip.js';
import type { IpCategory } from '../lib/ip.js';

function expectCategory(ip: string, category: IpCategory): void {
  const info = classifyIp(ip);
  assert.ok(info, `expected "${ip}" to parse as an IP`);
  assert.equal(info.category, category, `category of "${ip}"`);
}

test('IPv4 classification across reserved/private/public ranges', () => {
  expectCategory('10.0.0.1', 'private');
  expectCategory('10.255.255.255', 'private');
  expectCategory('172.16.0.1', 'private');
  expectCategory('172.31.255.255', 'private');
  expectCategory('172.32.0.1', 'public');
  expectCategory('192.168.0.1', 'private');
  expectCategory('192.168.255.255', 'private');
  // CGNAT 100.64.0.0/10
  expectCategory('100.64.0.1', 'private');
  expectCategory('100.127.255.255', 'private');
  expectCategory('100.128.0.1', 'public');
  // loopback 127/8
  expectCategory('127.0.0.1', 'loopback');
  expectCategory('127.255.255.254', 'loopback');
  // link-local 169.254/16 (incl. cloud metadata)
  expectCategory('169.254.0.1', 'link-local');
  expectCategory('169.254.169.254', 'link-local');
  expectCategory('169.255.0.1', 'public');
  // reserved
  expectCategory('0.0.0.0', 'reserved');
  expectCategory('0.255.255.255', 'reserved');
  expectCategory('192.0.0.1', 'reserved');
  expectCategory('192.0.2.1', 'reserved');
  expectCategory('192.88.99.1', 'reserved');
  expectCategory('198.18.0.1', 'reserved');
  expectCategory('198.19.255.255', 'reserved');
  expectCategory('198.20.0.1', 'public');
  expectCategory('198.51.100.1', 'reserved');
  expectCategory('203.0.113.1', 'reserved');
  expectCategory('224.0.0.1', 'reserved');
  expectCategory('239.255.255.255', 'reserved');
  expectCategory('240.0.0.1', 'reserved');
  expectCategory('255.255.255.254', 'reserved');
  expectCategory('255.255.255.255', 'reserved');
  // public
  expectCategory('8.8.8.8', 'public');
  expectCategory('1.1.1.1', 'public');
  expectCategory('93.184.216.34', 'public');
});

test('IPv6 classification across reserved/private/public ranges', () => {
  expectCategory('::', 'reserved');
  expectCategory('::1', 'loopback');
  expectCategory('fc00::', 'private');
  expectCategory('fd12:3456:789a:1::1', 'private');
  expectCategory('fdf8::1', 'private');
  expectCategory('fe80::1', 'link-local');
  expectCategory('ff02::1', 'reserved'); // multicast
  expectCategory('2001:db8::1', 'reserved'); // documentation
  expectCategory('2001:2::1', 'reserved'); // benchmarking
  expectCategory('2002:0102:0304::1', 'reserved'); // 6to4
  expectCategory('64:ff9b::1.2.3.4', 'reserved'); // NAT64 well-known prefix
  expectCategory('64:ff9b:1::1', 'reserved'); // NAT64 local-use prefix (/48)
  expectCategory('64:ff9b:1::10.0.0.1', 'reserved');
  expectCategory('100::1', 'reserved'); // discard-only (100::/64)
  // public IPv6
  expectCategory('2001:4860:4860::8888', 'public');
  expectCategory('2606:2800:220:1:248:1893:25c8:1946', 'public');
  expectCategory('2606:4700:4700::1111', 'public');
});

test('IPv4-mapped and IPv4-compatible IPv6 inherit the embedded IPv4 category', () => {
  expectCategory('::ffff:127.0.0.1', 'loopback');
  expectCategory('::ffff:10.0.0.1', 'private');
  expectCategory('::ffff:192.168.1.1', 'private');
  expectCategory('::ffff:169.254.169.254', 'link-local');
  expectCategory('::ffff:8.8.8.8', 'public');
  // bracket form
  expectCategory('[::ffff:10.0.0.1]', 'private');
  const mapped = classifyIp('::ffff:10.0.0.1');
  assert.equal(mapped?.mappedIpv4, true);
  // deprecated IPv4-compatible form embeds a plain IPv4
  expectCategory('::127.0.0.1', 'loopback');
  expectCategory('::10.0.0.1', 'private');
});

test('compact integer/hostname forms and malformed input', () => {
  // Pure decimal + hex IPv4 hostname forms (curl-style bypasses).
  const compact = classifyCompactIpv4Host('2130706433');
  assert.ok(compact);
  assert.equal(compact.category, 'loopback');
  const hex = classifyCompactIpv4Host('0x7f000001');
  assert.ok(hex);
  assert.equal(hex.category, 'loopback');
  assert.equal(classifyCompactIpv4Host('99999999999'), null); // > 2^32
  assert.equal(classifyCompactIpv4Host('example.com'), null);

  assert.equal(classifyIp('not-an-ip'), null);
  assert.equal(classifyIp(''), null);
  assert.equal(classifyIp('1.2.3'), null);
  assert.equal(classifyIp('1.2.3.4.5'), null);
  assert.equal(ipv4ToInt('256.1.1.1'), null);
  assert.equal(ipv4ToInt('01.2.3.4'), null); // leading zeros rejected
  assert.equal(classifyIp('::1::'), null);
});

test('ipv4Text / ipv6Text helpers normalize values', () => {
  const v4 = classifyIpv4Text('10.1.2.3');
  assert.equal(v4?.normalized, '10.1.2.3');
  assert.equal(v4?.family, 4);
  const v6 = classifyIpv6Text('::ffff:c0a8:0001');
  assert.equal(v6?.family, 6);
  assert.equal(v6?.category, 'private'); // mapped 192.168.0.1
});
