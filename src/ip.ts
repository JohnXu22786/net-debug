/**
 * IP address classification. Pure, dependency-free logic that maps an IP
 * literal to a category the SSRF guard can selectively block.
 *
 * Categories:
 *   - `loopback`   -- 127.0.0.0/8, ::1
 *   - `private`    -- RFC 1918 (10/8, 172.16/12, 192.168/16), CGNAT
 *                     100.64/10, IPv6 Unique Local fc00::/7
 *   - `link-local` -- 169.254/16, IPv6 fe80::/10
 *   - `reserved`   -- every other special-use / documentation / multicast /
 *                     broadcast / unspecified range
 *   - `public`     -- routable addresses that are safe to reach
 */

export type IpFamily = 4 | 6;
export type IpCategory = 'loopback' | 'private' | 'link-local' | 'reserved' | 'public';

export interface IpInfo {
  family: IpFamily;
  /** Normalized textual form (IPv4 dotted-quad, IPv6 canonical or dotted). */
  normalized: string;
  category: IpCategory;
  /** Whether this was an IPv6 address embedding an IPv4 literal (`::ffff:x`). */
  mappedIpv4: boolean;
}

/** Number of bits in an IPv4 address. */
const V4_MAX = 0xffff_ffff;

/* ------------------------------------------------------------------ */
/* IPv4                                                                */
/* ------------------------------------------------------------------ */

/** Parse a dotted-quad IPv4 into a 32-bit integer, or `null`. */
export function ipv4ToInt(text: string): number | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

/** Format a 32-bit integer back into a dotted-quad string. */
export function ipv4FromInt(value: number): string {
  return [value >>> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff].join('.');
}

/**
 * Classify a 32-bit IPv4. Range membership is checked largest-block-first so
 * the most specific documented meaning wins (e.g. 127/8 is loopback, not the
 * more generic first/early range).
 */
export function classifyIpv4(value: number): IpCategory {
  // Comparisons use `>>> 0` because `value & mask` yields a SIGNED int32 that
  // would never equal these large positive literals otherwise.
  const u = value >>> 0;
  // 100.64.0.0/10 -- carrier-grade NAT (shared address space).
  if ((u & 0xffc0_0000) === 0x6440_0000) return 'private';
  // 127.0.0.0/8 -- loopback.
  if (u >>> 24 === 127) return 'loopback';
  // 10.0.0.0/8 -- private.
  if (u >>> 24 === 10) return 'private';
  // 172.16.0.0/12 -- private.
  if (((u & 0xfff0_0000) >>> 0) === 0xac10_0000) return 'private';
  // 192.168.0.0/16 -- private.
  if (u >>> 16 === 0xc0a8) return 'private';
  // 169.254.0.0/16 -- link-local.
  if (u >>> 16 === 0xa9fe) return 'link-local';
  // 0.0.0.0/8 -- "this network" / unspecified.
  if (u >>> 24 === 0) return 'reserved';
  // 192.0.0.0/24 -- IETF protocol assignments.
  if (((u & 0xffff_ff00) >>> 0) === 0xc000_0000) return 'reserved';
  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 -- documentation TEST-NET.
  if (((u & 0xffff_ff00) >>> 0) === 0xc000_0200) return 'reserved';
  if (((u & 0xffff_ff00) >>> 0) === 0xc633_6400) return 'reserved';
  if (((u & 0xffff_ff00) >>> 0) === 0xcb00_7100) return 'reserved';
  // 192.88.99.0/24 -- deprecated 6to4 relay anycast.
  if (((u & 0xffff_ff00) >>> 0) === 0xc058_6300) return 'reserved';
  // 198.18.0.0/15 -- benchmarking.
  if (((u & 0xfffe_0000) >>> 0) === 0xc612_0000) return 'reserved';
  // 224.0.0.0/4 -- multicast.
  if (u >>> 28 === 14) return 'reserved';
  // 240.0.0.0/4 -- reserved (incl. 255.255.255.255 broadcast at the tail).
  if (u >= 0xf000_0000) return 'reserved';
  return 'public';
}

export function classifyIpv4Text(text: string): IpInfo | null {
  const value = ipv4ToInt(text);
  if (value === null) return null;
  return {
    family: 4,
    normalized: ipv4FromInt(value),
    category: classifyIpv4(value),
    mappedIpv4: false,
  };
}

/* ------------------------------------------------------------------ */
/* IPv6                                                                */
/* ------------------------------------------------------------------ */

/**
 * Parse an IPv6 text into a 128-bit BigInt, or `null`. Accepts the canonical
 * `::` compression and a trailing dotted-quad IPv4 form (e.g. `::ffff:1.2.3.4`).
 * Returns the numeric address AND the embedded IPv4 tail when present.
 */
export function ipv6ToBigInt(text: string): { value: bigint; embeddedIpv4: number | null } | null {
  const input = text.trim();
  if (!input || input.includes(' ')) return null;

  // A lone IPv4 is not IPv6.
  if (!input.includes(':')) return null;

  let head = input;
  let embeddedIpv4: number | null = null;

  // Split a trailing dotted-quad (last group) into a numeric value.
  const v4Match = input.match(/(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4Match && v4Match[1] && v4Match[2]) {
    const v4 = ipv4ToInt(v4Match[2]);
    if (v4 === null) return null;
    embeddedIpv4 = v4;
    head = `${v4Match[1]}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  const doubleColon = head.split('::');
  if (doubleColon.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (!part) return [];
    const groups = part.split(':');
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  let left: number[];
  let right: number[];
  if (doubleColon.length === 2) {
    const l = parseGroups(doubleColon[0] ?? '');
    const r = parseGroups(doubleColon[1] ?? '');
    if (l === null || r === null) return null;
    if (l.length + r.length >= 8) return null; // `::` must stand for >= 1 group
    left = l;
    right = r;
  } else {
    const all = parseGroups(head);
    if (all === null || all.length !== 8) return null;
    return { value: groupsToBigInt(all), embeddedIpv4 };
  }

  const pad = 8 - left.length - right.length;
  const groups = [...left, ...new Array<number>(pad).fill(0), ...right];
  return { value: groupsToBigInt(groups), embeddedIpv4 };
}

function groupsToBigInt(groups: number[]): bigint {
  let value = 0n;
  for (const g of groups) {
    value = (value << 16n) | BigInt(g);
  }
  return value;
}

/**
 * Classify a 128-bit IPv6 address. IPv4-mapped forms (`::ffff:a.b.c.d`) are
 * classified by the embedded IPv4. NAT64 well-known-prefix addresses are
 * conservative: they are reserved regardless of the embedded value, because we
 * cannot prove the translated endpoint is public.
 */
export function classifyIpv6Address(addr: bigint, embeddedIpv4: number | null): IpCategory {
  // IPv4-mapped: 0:0:0:0:0:ffff:a.b.c.d -> high 80 bits 0, then 0xffff, then v4.
  const g0 = addr >> 96n;
  const g1 = (addr >> 64n) & 0xffff_ffffn;
  const g2 = (addr >> 32n) & 0xffff_ffffn;
  const low = addr & 0xffff_ffffn;

  if (g0 === 0n && g1 === 0n && g2 === 0xffffn && embeddedIpv4 !== null) {
    return classifyIpv4(embeddedIpv4);
  }
  // The `::ffff:0:0/96` window where the host part is not a legal dotted form.
  if (g0 === 0n && g1 === 0n && g2 === 0xffffn) return classifyIpv4(Number(low));

  if (addr === 0n) return 'reserved'; // :: -- unspecified
  if (addr === 1n) return 'loopback'; // ::1

  // IPv4-compatible (deprecated) `::a.b.c.d` embeds a plain IPv4 in the low 32
  // bits; some stacks route these to the IPv4 address, so classify by it. (The
  // WHATWG URL parser may already have normalized the dotted tail to hex, so
  // match on the numeric shape, not the original spelling.)
  if (g0 === 0n && g1 === 0n && g2 === 0n && low !== 0n) {
    return classifyIpv4(Number(low));
  }
  // NAT64 prefixes: well-known `64:ff9b::/96` and local-use `64:ff9b:1::/48`,
  // both map to (possibly private) IPv4 and cannot be trusted as-is.
  if (g0 === 0x0064_ff9bn) {
    if ((g1 === 0n && g2 === 0n) || (g1 >> 16n) === 0x0001n) return 'reserved';
  }

  // fe80::/10 -- link-local.
  if ((addr >> 118n) === 0x3fan) return 'link-local';
  // fc00::/7 -- unique-local (private).
  if ((addr >> 121n) === 0x7en) return 'private';
  // ff00::/8 -- multicast.
  if ((addr >> 120n) === 0xffn) return 'reserved';
  // 2001:db8::/32 -- documentation.
  if (g0 === 0x2001_0db8n) return 'reserved';
  // 2001:2::/48 -- benchmarking.
  if (g0 === 0x2001_0002n && g1 === 0n) return 'reserved';
  // 2002::/16 -- 6to4.
  if ((g0 >> 16n) === 0x2002n) return 'reserved';
  // 100::/64 -- discard-only (first 64 bits fixed: 0100:0000:0000:0000).
  if (g0 === 0x0100_0000n && g1 === 0n) return 'reserved';

  return 'public';
}

/** Classify an IPv6 literal. Returns `null` when the text is not a valid IPv6. */
export function classifyIpv6Text(text: string): IpInfo | null {
  const cleaned = text.replace(/^\s*\[|\]\s*$/g, '');
  const parsed = ipv6ToBigInt(cleaned);
  if (parsed === null) return null;
  const g0 = parsed.value >> 96n;
  const g1 = (parsed.value >> 64n) & 0xffff_ffffn;
  const g2 = (parsed.value >> 32n) & 0xffff_ffffn;
  return {
    family: 6,
    normalized: cleaned,
    category: classifyIpv6Address(parsed.value, parsed.embeddedIpv4),
    mappedIpv4: parsed.embeddedIpv4 !== null && g0 === 0n && g1 === 0n && g2 === 0xffffn,
  };
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

/**
 * Classify an IP literal (either family). Returns `null` when `text` is not a
 * valid IP literal.
 */
export function classifyIp(text: string): IpInfo | null {
  const cleaned = text.trim();
  if (!cleaned) return null;
  if (cleaned.includes(':')) return classifyIpv6Text(cleaned);
  return classifyIpv4Text(cleaned);
}

/**
 * Attempt to interpret a hostname string that is not a dotted IPv4 as a compact
 * IPv4 notation (pure decimal or `0x`-prefixed hex, e.g. `2130706433`). This
 * closes a class of SSRF bypasses where tools like curl accept such forms.
 * Returns the classified IPv4 or `null`.
 */
export function classifyCompactIpv4Host(hostname: string): IpInfo | null {
  let match: RegExpMatchArray | null;
  if ((match = hostname.match(/^0x([0-9a-fA-F]{1,8})$/))) {
    const n = Number.parseInt(match[1]!, 16);
    if (Number.isNaN(n)) return null;
    return { family: 4, normalized: ipv4FromInt(n), category: classifyIpv4(n), mappedIpv4: false };
  }
  if ((match = hostname.match(/^(\d{1,10})$/))) {
    const n = Number.parseInt(match[1]!, 10);
    if (Number.isNaN(n) || n > V4_MAX) return null;
    return { family: 4, normalized: ipv4FromInt(n), category: classifyIpv4(n), mappedIpv4: false };
  }
  return null;
}
