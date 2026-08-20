/**
 * SSRF / private-network protection.
 *
 * The guard verifies a URL *before* the client issues the request AND before
 * every redirect hop:
 *
 *   1. Parse the URL (http/https only).
 *   2. If the host is an IP literal, classify it directly.
 *   3. Otherwise resolve every address (A + AAAA) and fail if ANY resolves to
 *      a blocked category.
 *   4. Whitelisted hostnames/IPs/CIDRs skip IP classification for that hop.
 *
 * The resolver is injectable so the guard is testable without external DNS.
 */
import { lookup } from 'node:dns/promises';
import {
  classifyCompactIpv4Host,
  classifyIp,
  classifyIpv4,
  classifyIpv6Address,
  ipv4ToInt,
  ipv6ToBigInt,
  type IpCategory,
  type IpInfo,
} from './ip.js';
import { HttpDebugError, type SsrfConfig } from './types.js';

/** Type of the DNS resolution hook (hostname -> resolved IP literals). */
export type HostResolver = (hostname: string) => Promise<string[]>;

/** Default resolver: `dns.promises.lookup` with `all` + `verbatim`. */
export async function defaultResolver(hostname: string): Promise<string[]> {
  const records = await lookup(hostname, { all: true, verbatim: true, family: 0 });
  return records.map((record) => record.address);
}

/** Source of the effective whitelist (config entries + runtime additions). */
export interface WhitelistProvider {
  /** Current effective whitelist rules. */
  list(): string[];
}

/** Static whitelist backed by a plain array (used in tests and the CLI). */
export class StaticWhitelist implements WhitelistProvider {
  constructor(private readonly rules: string[] = []) {}
  list(): string[] {
    return this.rules;
  }
}

/* ------------------------------------------------------------------ */
/* Whitelist rule parsing / matching                                   */
/* ------------------------------------------------------------------ */

export type WhitelistRuleKind = 'host' | 'wildcard' | 'ip' | 'cidr';

export interface WhitelistRule {
  kind: WhitelistRuleKind;
  /** Original rule text. */
  raw: string;
  /** For `host`/`wildcard`: normalized hostname (trailing dot stripped). */
  host?: string;
  /** For `ip`/`cidr`: address family. */
  family?: 4 | 6;
  /** For `ip`/`cidr`: base 32-bit IPv4 or 128-bit IPv6 value. */
  base?: number | bigint;
  /** For `cidr`: prefix length. */
  prefix?: number;
}

/**
 * Parse a whitelist rule. Returns `null` when the rule is not a supported form
 * (hostname, `*.hostname` wildcard, IP literal, or CIDR).
 */
export function parseWhitelistRule(rule: string): WhitelistRule | null {
  const raw = rule.trim();
  if (!raw) return null;

  // CIDR -- IPv4 or IPv6.
  const cidr = raw.match(/^(.*?)\/(\d{1,3})$/);
  if (cidr) {
    const addressText = cidr[1]!;
    const prefix = Number.parseInt(cidr[2]!, 10);
    if (prefix < 0) return null;
    if (addressText.includes(':')) {
      if (prefix > 128) return null;
      const clean = addressText.replace(/^\[|\]$/g, '');
      const base = ipv6ToBigInt(clean)?.value;
      if (base === undefined) return null;
      return { kind: 'cidr', raw, family: 6, base, prefix };
    }
    if (prefix > 32) return null;
    const base = ipv4ToInt(addressText);
    if (base === null) return null;
    return { kind: 'cidr', raw, family: 4, base, prefix };
  }

  // IP literal.
  const ipInfo = classifyIp(raw);
  if (ipInfo) {
    const value = literalValue(ipInfo);
    if (value !== null) return { kind: 'ip', raw, family: ipInfo.family, base: value };
    return null;
  }

  // Compact numeric hostnames (`2130706433`, `0x7f000001`) look like host
  // rules but would be reclassified as IPs by the guard and never matched, so
  // refuse them loudly instead of silently accepting a dead rule.
  if (/^(?:0x[0-9a-fA-F]{1,8}|\d{1,10})$/.test(raw.trim())) return null;

  // Hostname / wildcard hostname (`*.domain`). Single labels like `localhost`
  // are valid rule targets.
  const host = raw.toLowerCase().replace(/\.$/, '');
  const wildcard = host.startsWith('*.');
  const bare = wildcard ? host.slice(2) : host;
  if (bare.length === 0) return null;
  for (const label of bare.split('.')) {
    if (!/^[a-z0-9_\-]+$/.test(label)) return null;
  }
  if (wildcard) return { kind: 'wildcard', raw, host: bare };
  return { kind: 'host', raw, host: bare };
}

/** Public helper: is `address` inside the CIDR `rule`? */
export function ipInCidr(address: number | bigint, rule: WhitelistRule): boolean {
  if (typeof address === 'number') {
    if (rule.kind !== 'cidr' || rule.family !== 4 || typeof rule.base !== 'number') return false;
    const mask = rule.prefix === 0 ? 0 : ((0xffff_ffff << (32 - rule.prefix!)) >>> 0);
    const maskedBase = (rule.base & mask) >>> 0;
    // `address & mask` is a SIGNED int32; normalize with `>>> 0` before comparing.
    return ((address & mask) >>> 0) === maskedBase;
  }
  if (rule.kind !== 'cidr' || rule.family !== 6 || typeof rule.base !== 'bigint') return false;
  const v6Prefix = rule.prefix ?? 128;
  // Keep the HIGH `prefix` bits (network portion), unlike the host mask.
  const v6Mask = v6Prefix === 0 ? 0n : ((1n << BigInt(v6Prefix)) - 1n) << BigInt(128 - v6Prefix);
  return (address & v6Mask) === (rule.base & v6Mask);
}

/** Derive the comparable numeric value (32-bit v4 or 128-bit v6) for an IpInfo. */
function literalValue(info: IpInfo): number | bigint | null {
  if (info.family === 4) return ipv4ToInt(info.normalized);
  return ipv6ToBigInt(info.normalized)?.value ?? null;
}

/* ------------------------------------------------------------------ */
/* Guard                                                               */
/* ------------------------------------------------------------------ */

export type SsrfMatchKind = 'whitelist' | 'allowed-public' | 'blocked' | 'bypassed';

export interface SsrfVerdict {
  allowed: boolean;
  /** Human-readable reason for the decision. */
  reason: string;
  /** Normalized hostname examined. */
  host: string;
  /** Port from the URL (default per scheme). */
  port: number;
  /** IP literals the host resolved to (empty for literal hosts / bypass). */
  addresses: string[];
  /** Category of the first blocked address (when blocked). */
  category?: IpCategory;
  /** How the decision was reached. */
  match: SsrfMatchKind;
}

/** Map an IP category to the config toggle that governs it. */
function toggleFor(category: IpCategory): keyof Pick<SsrfConfig, 'blockPrivate' | 'blockLoopback' | 'blockLinkLocal' | 'blockReserved'> | null {
  switch (category) {
    case 'private':
      return 'blockPrivate';
    case 'loopback':
      return 'blockLoopback';
    case 'link-local':
      return 'blockLinkLocal';
    case 'reserved':
      return 'blockReserved';
    case 'public':
      return null;
  }
}

export interface SsrfGuardOptions {
  config: SsrfConfig;
  whitelist?: WhitelistProvider;
  resolver?: HostResolver;
}

/**
 * Verifies that a URL is safe to open. Throws {@link HttpDebugError} with
 * `code === 'SSRF_BLOCKED'` (or `'DNS_FAILED'`) when the target is blocked.
 */
export class SsrfGuard {
  readonly config: SsrfConfig;
  private readonly whitelist: WhitelistProvider;
  private readonly resolver: HostResolver;

  constructor(options: SsrfGuardOptions) {
    this.config = options.config;
    this.whitelist = options.whitelist ?? new StaticWhitelist(options.config.whitelist);
    this.resolver = options.resolver ?? defaultResolver;
  }

  /**
   * Verify a URL. Returns a verdict for allowed targets; throws for blocked
   * ones (unless `opts.bypass` lets everything through).
   */
  async verify(urlString: string, opts: { bypass?: boolean } = {}): Promise<{ url: URL; verdict: SsrfVerdict }> {
    let url: URL;
    try {
      url = new URL(urlString);
    } catch {
      throw new HttpDebugError('INVALID_URL', `Invalid URL: ${urlString}`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new HttpDebugError('UNSUPPORTED_PROTOCOL', `Unsupported protocol "${url.protocol}": only http and https are allowed`, {
        protocol: url.protocol,
      });
    }
    if (!this.config.enabled || opts.bypass) {
      return {
        url,
        verdict: {
          allowed: true,
          reason: 'SSRF protection disabled for this request',
          host: url.hostname,
          port: portOf(url),
          addresses: [],
          match: 'bypassed',
        },
      };
    }

    const host = normalizeHost(url.hostname);
    const verdict = await this.checkTarget(url, host);
    if (!verdict.allowed) {
      throw new HttpDebugError('SSRF_BLOCKED', verdict.reason, {
        host: verdict.host,
        port: verdict.port,
        category: verdict.category,
        addresses: verdict.addresses,
      });
    }
    return { url, verdict };
  }

  /** Whether a hostname is permitted by the whitelist (host or wildcard). */
  hostWhitelisted(host: string): boolean {
    const normalized = normalizeHost(host);
    for (const ruleText of this.whitelist.list()) {
      const parsed = parseWhitelistRule(ruleText);
      if (!parsed) continue;
      if (parsed.kind === 'host' && parsed.host === normalized) return true;
      if (parsed.kind === 'wildcard' && parsed.host) {
        if (normalized === parsed.host || normalized.endsWith(`.${parsed.host}`)) return true;
      }
    }
    return false;
  }

  /** Whether an IP literal matches the whitelist (IP or CIDR). */
  ipWhitelisted(ip: string): boolean {
    const info = classifyIp(ip);
    if (!info) return false;
    const value = literalValue(info);
    if (value === null) return false;
    for (const ruleText of this.whitelist.list()) {
      const parsed = parseWhitelistRule(ruleText);
      if (!parsed) continue;
      if (parsed.kind === 'ip' && parsed.family === info.family && parsed.base === value) return true;
      if (parsed.kind === 'cidr' && parsed.family === info.family && ipInCidr(value, parsed)) return true;
    }
    return false;
  }

  private async checkTarget(url: URL, host: string): Promise<SsrfVerdict> {
    // Literal IPv4/IPv6 host.
    if (host.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      return this.checkLiteralIp(url, host);
    }
    // A hostname whitelist rule is authoritative and wins over compact-IP
    // classification, so rules never silently die next to literal handling.
    if (this.hostWhitelisted(host)) {
      return { allowed: true, reason: `whitelisted hostname "${host}"`, host, port: portOf(url), addresses: [], match: 'whitelist' };
    }
    // Compact numeric IPv4 (pure decimal or 0x-hex) -- closes curl-style bypasses.
    const compact = classifyCompactIpv4Host(host);
    if (compact) {
      return this.classifyLiteral(host, compact.family, literalValue(compact), compact.normalized, portOf(url), compact.category);
    }

    // Hostname: resolve every address; block if any of them is disallowed.
    let addresses: string[];
    try {
      addresses = await this.resolver(host);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new HttpDebugError('DNS_FAILED', `DNS resolution failed for "${host}": ${message}`, { host });
    }
    if (addresses.length === 0) {
      throw new HttpDebugError('DNS_FAILED', `DNS resolution returned no addresses for "${host}"`, { host });
    }

    const block = this.firstBlocked(addresses);
    if (block) {
      return {
        allowed: false,
        reason: `Refused: "${host}" resolves to ${block.address} (${block.category}), which is not allowed`,
        host,
        port: portOf(url),
        addresses,
        category: block.category,
        match: 'blocked',
      };
    }
    return {
      allowed: true,
      reason: `DNS resolved "${host}" to ${addresses.join(', ')}`,
      host,
      port: portOf(url),
      addresses,
      match: 'allowed-public',
    };
  }

  private async checkLiteralIp(url: URL, host: string): Promise<SsrfVerdict> {
    // A hostname-style rule (e.g. a dotted-but-unparseable literal) is
    // authoritative; it lets operators whitelist such targets explicitly.
    if (this.hostWhitelisted(host)) {
      return { allowed: true, reason: `whitelisted hostname "${host}"`, host, port: portOf(url), addresses: [], match: 'whitelist' };
    }
    const info = classifyIp(host);
    if (!info) {
      // Unparseable literal (e.g. malformed IPv6) -- refuse closed.
      throw new HttpDebugError('SSRF_BLOCKED', `Unparseable IP literal host "${host}" (refused)`, { host });
    }
    return this.classifyLiteral(host, info.family, literalValue(info), info.normalized, portOf(url), info.category);
  }

  private classifyLiteral(
    host: string,
    family: 4 | 6,
    value: number | bigint | null,
    normalized: string,
    port: number,
    category?: IpCategory,
  ): SsrfVerdict {
    if (value !== null && this.ipWhitelisted(normalized)) {
      return { allowed: true, reason: `whitelisted address ${normalized}`, host, port, addresses: [normalized], match: 'whitelist' };
    }
    const cat = category ?? (typeof value === 'number' ? classifyIpv4(value) : classifyIpv6Address(value as bigint, null));
    const toggle = toggleFor(cat);
    if (toggle && this.config[toggle]) {
      return { allowed: false, reason: `Refused: ${host} is a ${cat} address`, host, port, addresses: [normalized], category: cat, match: 'blocked' };
    }
    return { allowed: true, reason: `address ${host} is ${cat} (allowed by config)`, host, port, addresses: [normalized], match: 'allowed-public' };
  }

  /** Find the first resolved address that would be blocked by the current config. */
  private firstBlocked(addresses: string[]): { address: string; category: IpCategory } | null {
    for (const address of addresses) {
      // A whitelisted address is permitted even when it is private/reserved:
      // whitelisting a CIDR must authorize hosts that resolve inside it.
      if (this.ipWhitelisted(address)) continue;
      const info = classifyIp(address);
      if (!info) continue;
      const toggle = toggleFor(info.category);
      if (toggle && this.config[toggle]) {
        return { address: info.normalized, category: info.category };
      }
    }
    return null;
  }
}

function normalizeHost(hostname: string): string {
  return hostname.replace(/\.$/, '').toLowerCase();
}

function portOf(url: URL): number {
  const port = Number(url.port);
  if (Number.isInteger(port) && port > 0) return port;
  return url.protocol === 'https:' ? 443 : 80;
}
