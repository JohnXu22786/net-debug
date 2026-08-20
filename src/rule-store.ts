/**
 * Session-lived whitelist overrides layered on top of the configured base
 * whitelist. Lets the `http_rules` tool add/remove rules at runtime without
 * editing configuration files.
 */
import { parseWhitelistRule, type WhitelistProvider } from './ssrf.js';
import { HttpDebugError } from './types.js';

export class RuleStore implements WhitelistProvider {
  private readonly runtime: string[] = [];
  private revision = 0;
  private readonly base: string[];

  /** Base rules are validated at construction so config typos fail loud. */
  constructor(base: string[] = []) {
    for (const rule of base) {
      if (!parseWhitelistRule(rule)) {
        throw new HttpDebugError('INVALID_RULE', `Invalid ssrf.whitelist rule "${rule}"`, { rule });
      }
    }
    this.base = [...base];
  }

  /** Effective whitelist: configured base rules first, then runtime ones. */
  list(): string[] {
    return [...this.base, ...this.runtime];
  }

  /** Runtime-only rules (excludes the configured base whitelist). */
  runtimeRules(): string[] {
    return [...this.runtime];
  }

  /** Current revision counter (bumped whenever the runtime set changes). */
  revisionOf(): number {
    return this.revision;
  }

  /** Add a runtime rule. Invalid input errors; duplicates are idempotent. */
  add(rule: string): { ok: boolean; rule?: string; error?: string; alreadyPresent?: boolean } {
    const trimmed = rule.trim();
    if (!trimmed) return { ok: false, error: 'empty rule' };
    if (!parseWhitelistRule(trimmed)) {
      return { ok: false, error: 'not a supported rule (hostname, *.wildcard, IP literal, or CIDR)' };
    }
    if (this.runtime.some((existing) => sameRule(existing, trimmed))) {
      return { ok: true, rule: trimmed, alreadyPresent: true };
    }
    this.runtime.push(trimmed);
    this.revision += 1;
    return { ok: true, rule: trimmed };
  }

  /** Remove a runtime rule by equivalent rule text. Returns `false` when absent. */
  remove(rule: string): boolean {
    const index = this.runtime.findIndex((existing) => sameRule(existing, rule));
    if (index === -1) return false;
    this.runtime.splice(index, 1);
    this.revision += 1;
    return true;
  }

  /** Remove every runtime rule; returns how many were removed. */
  clear(): number {
    const removed = this.runtime.length;
    this.runtime.length = 0;
    if (removed > 0) this.revision += 1;
    return removed;
  }
}

/** Compare two rules structurally (raw text or parsed form equivalence). */
function sameRule(a: string, b: string): boolean {
  if (a.trim().toLowerCase() === b.trim().toLowerCase()) return true;
  const pa = parseWhitelistRule(a);
  const pb = parseWhitelistRule(b);
  if (!pa || !pb) return false;
  if (pa.kind !== pb.kind) return false;
  if (pa.kind === 'host' || pa.kind === 'wildcard') return pa.host === pb.host;
  return pa.family === pb.family && pa.base === pb.base && (pa.prefix ?? 32) === (pb.prefix ?? 32);
}
