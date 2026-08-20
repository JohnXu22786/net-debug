/**
 * dsh-http-debug -- DeepSeek Harness bundle.
 *
 * Registers three model-facing tools on `ctx.tools`:
 *   - `http_request` -- general HTTP client with per-hop SSRF protection,
 *     redirect control, body caps, JSON validation, and HAR export,
 *   - `http_history` -- session request/response history with replay,
 *   - `http_rules`   -- runtime SSRF whitelist management.
 *
 * The core (guard, client, history, HAR) is dependency-free and is also
 * exported for programmatic use outside of dsh.
 */
import type { Context } from '@deepseek-ai/cordis';
import { defineHttpDebugTools } from './tools.js';
import { HttpDebug, type ToolRequestInput } from './service.js';
import type { HttpDebugConfig } from './types.js';

export const name = 'dsh-http-debug';

/** The plugin needs the tool registry to mount its tools. */
export const inject = ['tools'];

export function apply(ctx: Context, config?: Partial<HttpDebugConfig>): void {
  const service = new HttpDebug({ config });
  const tools = defineHttpDebugTools(service);
  for (const tool of tools) {
    ctx.tools.register(tool);
  }
  // Keep a back-reference so the model-facing tools and the plugin share one
  // config object (the tools close over `service`; nothing else to wire).
  void service;
}

// Re-export the core for programmatic use.
export { HttpDebug } from './service.js';
export type { ToolRequestInput, RulesView } from './service.js';
export { HttpDebugError } from './types.js';
export type {
  HttpDebugConfig,
  SsrfConfig,
  ClientConfig,
  HistoryConfig,
  HarConfig,
  NormalizedConfig,
  HttpResponse,
  HistoryEntry,
  HistorySummary,
  RedirectHop,
  JsonCheck,
  RequestOptions,
} from './types.js';
export { SsrfGuard, StaticWhitelist, parseWhitelistRule } from './ssrf.js';
export type { WhitelistProvider, SsrfVerdict, HostResolver } from './ssrf.js';
export { HttpClient } from './http.js';
export type { HttpClientOptions } from './http.js';
export { HistoryStore } from './history.js';
export { RuleStore } from './rule-store.js';
export { buildHarLog } from './har.js';
