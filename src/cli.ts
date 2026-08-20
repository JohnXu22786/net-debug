#!/usr/bin/env node
/**
 * dsh-http-debug CLI -- a zero-dependency command-line front-end for the same
 * HTTP debugging core the dsh plugin uses, with the same SSRF protection.
 *
 * Usage:
 *   dsh-http-debug <url> [options]
 *
 * Examples:
 *   dsh-http-debug https://api.example.com/users?limit=5 --validate-json
 *   dsh-http-debug https://example.com/login -X POST -d '{"user":"a"}' \
 *     -H 'content-type: application/json'
 *   dsh-http-debug https://example.com/file.bin --raw --max-body-bytes 1024
 */
import { readFile, writeFile } from 'node:fs/promises';
import { HttpDebug, type ToolRequestInput } from './service.js';
import { HttpDebugError, type HttpDebugConfig, type HttpResponse } from './types.js';
import { buildHarLog } from './har.js';
import { parseWhitelistRule } from './ssrf.js';

const VERSION = '1.0.0';

interface FileBodySpec {
  mode: 'text' | 'binary';
  path: string;
}

interface CliOptions {
  url?: string;
  input: ToolRequestInput;
  config: HttpDebugConfig | Partial<HttpDebugConfig>;
  raw: boolean;
  harFile?: string;
  jsonConfigFile?: string;
  fileBodies: FileBodySpec[];
}

function printHelp(): void {
  process.stdout.write(`dsh-http-debug ${VERSION}

Usage: dsh-http-debug <url> [options]

Options:
  -X, --method <m>          HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
  -H, --header <n:v>        request header (repeatable; also accepts n=v)
  -d, --data <body>         UTF-8 request body
      --data-base64 <b64>   base64 request body (binary)
      --data-file <path>    read the request body from a text file
      --data-binary <path>  read the request body from a file verbatim
      --timeout <ms>        per-request timeout in ms (0 = no timeout; default 30000)
  -F, --follow              follow redirects (default)
  -N, --no-follow           do not follow redirects
      --max-redirects <n>   redirect cap (default 10)
      --max-body-bytes <n>  captured body cap in bytes (default 131072)
      --validate-json       validate a JSON body
      --har <path>          write a HAR 1.2 file for this exchange
      --json                print the full structured result as JSON (default)
      --raw                 print only the response body
      --allow-private       bypass SSRF protection for this request (unsafe)
      --rule <rule>         add a runtime whitelist rule (hostname, *.wild, IP, CIDR; repeatable)
      --no-waf              do not add default User-Agent/Referer headers
      --ssrf-enabled        enable SSRF blocking (default)
      --ssrf-disabled       disable SSRF blocking entirely (unsafe)
      --config-file <path>  JSON config file overriding defaults (see README)
  -v, --version             print the version
  -h, --help                print this help
`);
}

function expectValue(argv: string[], index: number, flag: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('-')) throw new Error(`option ${flag} requires a value`);
  return value;
}

/** Parse a numeric flag value, requiring a finite non-negative number. */
function NonNegativeNumber(argv: string[], index: number, flag: string): number {
  const value = Number(expectValue(argv, index, flag));
  if (!Number.isFinite(value) || value < 0) throw new Error(`${flag} must be a non-negative number`);
  return value;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { input: {}, config: {}, raw: false, fileBodies: [] };
  const unknown: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '-v' || arg === '--version') {
      process.stdout.write(`dsh-http-debug ${VERSION}\n`);
      process.exit(0);
    } else if (arg === '-X' || arg === '--method') {
      opts.input.method = expectValue(argv, i++, arg).toUpperCase();
    } else if (arg === '-H' || arg === '--header') {
      const header = expectValue(argv, i++, arg);
      const sep = header.indexOf(':');
      const eq = header.indexOf('=');
      const at = sep === -1 ? eq : eq === -1 ? sep : Math.min(sep, eq);
      if (at === -1) throw new Error(`header must be "name:value", got "${header}"`);
      const key = header.slice(0, at).trim();
      const value = header.slice(at + 1).trim();
      if (!key) throw new Error(`empty header name in "${header}"`);
      opts.input.headers = { ...(opts.input.headers ?? {}), [key]: value };
    } else if (arg === '-d' || arg === '--data') {
      opts.input.body = expectValue(argv, i++, arg);
    } else if (arg === '--data-base64') {
      opts.input.bodyBase64 = expectValue(argv, i++, arg);
    } else if (arg === '--data-file') {
      opts.fileBodies.push({ mode: 'text', path: expectValue(argv, i++, arg) });
    } else if (arg === '--data-binary') {
      opts.fileBodies.push({ mode: 'binary', path: expectValue(argv, i++, arg) });
    } else if (arg === '--timeout') {
      opts.input.timeoutMs = NonNegativeNumber(argv, i, arg);
      i += 1;
    } else if (arg === '-F' || arg === '--follow') {
      opts.input.followRedirects = true;
    } else if (arg === '-N' || arg === '--no-follow') {
      opts.input.followRedirects = false;
    } else if (arg === '--max-redirects') {
      opts.input.maxRedirects = NonNegativeNumber(argv, i, arg);
      i += 1;
    } else if (arg === '--max-body-bytes') {
      opts.input.maxBodyBytes = NonNegativeNumber(argv, i, arg);
      i += 1;
    } else if (arg === '--validate-json') {
      opts.input.validateJson = true;
    } else if (arg === '--har') {
      opts.harFile = expectValue(argv, i++, arg);
    } else if (arg === '--json') {
      opts.raw = false;
    } else if (arg === '--raw') {
      opts.raw = true;
    } else if (arg === '--allow-private') {
      opts.input.bypassSsfr = true;
    } else if (arg === '--rule') {
      const rule = expectValue(argv, i++, arg);
      if (!parseWhitelistRule(rule)) {
        throw new Error(`--rule "${rule}" is not a supported rule (hostname, *.wildcard, IP literal, or CIDR)`);
      }
      const ssrf = opts.config.ssrf ?? {};
      ssrf.whitelist = [...(ssrf.whitelist ?? []), rule];
      opts.config.ssrf = ssrf;
    } else if (arg === '--no-waf') {
      opts.input.wafHeaders = false;
    } else if (arg === '--ssrf-enabled') {
      opts.config.ssrf = { ...(opts.config.ssrf ?? {}), enabled: true };
    } else if (arg === '--ssrf-disabled') {
      opts.config.ssrf = { ...(opts.config.ssrf ?? {}), enabled: false };
    } else if (arg === '--config-file') {
      opts.jsonConfigFile = expectValue(argv, i++, arg);
    } else if (arg.startsWith('-')) {
      unknown.push(arg);
    } else if (opts.url !== undefined) {
      throw new Error(`unexpected positional argument "${arg}" (only one URL allowed)`);
    } else {
      opts.url = arg;
    }
  }

  if (unknown.length > 0) throw new Error(`unknown option(s): ${unknown.join(', ')}`);
  if (!opts.url) throw new Error('a URL is required (see --help)');
  opts.input.url = opts.url;
  return opts;
}

function mergeConfig(base: Partial<HttpDebugConfig>, overlay: Partial<HttpDebugConfig>): Partial<HttpDebugConfig> {
  return {
    ssrf: { ...(base.ssrf ?? {}), ...(overlay.ssrf ?? {}) },
    client: { ...(base.client ?? {}), ...(overlay.client ?? {}) },
    history: { ...(base.history ?? {}), ...(overlay.history ?? {}) },
    har: { ...(base.har ?? {}), ...(overlay.har ?? {}) },
  };
}

async function runCli(argv: string[]): Promise<number> {
  const opts = parseArgs(argv);

  // Read any file-based bodies (last spec wins, mirroring flag order).
  for (const spec of opts.fileBodies) {
    try {
      if (spec.mode === 'text') {
        opts.input.body = await readFile(spec.path, 'utf8');
        delete opts.input.bodyBase64;
      } else {
        const buf = await readFile(spec.path);
        opts.input.bodyBase64 = buf.toString('base64');
        delete opts.input.body;
      }
    } catch (error) {
      process.stderr.write(`error: cannot read body file "${spec.path}": ${(error as Error).message}\n`);
      return 2;
    }
  }

  // Optional JSON config file is merged UNDER the CLI flags (flags win).
  if (opts.jsonConfigFile) {
    try {
      const parsed = JSON.parse(await readFile(opts.jsonConfigFile, 'utf8')) as Partial<HttpDebugConfig>;
      opts.config = mergeConfig(parsed, opts.config);
    } catch (error) {
      process.stderr.write(`error: cannot load config file: ${(error as Error).message}\n`);
      return 2;
    }
  }

  if (opts.input.bypassSsfr) {
    process.stderr.write('warning: --allow-private disables SSRF protection for this request\n');
  }

  const service = new HttpDebug({ config: opts.config });

  let result: HttpResponse;
  try {
    result = await service.request(opts.input);
  } catch (error) {
    const code = error instanceof HttpDebugError ? error.code : 'ERROR';
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`error: [${code}] ${message}\n`);
    return code === 'INVALID_URL' || code === 'UNSUPPORTED_PROTOCOL' ? 2 : 3;
  }

  if (opts.harFile) {
    // HAR captures the ORIGINAL request (pre-redirect method/body), plus the
    // final response.
    const har = buildHarLog(
      {
        method: (opts.input.method ?? 'GET').toUpperCase(),
        url: opts.input.url ?? result.url,
        headers: opts.input.headers ?? {},
        body: opts.input.body ?? opts.input.bodyBase64,
        bodyEncoding:
          opts.input.body !== undefined ? 'text' : opts.input.bodyBase64 !== undefined ? 'base64' : undefined,
      },
      {
        status: result.status,
        statusText: result.statusText,
        headers: result.headers,
        contentType: result.contentType,
        body: result.body,
        bodyEncoding: result.bodyEncoding,
        bodySizeBytes: result.bodySizeBytes,
      },
      { durationMs: result.durationMs },
    );
    try {
      await writeFile(opts.harFile, JSON.stringify(har, null, 2), 'utf8');
    } catch (error) {
      process.stderr.write(`error: cannot write HAR file: ${(error as Error).message}\n`);
      return 3;
    }
  }

  if (opts.raw) {
    process.stdout.write(result.body);
    if (result.bodyEncoding === 'none' || (result.body && !result.body.endsWith('\n'))) process.stdout.write('\n');
  } else {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  }
  return 0;
}

try {
  process.exitCode = await runCli(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`error: ${message}\n`);
  process.stderr.write('run "dsh-http-debug --help" for usage\n');
  process.exitCode = 2;
}
