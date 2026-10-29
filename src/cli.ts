#!/usr/bin/env node
/**
 * ssrf-corpus — browse the corpus, score the reference filter, or probe an endpoint
 * you are authorised to test.
 *
 * No argument-parsing dependency: the surface is three commands and a dozen flags,
 * which is less code to read than a parser's documentation.
 */

import { CATEGORIES, CORPUS, type Category, type CorpusEntry } from './corpus.js';
import { classifyTarget, referenceFilter } from './classify.js';
import { formatReport, runCorpus, type FilterFn } from './harness.js';

const USAGE = `ssrf-corpus — test corpus for SSRF destination filters

USAGE
  ssrf-corpus list [--category <name>] [--expect block|allow|needs-resolution] [--json]
  ssrf-corpus self-test [--category <name>] [--json]
  ssrf-corpus probe --target <url-template> --yes [options]
  ssrf-corpus categories

COMMANDS
  list        Print corpus entries, with the host each one normalises to.
  self-test   Score the bundled reference filter against the corpus. Must be 100%.
  probe       Substitute each corpus input into a URL template, send the request,
              and infer from the response whether the endpoint blocked it.
  categories  List category names and entry counts.

PROBE OPTIONS
  --target <tmpl>     Required. URL containing {{URL}}, e.g.
                      'https://app.example.test/api/fetch?url={{URL}}'
  --yes               Required. Confirms you are authorised to test this endpoint.
  --block-on <rule>   How to read a response (default: status)
                        status           any status >= 400 means blocked
                        status:403,422   exactly these statuses mean blocked
                        body:<regex>     a matching response body means blocked
  --method <verb>     HTTP method for the probe request (default: GET)
  --header <k: v>     Extra request header. Repeatable.
  --raw               Insert inputs without percent-encoding them.
  --timeout <ms>      Per-request timeout (default: 10000)
  --delay <ms>        Pause between requests (default: 0)
  --category <name>   Probe only one category.
  --json              Machine-readable output.

EXIT CODES
  0  no bypasses   1  bypasses or errors found   2  bad usage
`;

interface Args {
  positional: string[];
  values: Map<string, string[]>;
  flags: Set<string>;
}

function parseArgs(argv: readonly string[]): Args {
  const positional: string[] = [];
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  // Flags that take a value; anything else starting with -- is boolean.
  const withValue = new Set([
    'category',
    'expect',
    'target',
    'block-on',
    'method',
    'header',
    'timeout',
    'delay',
  ]);

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith('-')) {
      positional.push(arg);
      continue;
    }
    const name = arg.replace(/^--?/, '');
    const eq = name.indexOf('=');
    if (eq !== -1) {
      push(values, name.slice(0, eq), name.slice(eq + 1));
      continue;
    }
    if (withValue.has(name)) {
      const next = argv[i + 1];
      if (next === undefined) fail(`--${name} needs a value`);
      push(values, name, next);
      i++;
      continue;
    }
    flags.add(name);
  }
  return { positional, values, flags };
}

function push(map: Map<string, string[]>, key: string, value: string): void {
  const existing = map.get(key);
  if (existing) existing.push(value);
  else map.set(key, [value]);
}

function one(args: Args, key: string): string | undefined {
  return args.values.get(key)?.at(-1);
}

function fail(message: string): never {
  process.stderr.write(`ssrf-corpus: ${message}\n`);
  process.exit(2);
}

function selectCategory(args: Args): Category | undefined {
  const raw = one(args, 'category');
  if (raw === undefined) return undefined;
  const match = CATEGORIES.find((c) => c === raw);
  if (!match) fail(`unknown category "${raw}" — run 'ssrf-corpus categories'`);
  return match;
}

// ── list ───────────────────────────────────────────────────────────────────────

function cmdList(args: Args): number {
  const category = selectCategory(args);
  const expect = one(args, 'expect');
  if (expect && !['block', 'allow', 'needs-resolution'].includes(expect)) {
    fail(`--expect must be block, allow or needs-resolution`);
  }
  const entries = CORPUS.filter(
    (e) => (!category || e.category === category) && (!expect || e.expect === expect),
  );
  if (entries.length === 0) fail('no entries match that selection');

  if (args.flags.has('json')) {
    process.stdout.write(JSON.stringify(entries, null, 2) + '\n');
    return 0;
  }
  for (const entry of entries) {
    process.stdout.write(renderEntry(entry));
  }
  process.stdout.write(`${entries.length} entries\n`);
  return 0;
}

function renderEntry(entry: CorpusEntry): string {
  const verdict = classifyTarget(entry.input);
  const detail =
    verdict.verdict === 'block'
      ? verdict.reason
      : verdict.verdict === 'allow'
        ? `${verdict.host} is globally routable`
        : `${verdict.host} must be resolved before it can be judged`;
  return [
    `${entry.id}  [${entry.category}]  expect ${entry.expect}`,
    `  input       ${entry.input}`,
    `  normalises  ${entry.normalisedHost ?? '(does not parse)'}`,
    `  reference   ${verdict.verdict} — ${detail}`,
    `  why         ${entry.rationale}`,
    '',
  ].join('\n');
}

// ── categories ─────────────────────────────────────────────────────────────────

function cmdCategories(): number {
  const width = Math.max(...CATEGORIES.map((c) => c.length));
  for (const category of CATEGORIES) {
    const entries = CORPUS.filter((e) => e.category === category);
    const blocks = entries.filter((e) => e.expect === 'block').length;
    const allows = entries.filter((e) => e.expect === 'allow').length;
    const defer = entries.filter((e) => e.expect === 'needs-resolution').length;
    process.stdout.write(
      `${category.padEnd(width)}  ${String(entries.length).padStart(3)} entries` +
        `  (${blocks} block, ${allows} allow, ${defer} needs-resolution)\n`,
    );
  }
  process.stdout.write(`\n${CORPUS.length} entries in ${CATEGORIES.length} categories\n`);
  return 0;
}

// ── self-test ──────────────────────────────────────────────────────────────────

async function cmdSelfTest(args: Args): Promise<number> {
  const category = selectCategory(args);
  const report = await runCorpus(referenceFilter, category ? { categories: [category] } : {});
  if (args.flags.has('json')) {
    process.stdout.write(JSON.stringify(summarise(report), null, 2) + '\n');
  } else {
    process.stdout.write(formatReport(report, 'reference implementation (src/classify.ts)'));
  }
  const clean =
    report.bypasses.length === 0 && report.overBlocks.length === 0 && report.errors.length === 0;
  return clean ? 0 : 1;
}

function summarise(report: Awaited<ReturnType<typeof runCorpus>>) {
  return {
    total: report.total,
    scored: report.scored,
    passed: report.passed,
    bypasses: report.bypasses.map((r) => ({ id: r.entry.id, input: r.entry.input })),
    overBlocks: report.overBlocks.map((r) => ({ id: r.entry.id, input: r.entry.input })),
    errors: report.errors.map((r) => ({ id: r.entry.id, error: r.error })),
    skipped: report.skipped.length,
    deferredBlocked: report.deferredBlocked,
    byCategory: report.byCategory,
    durationMs: report.durationMs,
  };
}

// ── probe ──────────────────────────────────────────────────────────────────────

const AUTHORISATION_WARNING = banner([
  'PROBE MODE SENDS LIVE REQUESTS',
  '',
  'Every corpus entry becomes a real request to the target you name. Those',
  'requests ask it to fetch loopback, private-range and cloud metadata',
  'addresses. Against a system you do not have written permission to test,',
  'that is unauthorised access, and it will look exactly like an attack in',
  "the target's logs \u2014 because it is one.",
  '',
  'Run this only against your own service, or one whose owner has',
  'authorised the test, in writing and in scope.',
]);

/** Box-draw a block of text, measuring in codepoints so the borders line up. */
function banner(lines: readonly string[]): string {
  const width = Math.max(...lines.map((line) => [...line].length));
  const bar = '\u2500'.repeat(width + 2);
  const body = lines.map(
    (line) => `  \u2502 ${line}${' '.repeat(width - [...line].length)} \u2502`,
  );
  return ['', `  \u250c${bar}\u2510`, ...body, `  \u2514${bar}\u2518`, ''].join('\n') + '\n';
}

type BlockRule = (status: number, body: string) => boolean;

function parseBlockRule(raw: string | undefined): BlockRule {
  const rule = raw ?? 'status';
  if (rule === 'status') return (status) => status >= 400;
  if (rule.startsWith('status:')) {
    const codes = new Set(
      rule
        .slice('status:'.length)
        .split(',')
        .map((c) => Number(c.trim())),
    );
    for (const code of codes) {
      if (!Number.isInteger(code)) fail(`--block-on status: expects a comma-separated list of status codes`);
    }
    return (status) => codes.has(status);
  }
  if (rule.startsWith('body:')) {
    const pattern = rule.slice('body:'.length);
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, 'i');
    } catch (err) {
      fail(`--block-on body: invalid regex (${err instanceof Error ? err.message : String(err)})`);
    }
    return (_status, body) => regex.test(body);
  }
  return fail(`--block-on must be "status", "status:<codes>" or "body:<regex>"`);
}

function parseHeaders(args: Args): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const raw of args.values.get('header') ?? []) {
    const split = raw.indexOf(':');
    if (split === -1) fail(`--header must look like 'Name: value' (got "${raw}")`);
    headers[raw.slice(0, split).trim()] = raw.slice(split + 1).trim();
  }
  return headers;
}

async function cmdProbe(args: Args): Promise<number> {
  const target = one(args, 'target');
  if (!target) fail("probe needs --target '<url with {{URL}}>'");
  if (!target.includes('{{URL}}')) fail('--target must contain the {{URL}} placeholder');

  process.stderr.write(AUTHORISATION_WARNING);
  if (!args.flags.has('yes')) {
    fail('refusing to probe without --yes (see the warning above)');
  }

  const category = selectCategory(args);
  const isBlocked = parseBlockRule(one(args, 'block-on'));
  const headers = parseHeaders(args);
  const method = (one(args, 'method') ?? 'GET').toUpperCase();
  const timeout = Number(one(args, 'timeout') ?? 10_000);
  const delay = Number(one(args, 'delay') ?? 0);
  if (!Number.isFinite(timeout) || timeout <= 0) fail('--timeout must be a positive number of ms');
  if (!Number.isFinite(delay) || delay < 0) fail('--delay must be a non-negative number of ms');
  const encode = args.flags.has('raw') ? (s: string) => s : encodeURIComponent;

  const probe: FilterFn = async (input) => {
    const url = target.replaceAll('{{URL}}', encode(input));
    const response = await fetch(url, {
      method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeout),
    });
    const body = await response.text();
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    return isBlocked(response.status, body);
  };

  const quiet = args.flags.has('json');
  const report = await runCorpus(probe, {
    ...(category ? { categories: [category] } : {}),
    onResult: (result) => {
      if (quiet) return;
      const mark = { pass: 'ok  ', bypass: 'BYPASS', 'over-block': 'OVER', deferred: '--  ', error: 'ERR ' }[
        result.outcome
      ];
      process.stderr.write(`  ${mark}  ${result.entry.id}\n`);
    },
  });

  if (quiet) {
    process.stdout.write(JSON.stringify(summarise(report), null, 2) + '\n');
  } else {
    process.stdout.write('\n' + formatReport(report, `probe ${target}`));
  }
  return report.bypasses.length > 0 || report.errors.length > 0 ? 1 : 0;
}

// ── entry point ────────────────────────────────────────────────────────────────

async function main(argv: readonly string[]): Promise<number> {
  const args = parseArgs(argv);
  const command = args.positional[0];
  if (args.flags.has('help') || args.flags.has('h') || command === undefined) {
    process.stdout.write(USAGE);
    return command === undefined ? 2 : 0;
  }
  switch (command) {
    case 'list':
      return cmdList(args);
    case 'categories':
      return cmdCategories();
    case 'self-test':
      return cmdSelfTest(args);
    case 'probe':
      return cmdProbe(args);
    default:
      process.stderr.write(`ssrf-corpus: unknown command "${command}"\n\n${USAGE}`);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`ssrf-corpus: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
