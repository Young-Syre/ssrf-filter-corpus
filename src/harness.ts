/**
 * Scoring a filter against the corpus.
 *
 * The two numbers that matter are not symmetric. A **bypass** is an entry the corpus
 * expects blocked that your filter allowed: that is a reachable internal
 * destination. An **over-block** is a public destination your filter refused: that
 * is a broken feature. Both are reported, separately, because they are fixed by
 * different changes — and a filter with zero bypasses because it blocks everything
 * is not a passing filter.
 *
 * `needs-resolution` entries are not scored. A lexical filter has no basis to decide
 * them, so neither answer is a failure; the count of those a filter chose to block
 * is reported as `deferredBlocked`, which tells you whether it is deny-by-default.
 */

import { CORPUS, type Category, type CorpusEntry } from './corpus.js';

/** A filter under test. Returns true if it would block the URL. */
export type FilterFn = (url: string) => boolean | Promise<boolean>;

export type Outcome =
  /** Filter agreed with the corpus. */
  | 'pass'
  /** Expected block, filter allowed — a reachable internal destination. */
  | 'bypass'
  /** Expected allow, filter blocked — a broken legitimate fetch. */
  | 'over-block'
  /** `needs-resolution` entry: not scored. */
  | 'deferred'
  /** The filter threw. Counted as a failure, because a crash is not a deny. */
  | 'error';

export interface EntryResult {
  entry: CorpusEntry;
  /** What the filter answered, or null if it threw. */
  blocked: boolean | null;
  outcome: Outcome;
  /** Message from the filter if it threw. */
  error?: string;
}

export interface CategoryStats {
  category: Category;
  total: number;
  passed: number;
  bypasses: number;
  overBlocks: number;
  deferred: number;
  errors: number;
}

export interface CorpusReport {
  /** Entries run, after any `categories`/`ids` selection. */
  total: number;
  /** Scored entries the filter got right. */
  passed: number;
  /** Scored entries, i.e. `total` minus deferred. */
  scored: number;
  bypasses: EntryResult[];
  overBlocks: EntryResult[];
  errors: EntryResult[];
  /** `needs-resolution` entries, which are not scored. */
  skipped: EntryResult[];
  /** How many skipped entries the filter blocked anyway — informational. */
  deferredBlocked: number;
  byCategory: CategoryStats[];
  results: EntryResult[];
  durationMs: number;
}

export interface RunOptions {
  /** Restrict the run to these categories. */
  categories?: readonly Category[];
  /** Restrict the run to these entry ids. */
  ids?: readonly string[];
  /** Called after each entry — for progress output on slow (probing) filters. */
  onResult?: (result: EntryResult) => void;
}

/**
 * Run `filter` over the corpus and score it.
 *
 * Entries are run one at a time and awaited. That is deliberate: a filter wired to
 * a live endpoint should not fan out dozens of parallel requests at a target you
 * were given permission to test gently.
 */
export async function runCorpus(filter: FilterFn, opts: RunOptions = {}): Promise<CorpusReport> {
  const started = Date.now();
  const selected = CORPUS.filter(
    (e) =>
      (!opts.categories || opts.categories.includes(e.category)) &&
      (!opts.ids || opts.ids.includes(e.id)),
  );

  const results: EntryResult[] = [];
  for (const entry of selected) {
    let result: EntryResult;
    try {
      const blocked = await filter(entry.input);
      result = { entry, blocked, outcome: outcomeFor(entry, blocked) };
    } catch (err) {
      result = {
        entry,
        blocked: null,
        outcome: 'error',
        error: err instanceof Error ? err.message : String(err),
      };
    }
    results.push(result);
    opts.onResult?.(result);
  }

  const of = (outcome: Outcome) => results.filter((r) => r.outcome === outcome);
  const skipped = of('deferred');
  const scored = results.length - skipped.length;

  const categories = [...new Set(selected.map((e) => e.category))];
  const byCategory: CategoryStats[] = categories.map((category) => {
    const rows = results.filter((r) => r.entry.category === category);
    const count = (outcome: Outcome) => rows.filter((r) => r.outcome === outcome).length;
    return {
      category,
      total: rows.length,
      passed: count('pass'),
      bypasses: count('bypass'),
      overBlocks: count('over-block'),
      deferred: count('deferred'),
      errors: count('error'),
    };
  });

  return {
    total: results.length,
    passed: of('pass').length,
    scored,
    bypasses: of('bypass'),
    overBlocks: of('over-block'),
    errors: of('error'),
    skipped,
    deferredBlocked: skipped.filter((r) => r.blocked === true).length,
    byCategory,
    results,
    durationMs: Date.now() - started,
  };
}

function outcomeFor(entry: CorpusEntry, blocked: boolean): Outcome {
  if (entry.expect === 'needs-resolution') return 'deferred';
  if (entry.expect === 'block') return blocked ? 'pass' : 'bypass';
  return blocked ? 'over-block' : 'pass';
}

/** Render a report as aligned plain text. */
export function formatReport(report: CorpusReport, name = 'filter'): string {
  const out: string[] = [];
  const pct = report.scored === 0 ? 0 : Math.round((report.passed / report.scored) * 1000) / 10;

  out.push(`ssrf-filter-corpus — ${name}`);
  out.push('');
  out.push(`  ${report.passed}/${report.scored} scored entries passed (${pct}%)`);
  out.push(`  ${report.bypasses.length} bypasses   ${report.overBlocks.length} over-blocks   ${report.errors.length} errors`);
  out.push(`  ${report.skipped.length} needs-resolution (not scored; ${report.deferredBlocked} blocked by this filter)`);
  out.push(`  ${report.total} entries in ${report.durationMs}ms`);
  out.push('');

  const head = ['category', 'n', 'pass', 'bypass', 'over', 'defer'];
  const rows = report.byCategory.map((c) => [
    c.category,
    String(c.total),
    String(c.passed),
    String(c.bypasses),
    String(c.overBlocks),
    String(c.deferred),
  ]);
  out.push(...table(head, rows, '  '));

  if (report.bypasses.length > 0) {
    out.push('');
    out.push('  BYPASSES — expected block, filter allowed:');
    out.push(...detail(report.bypasses));
  }
  if (report.overBlocks.length > 0) {
    out.push('');
    out.push('  OVER-BLOCKS — legitimate public destination refused:');
    out.push(...detail(report.overBlocks));
  }
  if (report.errors.length > 0) {
    out.push('');
    out.push('  ERRORS — filter threw instead of answering:');
    out.push(...report.errors.map((r) => `    ${r.entry.id}  ${r.entry.input}  (${r.error})`));
  }
  out.push('');
  return out.join('\n');
}

function detail(results: readonly EntryResult[]): string[] {
  const rows = results.map((r) => [r.entry.id, r.entry.input, r.entry.normalisedHost ?? '(unparseable)']);
  return table(['id', 'input', 'normalises to'], rows, '    ');
}

/** Pad columns to the widest cell and underline the header. */
function table(head: readonly string[], rows: readonly string[][], indent: string): string[] {
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const line = (cells: readonly string[]) =>
    indent + cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join('  ').trimEnd();
  return [line(head), line(widths.map((w) => '-'.repeat(w))), ...rows.map(line)];
}
