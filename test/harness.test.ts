import test from 'node:test';
import assert from 'node:assert/strict';

import { CORPUS, type Category } from '../src/corpus.js';
import { referenceFilter } from '../src/classify.js';
import { runCorpus, formatReport } from '../src/harness.js';

/**
 * The filter almost everyone writes first. It does the right thing by parsing, and
 * then throws it away by string-matching the two hosts it has heard of. It is in
 * the test suite because the corpus has to be able to prove it is broken — and the
 * entry it misses most instructively is `[::ffff:127.0.0.1]`, whose hostname comes
 * back from the parser as `::ffff:7f00:1`.
 */
function naiveFilter(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false; // fails open on input it cannot parse, which is its own finding
  }
  return host.includes('127.0.0.1') || host.includes('localhost');
}

test('the reference implementation scores 100% with no bypasses or over-blocks', async () => {
  const report = await runCorpus(referenceFilter);
  assert.equal(report.total, CORPUS.length);
  assert.equal(report.bypasses.length, 0, 'reference implementation must not be bypassable');
  assert.equal(report.overBlocks.length, 0, 'reference implementation must not over-block');
  assert.equal(report.errors.length, 0);
  assert.equal(report.passed, report.scored);
  assert.equal(report.skipped.length, CORPUS.filter((e) => e.expect === 'needs-resolution').length);
  assert.equal(report.deferredBlocked, 0, 'it defers rather than blocking undecidable names');
});

test('the naive string filter is caught, with 73 bypasses', async () => {
  const report = await runCorpus(naiveFilter);
  assert.equal(report.bypasses.length, 73);
  assert.equal(report.overBlocks.length, 0, 'it is too narrow to over-block a public literal');

  const bypassed = new Set(report.bypasses.map((r) => r.entry.id));
  // The headline failures: addresses that reach loopback or metadata with neither
  // string anywhere in the parsed hostname.
  for (const id of [
    'ipv6-v4mapped-loopback',
    'ipv6-v4compat-loopback',
    'ipv6-nat64-loopback',
    'ipv6-6to4-loopback',
    'ipv6-loopback-short',
    'ipv4-loopback-high',
    'ipv4-short-zero',
    'linklocal-aws-imds-creds',
    'metadata-gcp-token',
    'metadata-aws-ipv6',
    'trailing-dot-double-metadata',
    'malformed-ipv6-zone-id',
  ]) {
    assert.ok(bypassed.has(id), `${id} should have been a bypass for the naive filter`);
  }
});

// This is the project's central claim, as a test. A filter that parses before it
// compares needs no IPv4 deobfuscation of its own: the parser has already done it.
// Every one of these inputs is a classic "SSRF bypass" payload, and the two-string
// filter stops all of them — which is why IPv4 obfuscation is not where the bugs are.
test('the naive filter still catches every IPv4 obfuscation of loopback', async () => {
  const report = await runCorpus(naiveFilter);
  const caught = new Set(
    report.results.filter((r) => r.outcome === 'pass').map((r) => r.entry.id),
  );
  for (const id of [
    'ipv4-dec-loopback',
    'ipv4-oct-loopback',
    'ipv4-oct-loopback-flat',
    'ipv4-hex-loopback-mixed',
    'ipv4-hex-loopback-flat',
    'ipv4-short-127-1',
    'ipv4-short-mixed-radix',
    'trailing-dot-loopback',
    'userinfo-at-loopback',
    'userinfo-backslash-terminates-authority',
    'idn-fullwidth-loopback',
    'idn-circled-letter-localhost',
    'alias-localhost-uppercase',
  ]) {
    assert.ok(caught.has(id), `${id} should have been caught — the parser normalises it`);
  }
});

test('the naive filter also blocks destinations it has no business blocking', async () => {
  const report = await runCorpus(naiveFilter);
  // It matches the substring inside a hostname that is not an address at all.
  assert.ok(report.deferredBlocked > 0, 'substring matching blocks resolvable public names');
  const blockedDeferred = report.skipped.filter((r) => r.blocked === true).map((r) => r.entry.id);
  assert.ok(
    blockedDeferred.includes('rebinding-nip-io-loopback'),
    'a public hostname containing the substring 127.0.0.1 is refused on sight',
  );
});

test('a block-everything filter has no bypasses and fails anyway', async () => {
  const report = await runCorpus(() => true);
  assert.equal(report.bypasses.length, 0);
  assert.equal(report.overBlocks.length, CORPUS.filter((e) => e.expect === 'allow').length);
  assert.ok(report.overBlocks.length >= 8, 'over-blocking must be visible, not just bypasses');
  assert.equal(report.deferredBlocked, report.skipped.length);
});

test('an allow-everything filter bypasses every blocking entry', async () => {
  const report = await runCorpus(() => false);
  assert.equal(report.bypasses.length, CORPUS.filter((e) => e.expect === 'block').length);
  assert.equal(report.overBlocks.length, 0);
});

test('a filter that throws is recorded as an error, not as a deny', async () => {
  const report = await runCorpus((url) => {
    if (url.includes('[')) throw new Error('cannot handle IPv6');
    return referenceFilter(url);
  });
  assert.ok(report.errors.length > 0);
  assert.equal(
    report.errors.every((r) => r.blocked === null && r.error === 'cannot handle IPv6'),
    true,
  );
  assert.ok(report.passed < report.scored, 'errors must not be counted as passes');
});

test('async filters are awaited', async () => {
  const report = await runCorpus(async (url) => {
    await new Promise((resolve) => setImmediate(resolve));
    return referenceFilter(url);
  });
  assert.equal(report.bypasses.length, 0);
  assert.equal(report.passed, report.scored);
});

test('runCorpus narrows by category and by id', async () => {
  const categories: Category[] = ['ipv6-v4mapped', 'cloud-metadata'];
  const byCat = await runCorpus(referenceFilter, { categories });
  assert.equal(byCat.total, CORPUS.filter((e) => categories.includes(e.category)).length);
  assert.deepEqual([...new Set(byCat.byCategory.map((c) => c.category))].sort(), [...categories].sort());

  const byId = await runCorpus(referenceFilter, { ids: ['ipv4-dec-loopback', 'public-google-dns'] });
  assert.equal(byId.total, 2);
  assert.equal(byId.passed, 2);
});

test('onResult is called once per entry, in corpus order', async () => {
  const seen: string[] = [];
  const report = await runCorpus(referenceFilter, { onResult: (r) => seen.push(r.entry.id) });
  assert.equal(seen.length, report.total);
  assert.deepEqual(seen, CORPUS.map((e) => e.id));
});

test('per-category totals add up to the whole run', async () => {
  const report = await runCorpus(naiveFilter);
  const sum = (key: 'total' | 'passed' | 'bypasses' | 'overBlocks' | 'deferred') =>
    report.byCategory.reduce((n, c) => n + c[key], 0);
  assert.equal(sum('total'), report.total);
  assert.equal(sum('passed'), report.passed);
  assert.equal(sum('bypasses'), report.bypasses.length);
  assert.equal(sum('overBlocks'), report.overBlocks.length);
  assert.equal(sum('deferred'), report.skipped.length);
});

test('formatReport prints the counts and names the bypassed entries', async () => {
  const report = await runCorpus(naiveFilter);
  const text = formatReport(report, 'naive filter');
  assert.match(text, /naive filter/);
  assert.match(text, /73 bypasses/);
  assert.match(text, /BYPASSES/);
  assert.match(text, /ipv6-v4mapped-loopback/);
  assert.ok(!text.includes('OVER-BLOCKS'), 'no over-blocks, so no over-block section');

  const clean = formatReport(await runCorpus(referenceFilter), 'reference');
  assert.match(clean, /0 bypasses/);
  assert.ok(!clean.includes('BYPASSES'), 'a clean run prints no failure sections');
});
