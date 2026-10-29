import test from 'node:test';
import assert from 'node:assert/strict';

import { CORPUS, CATEGORIES, byCategory, entryById } from '../src/corpus.js';
import { classifyTarget } from '../src/classify.js';

test('entry ids are unique and usable as identifiers', () => {
  const seen = new Set<string>();
  for (const entry of CORPUS) {
    assert.ok(!seen.has(entry.id), `duplicate id ${entry.id}`);
    seen.add(entry.id);
    assert.match(entry.id, /^[a-z0-9]+(-[a-z0-9]+)*$/, `${entry.id} is not kebab-case`);
  }
  assert.equal(seen.size, CORPUS.length);
});

test('every entry declares a known category and a rationale', () => {
  for (const entry of CORPUS) {
    assert.ok(CATEGORIES.includes(entry.category), `${entry.id}: unknown category`);
    assert.ok(entry.rationale.length > 40, `${entry.id}: rationale is too thin to be useful`);
    assert.ok(entry.rationale.endsWith('.'), `${entry.id}: rationale should be a sentence`);
  }
});

test('every declared category has at least one entry', () => {
  for (const category of CATEGORIES) {
    assert.ok(byCategory(category).length > 0, `${category} has no entries`);
  }
});

// The important test in this file: the corpus claims what the parser actually
// produces, re-derived here rather than trusted.
test('every normalisedHost matches what new URL() produces on this runtime', () => {
  let checked = 0;
  for (const entry of CORPUS) {
    if (entry.normalisedHost === undefined) continue;
    const actual = new URL(entry.input).hostname.replace(/^\[|\]$/g, '');
    assert.equal(
      actual,
      entry.normalisedHost,
      `${entry.id}: corpus says ${entry.normalisedHost}, parser says ${actual}`,
    );
    checked++;
  }
  assert.ok(checked > 100, `expected to verify over 100 hosts, verified ${checked}`);
});

test('entries without a normalisedHost are exactly the ones that do not parse', () => {
  for (const entry of CORPUS) {
    const parses = URL.canParse(entry.input);
    assert.equal(
      parses,
      entry.normalisedHost !== undefined,
      `${entry.id}: parseability and normalisedHost disagree`,
    );
  }
});

test('unparseable entries are expected to be blocked, never allowed', () => {
  for (const entry of CORPUS) {
    if (entry.normalisedHost === undefined) {
      assert.equal(entry.expect, 'block', `${entry.id}: a filter must fail closed here`);
    }
  }
});

test('the reference implementation agrees with every expectation', () => {
  for (const entry of CORPUS) {
    const verdict = classifyTarget(entry.input);
    assert.equal(
      verdict.verdict,
      entry.expect,
      `${entry.id} (${entry.input}): expected ${entry.expect}, reference said ${verdict.verdict}`,
    );
  }
});

test('block verdicts carry a reason naming what matched', () => {
  for (const entry of CORPUS) {
    const verdict = classifyTarget(entry.input);
    if (verdict.verdict !== 'block') continue;
    assert.ok(verdict.reason.length > 20, `${entry.id}: reason is not explanatory`);
  }
});

test('the corpus covers both halves of the problem, not just the attacks', () => {
  const counts = {
    block: CORPUS.filter((e) => e.expect === 'block').length,
    allow: CORPUS.filter((e) => e.expect === 'allow').length,
    defer: CORPUS.filter((e) => e.expect === 'needs-resolution').length,
  };
  assert.ok(counts.block >= 55, `only ${counts.block} block cases`);
  assert.ok(counts.allow >= 8, `only ${counts.allow} allow cases — over-blocking would go undetected`);
  assert.ok(counts.defer >= 4, `only ${counts.defer} needs-resolution cases`);
});

test('the IPv6 categories each contain at least one case a textual filter misses', () => {
  for (const category of ['ipv6-v4mapped', 'ipv6-v4compatible', 'ipv6-nat64', 'ipv6-6to4'] as const) {
    const entries = byCategory(category).filter((e) => e.expect === 'block');
    assert.ok(entries.length > 0, `${category} has no blocking cases`);
    for (const entry of entries) {
      // Assert the host is recorded before asserting what it is not:
      // `!undefined?.includes(x)` is true, so an entry with no recorded host
      // passed this test without being checked.
      assert.notEqual(entry.normalisedHost, undefined, `${entry.id}: no normalisedHost recorded`);
      const host = entry.normalisedHost!;
      assert.ok(
        !host.includes('127.') && !host.includes('169.254'),
        `${entry.id}: normalises to ${host}, which a grep would still catch`,
      );
    }
  }
});

test('entryById finds entries and returns undefined otherwise', () => {
  assert.equal(entryById('ipv6-v4mapped-loopback')?.normalisedHost, '::ffff:7f00:1');
  assert.equal(entryById('no-such-entry'), undefined);
});
