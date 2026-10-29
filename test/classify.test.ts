import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyTarget, isPrivateIPv4, ipv4Reservation, ipv4ToInt } from '../src/classify.js';

test('ipv4ToInt packs octets and rejects non-addresses', () => {
  assert.equal(ipv4ToInt('0.0.0.0'), 0);
  assert.equal(ipv4ToInt('127.0.0.1'), 0x7f000001);
  assert.equal(ipv4ToInt('169.254.169.254'), 0xa9fea9fe, 'must stay unsigned above 128.0.0.0');
  assert.equal(ipv4ToInt('255.255.255.255'), 0xffffffff);
  assert.equal(ipv4ToInt('0x7f000001'), null);
});

test('isPrivateIPv4 covers every reserved range this filter claims', () => {
  for (const address of [
    '0.0.0.0',
    '0.255.255.255',
    '10.0.0.1',
    '10.255.255.255',
    '100.64.0.0',
    '100.100.100.200',
    '100.127.255.255',
    '127.0.0.1',
    '127.255.255.254',
    '169.254.0.1',
    '169.254.169.254',
    '172.16.0.0',
    '172.31.255.255',
    '192.168.0.1',
    '198.18.0.0',
    '198.19.255.255',
    '224.0.0.1',
    '239.255.255.250',
    '255.255.255.255',
  ]) {
    assert.equal(isPrivateIPv4(address), true, `${address} must be treated as reserved`);
  }
});

test('isPrivateIPv4 leaves public addresses alone, including range boundaries', () => {
  for (const address of [
    '1.0.0.0',
    '1.1.1.1',
    '8.8.8.8',
    '9.255.255.255',
    '11.0.0.0',
    '100.63.255.255',
    '100.128.0.0',
    '126.255.255.255',
    '128.0.0.1',
    '169.253.255.255',
    '169.255.0.0',
    '172.15.255.255',
    '172.32.0.0',
    '192.167.255.255',
    '192.169.0.0',
    '198.17.255.255',
    '198.20.0.0',
    '223.255.255.255',
    '240.0.0.1',
    '255.255.255.254',
  ]) {
    assert.equal(isPrivateIPv4(address), false, `${address} is globally routable and must be allowed`);
  }
});

test('ipv4Reservation names the range that matched', () => {
  assert.equal(ipv4Reservation('169.254.169.254')?.cidr, '169.254.0.0/16');
  assert.equal(ipv4Reservation('100.100.100.200')?.category, 'cgnat');
  assert.equal(ipv4Reservation('172.20.0.1')?.cidr, '172.16.0.0/12');
  assert.equal(ipv4Reservation('8.8.8.8'), null);
});

test('classifyTarget blocks obfuscated IPv4 because the parser already decoded it', () => {
  for (const url of [
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://0x7f000001/',
    'http://127.1/',
    'http://0/',
    'http://127.0.0.1./',
  ]) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict, 'block', `${url} must be blocked`);
  }
});

test('classifyTarget blocks IPv6 carrying a private IPv4, in every transition form', () => {
  const cases: Record<string, string> = {
    'http://[::ffff:127.0.0.1]/': 'loopback',
    'http://[::127.0.0.1]/': 'loopback',
    'http://[64:ff9b::127.0.0.1]/': 'loopback',
    'http://[2002:7f00:1::1]/': 'loopback',
    'http://[::ffff:169.254.169.254]/': 'link-local',
    'http://[2002:a9fe:a9fe::]/': 'link-local',
  };
  for (const [url, category] of Object.entries(cases)) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict, 'block', `${url} must be blocked`);
    assert.equal(verdict.verdict === 'block' && verdict.category, category);
  }
});

test('classifyTarget blocks IPv6 ranges that carry no IPv4 at all', () => {
  const cases: Record<string, string> = {
    'http://[::1]/': 'loopback',
    'http://[::]/': 'unspecified',
    'http://[fc00::1]/': 'ipv6-ula',
    'http://[fd00:ec2::254]/': 'ipv6-ula',
    'http://[fe80::1]/': 'ipv6-link-local',
    'http://[ff02::1]/': 'ipv6-multicast',
    'http://[::ffff:0:7f00:1]/': 'ipv6-reserved',
  };
  for (const [url, category] of Object.entries(cases)) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict === 'block' && verdict.category, category, `${url}`);
  }
});

test('classifyTarget allows public destinations, v4-mapped and 6to4 ones included', () => {
  for (const url of [
    'http://8.8.8.8/',
    'http://1.1.1.1/',
    'http://172.32.0.1/',
    'http://[2606:4700:4700::1111]/',
    'http://[::ffff:8.8.8.8]/',
    'http://[2002:808:808::1]/',
    'http://[64:ff9b::8.8.8.8]/',
  ]) {
    assert.equal(classifyTarget(url).verdict, 'allow', `${url} must be allowed`);
  }
});

test('classifyTarget blocks local and metadata names, with their subdomains', () => {
  for (const url of [
    'http://localhost/',
    'http://LOCALHOST/',
    'http://localhost./',
    'http://foo.localhost/',
    'http://api.staging.localhost/',
    'http://metadata.google.internal/',
    'http://metadata.google.internal./',
    'http://metadata.goog/',
    'http://instance-data/',
    'http://instance-data.ec2.internal/',
  ]) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict, 'block', `${url} must be blocked`);
    assert.equal(verdict.verdict === 'block' && verdict.category, 'dangerous-name');
  }
});

test('classifyTarget re-tests a host the parser left as a domain after trailing dots', () => {
  const verdict = classifyTarget('http://169.254.169.254../');
  assert.equal(verdict.verdict, 'block');
  assert.equal(verdict.verdict === 'block' && verdict.category, 'link-local');
});

test('classifyTarget defers names it cannot decide instead of guessing', () => {
  for (const [url, host] of [
    ['http://example.com/', 'example.com'],
    ['http://localtest.me/', 'localtest.me'],
    ['http://127.0.0.1.nip.io/', '127.0.0.1.nip.io'],
    ['https://api.github.com/meta', 'api.github.com'],
  ] as const) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict, 'needs-resolution', `${url}`);
    assert.equal(verdict.verdict === 'needs-resolution' && verdict.host, host);
  }
});

test('classifyTarget resolves the authority the way the parser does, not the way it reads', () => {
  // Userinfo before the host: destination is the address.
  assert.equal(classifyTarget('http://example.com@127.0.0.1/').verdict, 'block');
  // A backslash ends the authority in special schemes, so @example.com is path.
  assert.equal(classifyTarget('http://127.0.0.1\\@example.com/').verdict, 'block');
  // A percent-encoded slash does not, so here the address really is userinfo.
  assert.equal(classifyTarget('http://127.0.0.1%2f@example.com/').verdict, 'needs-resolution');
  assert.equal(classifyTarget('http://[::1]@example.com/').verdict, 'needs-resolution');
});

test('classifyTarget fails closed on input that does not parse', () => {
  for (const url of ['http://[fe80::1%25eth0]/', '//169.254.169.254/', 'not a url', '']) {
    const verdict = classifyTarget(url);
    assert.equal(verdict.verdict, 'block', `${url} must fail closed`);
    assert.equal(verdict.verdict === 'block' && verdict.category, 'unparseable');
  }
});
