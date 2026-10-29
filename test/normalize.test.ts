import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normaliseHost,
  isDottedQuad,
  expandIPv6,
  extractEmbeddedIPv4,
} from '../src/normalize.js';

test('isDottedQuad accepts four in-range octets and nothing else', () => {
  assert.equal(isDottedQuad('127.0.0.1'), true);
  assert.equal(isDottedQuad('0.0.0.0'), true);
  assert.equal(isDottedQuad('255.255.255.255'), true);
  assert.equal(isDottedQuad('256.0.0.1'), false, 'octet out of range');
  assert.equal(isDottedQuad('127.0.0'), false, 'too few octets');
  assert.equal(isDottedQuad('127.0.0.1.1'), false, 'too many octets');
  assert.equal(isDottedQuad('127.0.0.01'), true, 'zero padding is still decimal here');
  assert.equal(isDottedQuad('0x7f.0.0.1'), false, 'hex is not dotted-decimal');
  assert.equal(isDottedQuad('127.0.0.1.'), false, 'trailing dot is not an octet');
  assert.equal(isDottedQuad(''), false);
});

test('expandIPv6 gives eight groups for equivalent spellings of loopback', () => {
  const loopback = [0, 0, 0, 0, 0, 0, 0, 1];
  assert.deepEqual(expandIPv6('::1'), loopback);
  assert.deepEqual(expandIPv6('0:0:0:0:0:0:0:1'), loopback);
  assert.deepEqual(expandIPv6('0000:0000:0000:0000:0000:0000:0000:0001'), loopback);
  assert.deepEqual(expandIPv6('0:0::1'), loopback);
});

test('expandIPv6 places the compressed zeros correctly', () => {
  assert.deepEqual(expandIPv6('::'), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(expandIPv6('fe80::1'), [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(expandIPv6('2002:7f00:1::1'), [0x2002, 0x7f00, 1, 0, 0, 0, 0, 1]);
  assert.deepEqual(expandIPv6('2002:a9fe:a9fe::'), [0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0]);
  assert.deepEqual(expandIPv6('64:ff9b::7f00:1'), [0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1]);
});

test('expandIPv6 folds a trailing dotted quad into two groups', () => {
  assert.deepEqual(expandIPv6('::ffff:127.0.0.1'), [0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  assert.deepEqual(expandIPv6('::ffff:127.0.0.1'), expandIPv6('::ffff:7f00:1'));
  assert.deepEqual(expandIPv6('64:ff9b::8.8.8.8'), expandIPv6('64:ff9b::808:808'));
  assert.deepEqual(expandIPv6('::255.255.255.255'), [0, 0, 0, 0, 0, 0, 0xffff, 0xffff]);
});

test('expandIPv6 rejects malformed input instead of guessing', () => {
  assert.equal(expandIPv6('1:2:3:4:5:6:7'), null, 'too few groups without ::');
  assert.equal(expandIPv6('1:2:3:4:5:6:7:8:9'), null, 'too many groups');
  assert.equal(expandIPv6('1::2::3'), null, 'two compressions is ambiguous');
  assert.equal(expandIPv6('12345::1'), null, 'group wider than 16 bits');
  assert.equal(expandIPv6('::ffff:999.0.0.1'), null, 'octet out of range');
  assert.equal(expandIPv6('::zzzz'), null, 'not hex');
  assert.equal(expandIPv6('1:2:3:4:5:6:7:8:'), null, 'empty trailing group');
  assert.equal(expandIPv6('fe80::1%eth0'), null, 'zone identifiers are not addresses');
});

test('extractEmbeddedIPv4 recovers all four transition forms', () => {
  assert.deepEqual(extractEmbeddedIPv4('::ffff:7f00:1'), { address: '127.0.0.1', via: 'v4-mapped' });
  assert.deepEqual(extractEmbeddedIPv4('::7f00:1'), { address: '127.0.0.1', via: 'v4-compatible' });
  assert.deepEqual(extractEmbeddedIPv4('64:ff9b::7f00:1'), { address: '127.0.0.1', via: 'nat64' });
  assert.deepEqual(extractEmbeddedIPv4('2002:7f00:1::1'), { address: '127.0.0.1', via: '6to4' });
});

test('extractEmbeddedIPv4 reads the metadata address out of each form', () => {
  for (const address of ['::ffff:a9fe:a9fe', '::a9fe:a9fe', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::']) {
    assert.equal(
      extractEmbeddedIPv4(address)?.address,
      '169.254.169.254',
      `${address} should yield the link-local metadata address`,
    );
  }
});

test('extractEmbeddedIPv4 declines addresses with no embedded IPv4', () => {
  assert.equal(extractEmbeddedIPv4('::1'), null, 'loopback is not v4-compatible 0.0.0.1');
  assert.equal(extractEmbeddedIPv4('::'), null, 'the unspecified address embeds nothing');
  assert.equal(extractEmbeddedIPv4('fe80::1'), null);
  assert.equal(extractEmbeddedIPv4('fd00:ec2::254'), null);
  assert.equal(extractEmbeddedIPv4('2606:4700:4700::1111'), null);
  assert.equal(extractEmbeddedIPv4('::ffff:0:7f00:1'), null, 'IPv4-translated is not v4-mapped');
  assert.equal(extractEmbeddedIPv4('not-an-address'), null);
});

test('normaliseHost reports the parser output, kind, and effective IPv4', () => {
  assert.deepEqual(normaliseHost('http://2130706433/'), {
    host: '127.0.0.1',
    kind: 'ipv4',
    effectiveIPv4: '127.0.0.1',
    via: 'literal',
  });
  assert.deepEqual(normaliseHost('http://[::ffff:127.0.0.1]/'), {
    host: '::ffff:7f00:1',
    kind: 'ipv6',
    effectiveIPv4: '127.0.0.1',
    via: 'v4-mapped',
  });
  assert.deepEqual(normaliseHost('http://[fe80::1]/'), { host: 'fe80::1', kind: 'ipv6' });
  assert.deepEqual(normaliseHost('http://example.com/'), { host: 'example.com', kind: 'domain' });
});

test('normaliseHost strips userinfo and brackets, and returns null on unparseable input', () => {
  assert.equal(normaliseHost('http://example.com@127.0.0.1/')?.host, '127.0.0.1');
  assert.equal(normaliseHost('http://[::1]/')?.host, '::1', 'brackets are not part of the host');
  assert.equal(normaliseHost('http://[fe80::1%25eth0]/'), null, 'zone id is rejected by the parser');
  assert.equal(normaliseHost('//169.254.169.254/'), null, 'no scheme, no host');
  assert.equal(normaliseHost('not a url'), null);
});
