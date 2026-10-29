# ssrf-filter-corpus

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)
[![tests](https://github.com/Young-Syre/ssrf-filter-corpus/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/ssrf-filter-corpus/actions/workflows/tests.yml)

A test corpus and scoring harness for SSRF destination filters. 117 entries, every
one a real address form, with the host each one normalises to **verified against
`new URL()` at test time** rather than asserted from memory.

## The thesis

Most published advice about SSRF filters is about IPv4 obfuscation —
`http://2130706433/`, `http://0177.0.0.1/`, `http://127.1/` — and most of it is
obsolete. A WHATWG-conformant URL parser, which includes the `URL` class in every
browser and in Node, collapses all of those into dotted-decimal **before your filter
sees the hostname**. If you parse the input and then check the address against the
reserved ranges, you have already handled the entire decimal/octal/hex/short-form
family, and you need none of the deobfuscation code those articles recommend. Where
filters actually fail is IPv6: the parser normalises the text of an IPv6 address but
does *not* convert an embedded IPv4 address back to dotted-decimal, so
`http://[::ffff:127.0.0.1]/` arrives at your filter as `::ffff:7f00:1` — no `127.`
anywhere in it, and still routing to loopback. This corpus exists to test for that
class of bug, and for the over-blocking that filters acquire while trying to avoid it.

## What the URL parser already does for you

Verified on Node 22. Every row is a corpus entry; `test/corpus.test.ts` re-derives
the right-hand column with `new URL(input).hostname` and fails the build if it drifts.

| Input | `new URL(…).hostname` | Why it is already handled |
| --- | --- | --- |
| `http://2130706433/` | `127.0.0.1` | 32-bit integer form |
| `http://0x7f000001/` | `127.0.0.1` | flat hexadecimal |
| `http://0x7f.0.0.1/` | `127.0.0.1` | mixed radix per octet |
| `http://017700000001/` | `127.0.0.1` | flat octal |
| `http://0177.0.0.1/` | `127.0.0.1` | octal first octet |
| `http://127.1/` | `127.0.0.1` | omitted octets expand |
| `http://0/` | `0.0.0.0` | a bare zero is an address |
| `http://127.0.0.1./` | `127.0.0.1` | one trailing dot is stripped |
| `http://example.com@127.0.0.1/` | `127.0.0.1` | userinfo is not the host |
| `http://１２７.０.０.１/` | `127.0.0.1` | IDNA maps full-width digits |
| `http://⑦⑦.com/` | `77.com` | IDNA maps circled digits |
| `http://ⓛocalhost/` | `localhost` | IDNA maps lookalike letters |

So: **parse first, then range-check**. A filter that string-matches the raw URL has to
re-implement all of this and will get it wrong; a filter that string-matches the
*parsed hostname* gets the whole table above for free. That is why IPv4 obfuscation is
not where the bugs are, and `test/harness.test.ts` asserts exactly that — a filter
doing nothing but `hostname.includes('127.0.0.1') || hostname.includes('localhost')`
stops every loopback and localhost row above, obfuscated or not.

## Where filters actually fail

The same filter misses 73 of the 96 blocking entries in this corpus. Here is the
shape of it:

```js
new URL('http://[::ffff:127.0.0.1]/').hostname  // '[::ffff:7f00:1]'
new URL('http://[::127.0.0.1]/').hostname       // '[::7f00:1]'
new URL('http://[64:ff9b::127.0.0.1]/').hostname // '[64:ff9b::7f00:1]'
new URL('http://[2002:7f00:1::1]/').hostname    // '[2002:7f00:1::1]'
```

All four designate 127.0.0.1. The parser rewrote the embedded IPv4 as hex groups
(`7f00:1`), so no substring, prefix or regex over the hostname will find it — and
unlike the IPv4 cases, the parser has not done the work for you. You have to expand
the address and recover the embedded IPv4 yourself:

```ts
import { extractEmbeddedIPv4 } from 'ssrf-filter-corpus';

extractEmbeddedIPv4('::ffff:7f00:1');   // { address: '127.0.0.1', via: 'v4-mapped' }
extractEmbeddedIPv4('::7f00:1');        // { address: '127.0.0.1', via: 'v4-compatible' }
extractEmbeddedIPv4('64:ff9b::7f00:1'); // { address: '127.0.0.1', via: 'nat64' }
extractEmbeddedIPv4('2002:7f00:1::1');  // { address: '127.0.0.1', via: '6to4' }
```

Then range-check what comes back. The other half of the problem is that this is easy
to over-correct: `[::ffff:8.8.8.8]` and `[2002:808:808::1]` are public destinations,
and a filter that rejects the `::ffff:` prefix or all bracketed hosts has broken
IPv6 egress. The corpus includes those cases too, scored as over-blocks.

## Install

```bash
npm install --save-dev ssrf-filter-corpus
```

Zero runtime dependencies. Node 20 or newer, for `URL.canParse` and
`AbortSignal.timeout`.

## Using this against your own code

Wire your filter into `runCorpus`. It takes any function from a URL string to a
boolean — `true` meaning "I would block this" — and may be async.

```ts
import { runCorpus, formatReport } from 'ssrf-filter-corpus';
import { isAllowedFetchTarget } from '../src/http/egress.js';

const report = await runCorpus((url) => !isAllowedFetchTarget(url));

console.log(formatReport(report, 'egress.ts'));

// Fail CI on a reachable internal destination, but not on a deferred name.
if (report.bypasses.length > 0) {
  for (const { entry } of report.bypasses) {
    console.error(`${entry.id}: ${entry.input} -> ${entry.normalisedHost}`);
  }
  process.exit(1);
}
```

The report separates three outcomes, because they are not the same failure:

| Field | Meaning | Severity |
| --- | --- | --- |
| `bypasses` | Expected block, your filter allowed | A reachable internal destination |
| `overBlocks` | Expected allow, your filter blocked | A broken legitimate fetch |
| `errors` | Your filter threw | A crash is not a deny |
| `skipped` | `needs-resolution` entries, not scored | — |

A filter that blocks everything has zero bypasses and is not a passing filter; that
is what `overBlocks` is for.

### The honest limit: names

Nine entries expect `needs-resolution` and are not scored. They are hostnames, and no
lexical filter can decide them:

```ts
import { classifyTarget } from 'ssrf-filter-corpus';

classifyTarget('http://localtest.me/');
// { verdict: 'needs-resolution', host: 'localtest.me' }
```

`localtest.me` is an ordinary public domain whose A record is 127.0.0.1. Nothing about
the string distinguishes it from `example.com`, which is why it sits in the same
bucket. The only correct handling is to resolve the name, classify **every** address
the resolver returns, and then connect to a pinned address — if you resolve, check,
and then let the HTTP client resolve again, you have built a DNS rebinding
vulnerability regardless of how good your range checks are. `deferredBlocked` in the
report tells you how many of these your filter blocked anyway, which is how you tell
a deny-by-default allowlist from a lexical blocklist.

## Categories

117 entries: 96 expect `block`, 12 expect `allow`, 9 expect `needs-resolution`.

| Category | n | block | allow | needs-resolution |
| --- | --- | --- | --- | --- |
| `ipv4-decimal` | 4 | 4 | 0 | 0 |
| `ipv4-octal` | 4 | 4 | 0 | 0 |
| `ipv4-hex` | 4 | 4 | 0 | 0 |
| `ipv4-short` | 5 | 5 | 0 | 0 |
| `ipv4-private` | 5 | 5 | 0 | 0 |
| `ipv4-reserved` | 4 | 4 | 0 | 0 |
| `cgnat` | 5 | 3 | 2 | 0 |
| `linklocal` | 3 | 3 | 0 | 0 |
| `cloud-metadata` | 10 | 10 | 0 | 0 |
| `ipv6-loopback` | 4 | 4 | 0 | 0 |
| `ipv6-v4mapped` | 7 | 6 | 1 | 0 |
| `ipv6-v4compatible` | 4 | 4 | 0 | 0 |
| `ipv6-nat64` | 3 | 2 | 1 | 0 |
| `ipv6-6to4` | 4 | 3 | 1 | 0 |
| `ipv6-ula` | 2 | 2 | 0 | 0 |
| `ipv6-linklocal` | 2 | 2 | 0 | 0 |
| `ipv6-multicast` | 2 | 2 | 0 | 0 |
| `ipv6-reserved` | 1 | 1 | 0 | 0 |
| `hostname-alias` | 5 | 5 | 0 | 0 |
| `userinfo-confusion` | 8 | 5 | 0 | 3 |
| `idn` | 6 | 5 | 0 | 1 |
| `trailing-dot` | 5 | 5 | 0 | 0 |
| `rebinding` | 4 | 0 | 0 | 4 |
| `public-allow` | 8 | 0 | 7 | 1 |
| `scheme` | 6 | 6 | 0 | 0 |
| `malformed` | 2 | 2 | 0 | 0 |

<details>
<summary><b>The cases worth reading even if you never run the harness</b></summary>

**`[::ffff:127.0.0.1]` → `::ffff:7f00:1`** — v4-mapped (RFC 4291). The parser rewrites
the embedded address as hex. Routes to loopback; contains no `127.`.

**`http://169.254.169.254../`** → `169.254.169.254..` — two trailing dots stop the
parser treating the host as an address at all. It stays a *domain*, so every IPv4
range check in your filter is skipped. Strip trailing dots and re-test.

**`http://127.0.0.1\@example.com/`** → `127.0.0.1` — in special schemes a backslash
terminates the authority, so `@example.com` is the path and the host is loopback. A
regex that reads up to the `@` gets the opposite answer.

**`http://127.0.0.1%2f@example.com/`** → `example.com` — and here the loopback address
really *is* userinfo, because a percent-encoded slash does not terminate the
authority. Blocking this one is an over-block. These two inputs differ by one
character and must be decided differently; only a conformant parser gets both right.

**`file:///etc/passwd`** → host `''` — the host is the wrong question. A filter that
reaches for the hostname finds an empty string, and an empty string is neither a
blocked range nor a resolvable name, so the usual outcome is "cannot decide, pass it
on". The scheme is what decides this one, which is why the reference filter gates on
`http`/`https` before it looks at the host at all. `gopher://` and `dict://` are the
same decision for the opposite reason: their hosts are often perfectly ordinary, and
what makes them useful to an attacker is that the client writes caller-chosen bytes
to a caller-chosen port. A fetcher that follows redirects has to re-run the scheme
check on every hop, because the scheme can change mid-chain.

**`http://100.100.100.200/latest/meta-data/`** — Alibaba Cloud instance metadata, in
carrier-grade NAT space (RFC 6598). Blocklists built from RFC 1918 plus loopback plus
169.254/16 — which is most of them — allow it.

**`http://[fd00:ec2::254]/latest/meta-data/`** — AWS serves IMDS over IPv6 at this
unique-local address. No IPv4 blocklist can express it.

**`http://ⓛocalhost/`** → `localhost` — IDNA mapping turns the circled letter into
`l`, producing the literal name from input containing no ASCII `l`. Mapping is a
table, so enumerating lookalikes is the wrong defence; comparing after parsing is the
right one.

**`http://[2002:a9fe:a9fe::]/`** → 6to4 (RFC 3056) carrying 169.254.169.254 in bits
16–48. Looks like an ordinary global-unicast address to a prefix-based filter.

**`http://instance-data/latest/meta-data/`** — EC2 resolves this unqualified name to
the metadata service. A single-label host with no dots to validate.

</details>

## CLI

```bash
npx ssrf-corpus categories
npx ssrf-corpus list --category ipv6-v4mapped
npx ssrf-corpus list --expect allow --json
npx ssrf-corpus self-test
```

`list` prints each entry with the host it normalises to, the reference
implementation's verdict, and why the case matters:

```
ipv6-v4mapped-loopback  [ipv6-v4mapped]  expect block
  input       http://[::ffff:127.0.0.1]/
  normalises  ::ffff:7f00:1
  reference   block — ::ffff:7f00:1 carries 127.0.0.1 as v4-mapped: loopback (RFC 1122) — all 16.7M of it, not just 127.0.0.1
  why         The core bug class: the parser rewrites the embedded IPv4 as hex, so the string "127." is gone while the route to loopback remains.
```

`self-test` scores the bundled reference filter (`src/classify.ts`) against the
corpus. It must be 100%, and CI fails if it is not — the corpus and the reference
implementation keep each other honest.

### Probe mode

> [!WARNING]
> `probe` sends live requests. Each corpus entry is substituted into your URL
> template and dispatched, asking the target to fetch loopback, private-range and
> cloud metadata addresses. Against a system you do not have written permission to
> test, that is unauthorised access, and it will look exactly like an attack in the
> target's logs. It refuses to run without `--yes`.

```bash
npx ssrf-corpus probe \
  --target 'https://app.example.test/api/preview?url={{URL}}' \
  --block-on 'body:not allowed' \
  --header 'Authorization: Bearer …' \
  --delay 250 \
  --yes
```

`{{URL}}` is replaced with each percent-encoded corpus input (`--raw` to skip the
encoding). The response is read as a block or an allow according to `--block-on`:

| `--block-on` | Interpretation |
| --- | --- |
| `status` (default) | any status ≥ 400 means blocked |
| `status:403,422` | exactly these statuses mean blocked |
| `body:<regex>` | a response body matching the regex means blocked |

Requests are issued one at a time, and `--delay` adds a pause between them. Exit
status is 1 if any bypass or error was found, so it drops into CI unchanged.

## API

| Export | Purpose |
| --- | --- |
| `runCorpus(filter, opts?)` | Score a filter; returns a `CorpusReport` |
| `formatReport(report, name?)` | Render a report as an aligned text table |
| `CORPUS`, `CATEGORIES` | The entries and category names |
| `byCategory(c)`, `entryById(id)` | Corpus lookups |
| `normaliseHost(url)` | Parse to `{ host, kind, effectiveIPv4?, via? }` |
| `extractEmbeddedIPv4(addr)` | Recover IPv4 from v4-mapped / v4-compatible / NAT64 / 6to4 |
| `expandIPv6(addr)` | Expand to eight 16-bit groups, or `null` |
| `classifyTarget(url)` | Reference verdict: `block` / `allow` / `needs-resolution` |
| `isPrivateIPv4(dotted)`, `ipv4Reservation(dotted)` | Range checks, and which range matched |
| `IPV4_RESERVED` | The reserved ranges, with the RFC for each |

## Prior art and references

- [WHATWG URL Standard](https://url.spec.whatwg.org/) — the host parser and IPv4
  parser, which between them define every normalisation in the first table. The host
  parsing and IPv4 parsing algorithms are the two worth reading in full.
- [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) — IPv6 addressing architecture:
  §2.5.5.1 IPv4-compatible and §2.5.5.2 IPv4-mapped addresses, plus the reserved,
  unique-local, link-local and multicast prefixes.
- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052) — IPv6 addressing of IPv4/IPv6
  translators, which defines the `64:ff9b::/96` well-known NAT64 prefix.
- [RFC 3056](https://www.rfc-editor.org/rfc/rfc3056) — connection of IPv6 domains via
  IPv4 clouds (6to4), which puts the IPv4 address in bits 16–48 of a `2002::/16` address.
- [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) — `100.64.0.0/10` for shared
  address space (carrier-grade NAT), the range most often missing from SSRF blocklists.
- [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918),
  [RFC 3927](https://www.rfc-editor.org/rfc/rfc3927),
  [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) — private address space,
  IPv4 link-local, and the reservation of `.localhost`.
- [OWASP: Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
  — for the defensive architecture around the filter, which matters more than the filter.

## Licence

MIT © David Nichols
