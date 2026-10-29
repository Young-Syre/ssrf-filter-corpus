/**
 * A reference destination filter — the blocklist this corpus is scored against.
 *
 * It is deliberately lexical. It parses, normalises, recovers embedded IPv4, and
 * then decides from the address alone. It never resolves DNS, which means there is
 * a whole class of input it honestly cannot rule on: a hostname like
 * `localtest.me` is syntactically ordinary and resolves to 127.0.0.1. Those return
 * `needs-resolution` rather than a guess, because a filter that pretends to decide
 * them is the filter that gets bypassed by DNS rebinding — resolve, pin the
 * resulting address, check *that*, and connect to the pinned address.
 *
 * Two design choices worth stating, because they are what filters usually get wrong:
 *
 * 1. Ranges, not strings. `127.0.0.1` is one of 16.7 million loopback addresses and
 *    `0.0.0.0` reaches every local listener. Substring matching catches neither.
 * 2. IPv6 is checked by expanding it and recovering any embedded IPv4, not by
 *    looking at its text. `[::ffff:7f00:1]` contains no "127." to match on.
 */

import { isDottedQuad, expandIPv6, normaliseHost, type NormalisedHost } from './normalize.js';

export type BlockCategory =
  | 'unspecified'
  | 'loopback'
  | 'private'
  | 'cgnat'
  | 'link-local'
  | 'benchmark'
  | 'multicast'
  | 'broadcast'
  | 'ipv6-ula'
  | 'ipv6-link-local'
  | 'ipv6-multicast'
  | 'ipv6-reserved'
  | 'dangerous-name'
  | 'unsupported-scheme'
  | 'no-host'
  | 'unparseable';

export interface BlockVerdict {
  verdict: 'block';
  /** One sentence naming the range or name that matched, for logs and reports. */
  reason: string;
  category: BlockCategory;
}

export interface AllowVerdict {
  verdict: 'allow';
  /** The normalised host that was cleared, so callers can pin and connect to it. */
  host: string;
}

/**
 * The host is a name, not an address. A lexical filter cannot decide it: resolve it,
 * then classify every address the resolver returns, then connect to a pinned address.
 */
export interface NeedsResolutionVerdict {
  verdict: 'needs-resolution';
  host: string;
}

export type Verdict = BlockVerdict | AllowVerdict | NeedsResolutionVerdict;

export interface Ipv4Reservation {
  cidr: string;
  category: BlockCategory;
  /** Why this range must never be a fetch destination, with its defining RFC. */
  note: string;
}

/**
 * IPv4 ranges that are never a legitimate outbound fetch target.
 *
 * 169.254.0.0/16 is the one that pays: it holds 169.254.169.254, the instance
 * metadata endpoint on AWS, Azure, GCP, DigitalOcean and Oracle Cloud. 100.64/10
 * is the one that gets forgotten: Alibaba Cloud puts its metadata service at
 * 100.100.100.200, inside carrier-grade NAT space.
 */
export const IPV4_RESERVED: readonly Ipv4Reservation[] = [
  { cidr: '0.0.0.0/8', category: 'unspecified', note: '"this network" (RFC 1122) — 0.0.0.0 binds to every local interface' },
  { cidr: '10.0.0.0/8', category: 'private', note: 'private use (RFC 1918)' },
  { cidr: '100.64.0.0/10', category: 'cgnat', note: 'carrier-grade NAT (RFC 6598) — Alibaba Cloud metadata lives at 100.100.100.200' },
  { cidr: '127.0.0.0/8', category: 'loopback', note: 'loopback (RFC 1122) — all 16.7M of it, not just 127.0.0.1' },
  { cidr: '169.254.0.0/16', category: 'link-local', note: 'link-local (RFC 3927) — cloud instance metadata at 169.254.169.254' },
  { cidr: '172.16.0.0/12', category: 'private', note: 'private use (RFC 1918) — 172.16.0.0 through 172.31.255.255 only' },
  { cidr: '192.168.0.0/16', category: 'private', note: 'private use (RFC 1918)' },
  { cidr: '198.18.0.0/15', category: 'benchmark', note: 'benchmarking (RFC 2544) — routed internally at some providers' },
  { cidr: '224.0.0.0/4', category: 'multicast', note: 'multicast (RFC 5771) — includes SSDP at 239.255.255.250' },
  { cidr: '255.255.255.255/32', category: 'broadcast', note: 'limited broadcast (RFC 919)' },
];

interface CompiledRange extends Ipv4Reservation {
  network: number;
  mask: number;
}

const COMPILED: readonly CompiledRange[] = IPV4_RESERVED.map((r) => {
  const [addr = '', bits = ''] = r.cidr.split('/');
  const length = Number(bits);
  const mask = length === 0 ? 0 : (0xffffffff << (32 - length)) >>> 0;
  // `&` yields a signed 32-bit int, so the >>> 0 is load-bearing: without it every
  // network above 128.0.0.0 compares negative and never matches.
  const network = ((ipv4ToInt(addr) ?? 0) & mask) >>> 0;
  return { ...r, network, mask };
});

/** Pack a dotted-decimal IPv4 string into a 32-bit unsigned integer. */
export function ipv4ToInt(dotted: string): number | null {
  if (!isDottedQuad(dotted)) return null;
  const o = dotted.split('.').map(Number) as [number, number, number, number];
  return (((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0);
}

/** The reserved range a dotted-decimal address falls in, or null if it is public. */
export function ipv4Reservation(dotted: string): Ipv4Reservation | null {
  const value = ipv4ToInt(dotted);
  if (value === null) return null;
  for (const range of COMPILED) {
    if (((value & range.mask) >>> 0) === range.network) return range;
  }
  return null;
}

/** True if a dotted-decimal address is in any range that must not be fetched. */
export function isPrivateIPv4(dotted: string): boolean {
  return ipv4Reservation(dotted) !== null;
}

interface Ipv6Special {
  /** Match against the eight expanded 16-bit groups. */
  test: (g: readonly number[]) => boolean;
  category: BlockCategory;
  reason: string;
}

/**
 * IPv6 ranges checked on the expanded address. Order matters: embedded IPv4 is
 * recovered before these run, so a v4-mapped public address is not caught by the
 * `::/8` reserved sweep at the end.
 */
const IPV6_SPECIAL: readonly Ipv6Special[] = [
  {
    test: (g) => g.every((x, i) => (i < 7 ? x === 0 : x === 1)),
    category: 'loopback',
    reason: '::1/128 is IPv6 loopback (RFC 4291)',
  },
  {
    test: (g) => g.every((x) => x === 0),
    category: 'unspecified',
    reason: ':: is the unspecified address (RFC 4291) and binds locally',
  },
  {
    test: (g) => (g[0]! & 0xfe00) === 0xfc00,
    category: 'ipv6-ula',
    reason: 'fc00::/7 is unique-local (RFC 4193) — AWS serves IMDS over IPv6 at fd00:ec2::254',
  },
  {
    test: (g) => (g[0]! & 0xffc0) === 0xfe80,
    category: 'ipv6-link-local',
    reason: 'fe80::/10 is link-local (RFC 4291)',
  },
  {
    test: (g) => (g[0]! & 0xff00) === 0xff00,
    category: 'ipv6-multicast',
    reason: 'ff00::/8 is multicast (RFC 4291)',
  },
  {
    // Last resort. Everything with a zero leading byte that is not one of the
    // transition forms above is IETF-reserved (RFC 4291 §2.4) and unroutable —
    // which covers ::ffff:0:a.b.c.d, the deprecated IPv4-translated form.
    test: (g) => (g[0]! & 0xff00) === 0,
    category: 'ipv6-reserved',
    reason: '::/8 is reserved by the IETF (RFC 4291) and is not a routable destination',
  },
];

/**
 * Hostnames that designate something local or an internal metadata service, and so
 * must be refused by name — resolving them is already a loss on a host where the
 * resolver answers for them.
 *
 * 169.254.169.254 needs no entry here: the link-local range check covers it, and
 * every obfuscation of it (0xA9FEA9FE, 2852039166, ①⑥⑨.②⑤④.①⑥⑨.②⑤④) arrives as
 * dotted-decimal from the parser.
 */
export const DANGEROUS_NAMES: readonly string[] = [
  'localhost',
  'instance-data', // EC2's legacy unqualified metadata name
  'metadata.goog', // GCP alternative metadata name
  'metadata.google.internal',
];

/**
 * Suffixes refused wholesale. RFC 6761 reserves `.localhost` for loopback, and
 * `.internal` is reserved for private networks — it is where AWS (`*.ec2.internal`)
 * and GCP (`metadata.google.internal`) put instance metadata.
 */
export const DANGEROUS_SUFFIXES: readonly string[] = ['.localhost', '.internal'];

/**
 * The only schemes a destination filter for an HTTP fetcher should pass.
 *
 * Everything else is refused by name rather than by host, because the host is
 * the wrong question for them: `file:///etc/passwd` has no host at all, and
 * `gopher://` and `dict://` are useful to an attacker precisely because the
 * client will write attacker-chosen bytes to an arbitrary port. A fetcher that
 * follows redirects has to re-run this check on every hop, since the scheme can
 * change mid-chain.
 */
export const ALLOWED_SCHEMES: readonly string[] = ['http', 'https'];

/**
 * Classify a target URL for a lexical SSRF filter.
 *
 * @param url Raw, untrusted input — exactly as it arrived from the user.
 */
export function classifyTarget(url: string): Verdict {
  const parsed = normaliseHost(url);
  if (!parsed) {
    return {
      verdict: 'block',
      reason: 'input is not a URL the WHATWG parser accepts, so nothing downstream can agree on its host',
      category: 'unparseable',
    };
  }
  if (!ALLOWED_SCHEMES.includes(parsed.scheme)) {
    return {
      verdict: 'block',
      reason: `${parsed.scheme}: is not ${ALLOWED_SCHEMES.join(' or ')}, so the host is the wrong question`,
      category: 'unsupported-scheme',
    };
  }
  return classifyHost(parsed);
}

/** The address-level half of {@link classifyTarget}, for callers holding a parsed host. */
export function classifyHost(parsed: NormalisedHost): Verdict {
  // The parser strips one trailing dot from an address-shaped host but keeps every
  // dot on a name: `169.254.169.254..` survives as a domain and slips past any
  // range check. Strip the root label(s) and re-test before anything else.
  const host = parsed.host.replace(/\.+$/, '');

  // No host at all. This used to fall through to the domain branch and return
  // needs-resolution with an empty host, which referenceFilter reads as "not
  // blocked" -- so `file:///etc/passwd` was allowed. There is nothing to
  // resolve, so there is nothing a resolver could rule on later.
  if (host === '') {
    return {
      verdict: 'block',
      reason: `${parsed.scheme}: carries no host, so there is nothing to resolve or pin`,
      category: 'no-host',
    };
  }

  const embedded = parsed.effectiveIPv4;
  if (embedded) {
    const range = ipv4Reservation(embedded);
    if (range) {
      const how =
        parsed.via === 'literal'
          ? embedded
          : `${parsed.host} carries ${embedded} as ${parsed.via}`;
      return { verdict: 'block', reason: `${how}: ${range.note}`, category: range.category };
    }
    return { verdict: 'allow', host: parsed.host };
  }

  if (parsed.kind === 'ipv6') {
    const groups = expandIPv6(host);
    if (!groups) {
      return {
        verdict: 'block',
        reason: `${parsed.host} is bracketed as IPv6 but does not expand to eight groups`,
        category: 'unparseable',
      };
    }
    for (const special of IPV6_SPECIAL) {
      if (special.test(groups)) {
        return { verdict: 'block', reason: `${parsed.host}: ${special.reason}`, category: special.category };
      }
    }
    return { verdict: 'allow', host: parsed.host };
  }

  // A name the parser left alone may still be an address once trailing dots go.
  if (isDottedQuad(host)) {
    const range = ipv4Reservation(host);
    if (range) {
      return { verdict: 'block', reason: `${host}: ${range.note}`, category: range.category };
    }
    return { verdict: 'allow', host };
  }

  if (parsed.kind === 'domain') {
    const name = host.toLowerCase();
    if (DANGEROUS_NAMES.includes(name)) {
      return { verdict: 'block', reason: `${name} names a local or metadata service`, category: 'dangerous-name' };
    }
    const suffix = DANGEROUS_SUFFIXES.find((s) => name.endsWith(s));
    if (suffix) {
      return {
        verdict: 'block',
        reason: `${name} is under ${suffix}, which is reserved for local and internal use`,
        category: 'dangerous-name',
      };
    }
    return { verdict: 'needs-resolution', host: name };
  }

  return { verdict: 'allow', host };
}

/**
 * {@link classifyTarget} as the boolean predicate {@link runCorpus} expects: true
 * means block. `needs-resolution` becomes false, which is the honest answer for a
 * filter with no resolver — and the reason a real deployment must pair this with
 * resolve-then-pin rather than ship it alone.
 */
export function referenceFilter(url: string): boolean {
  return classifyTarget(url).verdict === 'block';
}
