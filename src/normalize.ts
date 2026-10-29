/**
 * Host normalisation, and the embedded-IPv4 extraction that SSRF filters forget.
 *
 * The important thing to understand before writing an SSRF filter: by the time you
 * see a hostname from `new URL(input).hostname`, the WHATWG URL parser has already
 * collapsed every classic IPv4 obfuscation into dotted-decimal form.
 *
 *   http://2130706433/      -> 127.0.0.1
 *   http://0x7f.0.0.1/      -> 127.0.0.1
 *   http://0177.0.0.1/      -> 127.0.0.1
 *   http://127.1/           -> 127.0.0.1
 *   http://0/               -> 0.0.0.0
 *   http://127.0.0.1./      -> 127.0.0.1   (trailing dot stripped)
 *
 * So a dotted-decimal range check is *sufficient* for IPv4 — provided you ran the
 * input through a WHATWG-conformant parser first, and provided you check ranges
 * rather than string-matching "127.0.0.1".
 *
 * IPv6 is where filters actually fail. The parser normalises the textual form but
 * does **not** convert embedded IPv4 back to dotted-decimal:
 *
 *   http://[::ffff:127.0.0.1]/   -> [::ffff:7f00:1]
 *   http://[::127.0.0.1]/        -> [::7f00:1]
 *
 * A filter that greps for `127.` never sees it. The address still routes to
 * loopback. Extracting the embedded v4 and re-checking it is the fix, and it is
 * what {@link extractEmbeddedIPv4} exists for.
 */

export type HostKind = 'ipv4' | 'ipv6' | 'domain';

export interface NormalisedHost {
  /** Hostname exactly as the WHATWG parser produced it, brackets stripped for IPv6. */
  host: string;
  kind: HostKind;
  /**
   * Dotted-decimal IPv4 this host ultimately designates, if any — either because it
   * *is* IPv4, or because it is an IPv6 address with an embedded IPv4 (v4-mapped,
   * v4-compatible, NAT64 or 6to4).
   */
  effectiveIPv4?: string;
  /** How `effectiveIPv4` was obtained, for reporting. */
  via?: 'literal' | 'v4-mapped' | 'v4-compatible' | 'nat64' | '6to4';
}

/** Parse and normalise a target URL's host. Returns null if the URL will not parse. */
export function normaliseHost(input: string): NormalisedHost | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  let host = url.hostname;
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  if (host.includes(':')) {
    const embedded = extractEmbeddedIPv4(host);
    return embedded
      ? { host, kind: 'ipv6', effectiveIPv4: embedded.address, via: embedded.via }
      : { host, kind: 'ipv6' };
  }
  if (isDottedQuad(host)) {
    return { host, kind: 'ipv4', effectiveIPv4: host, via: 'literal' };
  }
  return { host, kind: 'domain' };
}

/** True for a well-formed dotted-decimal IPv4 string with four octets in range. */
export function isDottedQuad(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** Expand an IPv6 address to its eight 16-bit groups. Returns null if malformed. */
export function expandIPv6(address: string): number[] | null {
  // A trailing dotted-quad (e.g. ::ffff:127.0.0.1) becomes two hex groups.
  let text = address;
  const dotted = text.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted?.[1]) {
    if (!isDottedQuad(dotted[1])) return null;
    const o = dotted[1].split('.').map(Number) as [number, number, number, number];
    const hi = ((o[0] << 8) | o[1]).toString(16);
    const lo = ((o[2] << 8) | o[3]).toString(16);
    text = text.slice(0, dotted.index) + `${hi}:${lo}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (chunk: string): number[] | null => {
    if (chunk === '') return [];
    const out: number[] = [];
    for (const group of chunk.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      out.push(parseInt(group, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? '');
  const tail = halves.length === 2 ? parse(halves[1] ?? '') : [];
  if (head === null || tail === null) return null;

  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...tail];
}

export interface EmbeddedIPv4 {
  address: string;
  via: 'v4-mapped' | 'v4-compatible' | 'nat64' | '6to4';
}

/**
 * Recover the IPv4 address an IPv6 address designates, for every transition form
 * that routes to a v4 destination.
 *
 * - `::ffff:a.b.c.d`  v4-mapped (RFC 4291)
 * - `::a.b.c.d`       v4-compatible, deprecated but still resolvable on many stacks
 * - `64:ff9b::a.b.c.d` NAT64 well-known prefix (RFC 6052)
 * - `2002:abcd:efgh::` 6to4, v4 in bits 16..48 (RFC 3056)
 */
export function extractEmbeddedIPv4(address: string): EmbeddedIPv4 | null {
  const g = expandIPv6(address);
  if (!g) return null;
  const quad = (hi: number, lo: number) =>
    `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  const zeros = (upTo: number) => g.slice(0, upTo).every((x) => x === 0);

  if (zeros(5) && g[5] === 0xffff) {
    return { address: quad(g[6]!, g[7]!), via: 'v4-mapped' };
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return { address: quad(g[6]!, g[7]!), via: 'nat64' };
  }
  if (g[0] === 0x2002) {
    return { address: quad(g[1]!, g[2]!), via: '6to4' };
  }
  // v4-compatible: all-zero prefix, non-zero tail, and not ::1 / :: themselves.
  if (zeros(6) && !(g[6] === 0 && (g[7] === 0 || g[7] === 1))) {
    return { address: quad(g[6]!, g[7]!), via: 'v4-compatible' };
  }
  return null;
}
