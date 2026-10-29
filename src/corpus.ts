/**
 * The corpus: every case is a real address form that reaches a real destination.
 *
 * Each `normalisedHost` below was taken from `new URL(input).hostname` on Node 22,
 * not from reasoning about what the parser ought to do. `test/corpus.test.ts`
 * re-derives all of them at test time, so an entry that drifts from the parser's
 * actual behaviour fails the build rather than quietly misleading a reader.
 *
 * Nothing here contacts a network. The inputs are strings; the paths are real
 * metadata paths so that a probe run against your own endpoint produces traffic
 * that looks like the attack rather than like a scanner.
 */

export const CATEGORIES = [
  'ipv4-decimal',
  'ipv4-octal',
  'ipv4-hex',
  'ipv4-short',
  'ipv4-private',
  'ipv4-reserved',
  'cgnat',
  'linklocal',
  'cloud-metadata',
  'ipv6-loopback',
  'ipv6-v4mapped',
  'ipv6-v4compatible',
  'ipv6-nat64',
  'ipv6-6to4',
  'ipv6-ula',
  'ipv6-linklocal',
  'ipv6-multicast',
  'ipv6-reserved',
  'hostname-alias',
  'userinfo-confusion',
  'idn',
  'trailing-dot',
  'rebinding',
  'public-allow',
  'malformed',
] as const;

export type Category = (typeof CATEGORIES)[number];

/** What a correct filter must do with an entry. */
export type Expectation = 'block' | 'allow' | 'needs-resolution';

export interface CorpusEntry {
  /** Stable identifier — safe to cite in a report or an exclusion list. */
  id: string;
  /** The URL to hand the filter, verbatim. */
  input: string;
  category: Category;
  expect: Expectation;
  /**
   * Host as `normaliseHost()` reports it: `new URL(input).hostname`, with IPv6
   * brackets stripped. Absent only when the input does not parse.
   */
  normalisedHost?: string;
  /** Why this specific case matters, in one sentence. */
  rationale: string;
}

export const CORPUS: readonly CorpusEntry[] = [
  // ── IPv4, written as a single decimal integer ──────────────────────────────
  {
    id: 'ipv4-dec-loopback',
    input: 'http://2130706433/',
    category: 'ipv4-decimal',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'The canonical "SSRF bypass" payload, and the one that proves the thesis: the parser hands your filter 127.0.0.1 before you look at it.',
  },
  {
    id: 'ipv4-dec-private',
    input: 'http://3232235521/',
    category: 'ipv4-decimal',
    expect: 'block',
    normalisedHost: '192.168.0.1',
    rationale: 'Decimal form of 192.168.0.1 — the range check must run on the parsed host, not on the input string.',
  },
  {
    id: 'ipv4-dec-metadata',
    input: 'http://2852039166/latest/meta-data/iam/security-credentials/',
    category: 'ipv4-decimal',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Decimal form of the AWS metadata address, with the path that yields role credentials.',
  },
  {
    id: 'ipv4-dec-alibaba',
    input: 'http://1684301000/latest/meta-data/',
    category: 'ipv4-decimal',
    expect: 'block',
    normalisedHost: '100.100.100.200',
    rationale: 'Decimal form of Alibaba Cloud metadata, which sits in CGNAT space that private-range blocklists routinely omit.',
  },

  // ── IPv4, octal octets ────────────────────────────────────────────────────
  {
    id: 'ipv4-oct-loopback',
    input: 'http://0177.0.0.1/',
    category: 'ipv4-octal',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Leading-zero octal in the first octet; the parser resolves it, so only a string-matching filter is fooled.',
  },
  {
    id: 'ipv4-oct-loopback-flat',
    input: 'http://017700000001/',
    category: 'ipv4-octal',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Whole address as one octal number — a form that defeats per-octet regex validation entirely.',
  },
  {
    id: 'ipv4-oct-private',
    input: 'http://0300.0250.0.1/',
    category: 'ipv4-octal',
    expect: 'block',
    normalisedHost: '192.168.0.1',
    rationale: 'Octal 192.168.0.1, included because allowlists that permit "numeric-looking" hosts tend to assume decimal.',
  },
  {
    id: 'ipv4-oct-metadata',
    input: 'http://0251.0376.0251.0376/',
    category: 'ipv4-octal',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Octal 169.254.169.254, the form most commonly seen in real SSRF reports against naive deny-lists.',
  },

  // ── IPv4, hexadecimal ─────────────────────────────────────────────────────
  {
    id: 'ipv4-hex-loopback-mixed',
    input: 'http://0x7f.0.0.1/',
    category: 'ipv4-hex',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Mixed radix within one address: the parser accepts hex and decimal octets side by side.',
  },
  {
    id: 'ipv4-hex-loopback-flat',
    input: 'http://0x7f000001/',
    category: 'ipv4-hex',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Single hex integer for the whole address — contains no dot, so dot-counting validators pass it through.',
  },
  {
    id: 'ipv4-hex-metadata',
    input: 'http://0xA9FEA9FE/',
    category: 'ipv4-hex',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Hex metadata address; also checks that uppercase hex digits are handled.',
  },
  {
    id: 'ipv4-hex-private-octets',
    input: 'http://0xc0.0xa8.0x00.0x01/',
    category: 'ipv4-hex',
    expect: 'block',
    normalisedHost: '192.168.0.1',
    rationale: 'All four octets in hex, which looks nothing like an RFC 1918 address to a textual filter.',
  },

  // ── IPv4, omitted octets ──────────────────────────────────────────────────
  {
    id: 'ipv4-short-127-1',
    input: 'http://127.1/',
    category: 'ipv4-short',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Two-part form: the last part fills the remaining 24 bits, so 127.1 is loopback.',
  },
  {
    id: 'ipv4-short-10-1',
    input: 'http://10.1/',
    category: 'ipv4-short',
    expect: 'block',
    normalisedHost: '10.0.0.1',
    rationale: 'Short form of an RFC 1918 host, which an "is it in 10.x.x.x" string test never recognises.',
  },
  {
    id: 'ipv4-short-172-16-1',
    input: 'http://172.16.1/',
    category: 'ipv4-short',
    expect: 'block',
    normalisedHost: '172.16.0.1',
    rationale: 'Three-part form; the final part spans the low 16 bits rather than becoming the last octet.',
  },
  {
    id: 'ipv4-short-zero',
    input: 'http://0/',
    category: 'ipv4-short',
    expect: 'block',
    normalisedHost: '0.0.0.0',
    rationale: 'A single zero becomes 0.0.0.0, which on Linux reaches any service bound to the loopback interface.',
  },
  {
    id: 'ipv4-short-mixed-radix',
    input: 'http://127.0.0.0x1/',
    category: 'ipv4-short',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Hex in the final octet only — the kind of hybrid that hand-written address validators miss.',
  },

  // ── IPv4, plain private ranges ────────────────────────────────────────────
  {
    id: 'ipv4-private-10',
    input: 'http://10.0.0.1/',
    category: 'ipv4-private',
    expect: 'block',
    normalisedHost: '10.0.0.1',
    rationale: 'Baseline RFC 1918 case: if this is allowed, nothing else in the corpus matters.',
  },
  {
    id: 'ipv4-private-172-16-low',
    input: 'http://172.16.0.1/',
    category: 'ipv4-private',
    expect: 'block',
    normalisedHost: '172.16.0.1',
    rationale: 'Bottom of 172.16/12 — the range most often implemented as the wrong prefix length.',
  },
  {
    id: 'ipv4-private-172-31-high',
    input: 'http://172.31.255.255/',
    category: 'ipv4-private',
    expect: 'block',
    normalisedHost: '172.31.255.255',
    rationale: 'Top of 172.16/12; a filter that wrote 172.16/16 instead of /12 allows this.',
  },
  {
    id: 'ipv4-private-192-168',
    input: 'http://192.168.0.1/',
    category: 'ipv4-private',
    expect: 'block',
    normalisedHost: '192.168.0.1',
    rationale: 'Baseline home/office LAN range, reachable from any container with host networking.',
  },
  {
    id: 'ipv4-loopback-high',
    input: 'http://127.255.255.254/',
    category: 'ipv4-private',
    expect: 'block',
    normalisedHost: '127.255.255.254',
    rationale: 'Loopback is a /8: this address reaches the same local services as 127.0.0.1 but matches no "127.0.0.1" string test.',
  },

  // ── IPv4, other reserved space ────────────────────────────────────────────
  {
    id: 'ipv4-broadcast',
    input: 'http://255.255.255.255/',
    category: 'ipv4-reserved',
    expect: 'block',
    normalisedHost: '255.255.255.255',
    rationale: 'Limited broadcast; never a legitimate HTTP destination and useful to an attacker for internal noise.',
  },
  {
    id: 'ipv4-multicast-ssdp',
    input: 'http://239.255.255.250/',
    category: 'ipv4-reserved',
    expect: 'block',
    normalisedHost: '239.255.255.250',
    rationale: 'The SSDP group address — a fetch here is a request to every UPnP device on the segment.',
  },
  {
    id: 'ipv4-multicast-all-hosts',
    input: 'http://224.0.0.1/',
    category: 'ipv4-reserved',
    expect: 'block',
    normalisedHost: '224.0.0.1',
    rationale: 'All-hosts multicast group, at the bottom of 224/4; blocklists written as three /8s miss most of that range.',
  },
  {
    id: 'ipv4-benchmark',
    input: 'http://198.18.0.1/',
    category: 'ipv4-reserved',
    expect: 'block',
    normalisedHost: '198.18.0.1',
    rationale: 'RFC 2544 benchmarking space, which some providers route internally and almost no blocklist includes.',
  },

  // ── Carrier-grade NAT ─────────────────────────────────────────────────────
  {
    id: 'cgnat-low',
    input: 'http://100.64.0.1/',
    category: 'cgnat',
    expect: 'block',
    normalisedHost: '100.64.0.1',
    rationale: 'Bottom of 100.64/10 (RFC 6598); inside many cloud networks this reaches provider infrastructure.',
  },
  {
    id: 'cgnat-high',
    input: 'http://100.127.255.255/',
    category: 'cgnat',
    expect: 'block',
    normalisedHost: '100.127.255.255',
    rationale: 'Top of 100.64/10 — the boundary a filter using /8 or /16 by mistake gets wrong.',
  },
  {
    id: 'cgnat-alibaba-metadata',
    input: 'http://100.100.100.200/latest/meta-data/',
    category: 'cgnat',
    expect: 'block',
    normalisedHost: '100.100.100.200',
    rationale: 'Alibaba Cloud instance metadata: a real credential endpoint that private-range-only filters allow.',
  },
  {
    id: 'cgnat-below-range',
    input: 'http://100.63.255.255/',
    category: 'cgnat',
    expect: 'allow',
    normalisedHost: '100.63.255.255',
    rationale: 'One address below 100.64/10 and globally routable — catches a filter that blocks all of 100/8.',
  },
  {
    id: 'cgnat-above-range',
    input: 'http://100.128.0.1/',
    category: 'cgnat',
    expect: 'allow',
    normalisedHost: '100.128.0.1',
    rationale: 'One address above 100.64/10 and globally routable, for the same reason.',
  },

  // ── Link-local ────────────────────────────────────────────────────────────
  {
    id: 'linklocal-aws-imds-creds',
    input: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    category: 'linklocal',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'The request that turns an SSRF into AWS credentials; the baseline every filter claims to stop.',
  },
  {
    id: 'linklocal-aws-time-sync',
    input: 'http://169.254.169.123/',
    category: 'linklocal',
    expect: 'block',
    normalisedHost: '169.254.169.123',
    rationale: 'AWS time sync service — link-local is a whole /16, not one address.',
  },
  {
    id: 'linklocal-arbitrary',
    input: 'http://169.254.1.1/',
    category: 'linklocal',
    expect: 'block',
    normalisedHost: '169.254.1.1',
    rationale: 'Ordinary autoconfiguration address, included so the range is tested rather than the famous host.',
  },

  // ── Cloud metadata services ───────────────────────────────────────────────
  {
    id: 'metadata-aws-imdsv2-token',
    input: 'http://169.254.169.254/latest/api/token',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'IMDSv2 token endpoint: reachable by SSRF only if the vulnerable client can send PUT and custom headers.',
  },
  {
    id: 'metadata-aws-ipv6',
    input: 'http://[fd00:ec2::254]/latest/meta-data/',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: 'fd00:ec2::254',
    rationale: 'AWS serves IMDS over IPv6 at this unique-local address, which no IPv4 blocklist can express.',
  },
  {
    id: 'metadata-gcp-token',
    input: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: 'metadata.google.internal',
    rationale: 'GCP service-account token endpoint, addressed by name — an address-only filter never sees an IP here.',
  },
  {
    id: 'metadata-gcp-goog',
    input: 'http://metadata.goog/computeMetadata/v1/',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: 'metadata.goog',
    rationale: 'GCP alternative metadata name; a deny-list containing only metadata.google.internal misses it.',
  },
  {
    id: 'metadata-gcp-by-ip',
    input: 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Same GCP endpoint by address, which also needs the Metadata-Flavor header to answer.',
  },
  {
    id: 'metadata-azure-imds',
    input: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Azure IMDS, which shares the link-local address but requires the api-version query parameter.',
  },
  {
    id: 'metadata-digitalocean',
    input: 'http://169.254.169.254/metadata/v1.json',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'DigitalOcean metadata returns user-data in one JSON document, which often contains provisioning secrets.',
  },
  {
    id: 'metadata-oracle-oci',
    input: 'http://169.254.169.254/opc/v2/instance/',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Oracle Cloud metadata v2 at the same address under a different path prefix.',
  },
  {
    id: 'metadata-ec2-legacy-name',
    input: 'http://instance-data/latest/meta-data/',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: 'instance-data',
    rationale: 'EC2 resolves the unqualified name instance-data to the metadata service — a single-label host with no dots to validate.',
  },
  {
    id: 'metadata-ec2-legacy-fqdn',
    input: 'http://instance-data.ec2.internal/latest/meta-data/',
    category: 'cloud-metadata',
    expect: 'block',
    normalisedHost: 'instance-data.ec2.internal',
    rationale: 'The qualified form of the same name, which is why .internal is refused as a suffix rather than host by host.',
  },

  // ── IPv6 loopback and unspecified ─────────────────────────────────────────
  {
    id: 'ipv6-loopback-short',
    input: 'http://[::1]/',
    category: 'ipv6-loopback',
    expect: 'block',
    normalisedHost: '::1',
    rationale: 'IPv6 loopback: on a dual-stack host, services on 127.0.0.1 are frequently also on ::1.',
  },
  {
    id: 'ipv6-loopback-expanded',
    input: 'http://[0:0:0:0:0:0:0:1]/',
    category: 'ipv6-loopback',
    expect: 'block',
    normalisedHost: '::1',
    rationale: 'Fully written loopback, which the parser compresses — so a deny-list of literal strings needs only one entry, if it compares post-parse.',
  },
  {
    id: 'ipv6-loopback-padded',
    input: 'http://[::0001]/',
    category: 'ipv6-loopback',
    expect: 'block',
    normalisedHost: '::1',
    rationale: 'Zero-padded group; the parser strips the padding, confirming textual comparison is safe only after parsing.',
  },
  {
    id: 'ipv6-unspecified',
    input: 'http://[::]/',
    category: 'ipv6-loopback',
    expect: 'block',
    normalisedHost: '::',
    rationale: 'The unspecified address — the IPv6 counterpart of 0.0.0.0 and equally able to reach local listeners.',
  },

  // ── IPv6, v4-mapped (RFC 4291) ────────────────────────────────────────────
  {
    id: 'ipv6-v4mapped-loopback',
    input: 'http://[::ffff:127.0.0.1]/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:7f00:1',
    rationale: 'The core bug class: the parser rewrites the embedded IPv4 as hex, so the string "127." is gone while the route to loopback remains.',
  },
  {
    id: 'ipv6-v4mapped-loopback-hex',
    input: 'http://[::ffff:7f00:1]/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:7f00:1',
    rationale: 'The same address written in hex to begin with — what an attacker sends once they know the parser normalises it anyway.',
  },
  {
    id: 'ipv6-v4mapped-metadata',
    input: 'http://[::ffff:169.254.169.254]/latest/meta-data/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:a9fe:a9fe',
    rationale: 'Cloud metadata as a v4-mapped address: the highest-value instance of the bypass.',
  },
  {
    id: 'ipv6-v4mapped-private',
    input: 'http://[::ffff:10.0.0.1]/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:a00:1',
    rationale: 'RFC 1918 target through the v4-mapped prefix; the hex form a00:1 defeats any 10.x pattern.',
  },
  {
    id: 'ipv6-v4mapped-alibaba',
    input: 'http://[::ffff:100.100.100.200]/latest/meta-data/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:6464:64c8',
    rationale: 'Two omissions chained: CGNAT metadata reached through a v4-mapped address.',
  },
  {
    id: 'ipv6-v4mapped-zero',
    input: 'http://[::ffff:0.0.0.0]/',
    category: 'ipv6-v4mapped',
    expect: 'block',
    normalisedHost: '::ffff:0:0',
    rationale: 'v4-mapped 0.0.0.0, which still designates every local interface.',
  },
  {
    id: 'ipv6-v4mapped-public',
    input: 'http://[::ffff:8.8.8.8]/',
    category: 'ipv6-v4mapped',
    expect: 'allow',
    normalisedHost: '::ffff:808:808',
    rationale: 'A v4-mapped public address must still be allowed — this catches filters that block the ::ffff: prefix wholesale.',
  },

  // ── IPv6, v4-compatible (deprecated, still parsed) ────────────────────────
  {
    id: 'ipv6-v4compat-loopback',
    input: 'http://[::127.0.0.1]/',
    category: 'ipv6-v4compatible',
    expect: 'block',
    normalisedHost: '::7f00:1',
    rationale: 'Deprecated v4-compatible form; it normalises to ::7f00:1, which looks like an ordinary IPv6 address.',
  },
  {
    id: 'ipv6-v4compat-metadata',
    input: 'http://[::169.254.169.254]/latest/meta-data/',
    category: 'ipv6-v4compatible',
    expect: 'block',
    normalisedHost: '::a9fe:a9fe',
    rationale: 'Metadata address in v4-compatible form, which no v4-mapped-only check recovers.',
  },
  {
    id: 'ipv6-v4compat-low',
    input: 'http://[::2]/',
    category: 'ipv6-v4compatible',
    expect: 'block',
    normalisedHost: '::2',
    rationale: '::2 is indistinguishable from v4-compatible 0.0.0.2, so it belongs to the reserved zero prefix either way.',
  },
  {
    id: 'ipv6-v4compat-collapses-to-loopback',
    input: 'http://[::0.0.0.1]/',
    category: 'ipv6-v4compatible',
    expect: 'block',
    normalisedHost: '::1',
    rationale: 'The parser turns v4-compatible 0.0.0.1 into ::1 — a reminder that it rewrites addresses, not just reformats them.',
  },

  // ── IPv6, NAT64 (RFC 6052) ────────────────────────────────────────────────
  {
    id: 'ipv6-nat64-loopback',
    input: 'http://[64:ff9b::127.0.0.1]/',
    category: 'ipv6-nat64',
    expect: 'block',
    normalisedHost: '64:ff9b::7f00:1',
    rationale: 'The well-known NAT64 prefix carrying loopback; on a NAT64 network this is translated and delivered.',
  },
  {
    id: 'ipv6-nat64-metadata',
    input: 'http://[64:ff9b::169.254.169.254]/latest/meta-data/',
    category: 'ipv6-nat64',
    expect: 'block',
    normalisedHost: '64:ff9b::a9fe:a9fe',
    rationale: 'NAT64-encoded metadata address, relevant on IPv6-only clusters where NAT64 is how egress works.',
  },
  {
    id: 'ipv6-nat64-public',
    input: 'http://[64:ff9b::8.8.8.8]/',
    category: 'ipv6-nat64',
    expect: 'allow',
    normalisedHost: '64:ff9b::808:808',
    rationale: 'NAT64 to a public address is ordinary traffic on such a network and must not be blocked by prefix alone.',
  },

  // ── IPv6, 6to4 (RFC 3056) ─────────────────────────────────────────────────
  {
    id: 'ipv6-6to4-loopback',
    input: 'http://[2002:7f00:1::1]/',
    category: 'ipv6-6to4',
    expect: 'block',
    normalisedHost: '2002:7f00:1::1',
    rationale: '6to4 keeps the IPv4 address in bits 16-48: 7f00:1 is 127.0.0.1, in a form with no zero prefix to notice.',
  },
  {
    id: 'ipv6-6to4-private',
    input: 'http://[2002:c0a8:1::1]/',
    category: 'ipv6-6to4',
    expect: 'block',
    normalisedHost: '2002:c0a8:1::1',
    rationale: '6to4 wrapping 192.168.0.1 — the embedded address must be extracted and range-checked like any other.',
  },
  {
    id: 'ipv6-6to4-metadata',
    input: 'http://[2002:a9fe:a9fe::]/',
    category: 'ipv6-6to4',
    expect: 'block',
    normalisedHost: '2002:a9fe:a9fe::',
    rationale: '6to4 wrapping 169.254.169.254, which looks like a routable global address to a prefix-based filter.',
  },
  {
    id: 'ipv6-6to4-public',
    input: 'http://[2002:808:808::1]/',
    category: 'ipv6-6to4',
    expect: 'allow',
    normalisedHost: '2002:808:808::1',
    rationale: '6to4 wrapping 8.8.8.8: 2002::/16 is globally assigned, so the prefix alone is not grounds to block.',
  },

  // ── IPv6, unique-local and link-local ─────────────────────────────────────
  {
    id: 'ipv6-ula-fc00',
    input: 'http://[fc00::1]/',
    category: 'ipv6-ula',
    expect: 'block',
    normalisedHost: 'fc00::1',
    rationale: 'Bottom of fc00::/7 — the IPv6 equivalent of RFC 1918 and routinely used inside clusters.',
  },
  {
    id: 'ipv6-ula-fd',
    input: 'http://[fd12:3456:789a::1]/',
    category: 'ipv6-ula',
    expect: 'block',
    normalisedHost: 'fd12:3456:789a::1',
    rationale: 'A randomly generated fd00::/8 prefix, the half of fc00::/7 actually in use; a filter testing only fc00:: misses it.',
  },
  {
    id: 'ipv6-linklocal-one',
    input: 'http://[fe80::1]/',
    category: 'ipv6-linklocal',
    expect: 'block',
    normalisedHost: 'fe80::1',
    rationale: 'IPv6 link-local, the range that carries router and neighbour services on every interface.',
  },
  {
    id: 'ipv6-linklocal-eui64',
    input: 'http://[fe80::a00:27ff:fe00:1]/',
    category: 'ipv6-linklocal',
    expect: 'block',
    normalisedHost: 'fe80::a00:27ff:fe00:1',
    rationale: 'EUI-64 derived link-local address; fe80::/10 must be matched as a prefix, not as the literal fe80::1.',
  },

  // ── IPv6, multicast and reserved ──────────────────────────────────────────
  {
    id: 'ipv6-multicast-all-nodes',
    input: 'http://[ff02::1]/',
    category: 'ipv6-multicast',
    expect: 'block',
    normalisedHost: 'ff02::1',
    rationale: 'All-nodes link-local multicast: one request addressed to every host on the segment.',
  },
  {
    id: 'ipv6-multicast-ff00',
    input: 'http://[ff00::1]/',
    category: 'ipv6-multicast',
    expect: 'block',
    normalisedHost: 'ff00::1',
    rationale: 'Bottom of ff00::/8, included so the whole multicast prefix is covered rather than the well-known groups.',
  },
  {
    id: 'ipv6-reserved-v4translated',
    input: 'http://[::ffff:0:127.0.0.1]/',
    category: 'ipv6-reserved',
    expect: 'block',
    normalisedHost: '::ffff:0:7f00:1',
    rationale: 'The deprecated IPv4-translated form ::ffff:0:a.b.c.d: not v4-mapped, so extraction skips it, but it sits in IETF-reserved ::/8 and must not be fetched.',
  },

  // ── Hostnames that mean "here" ────────────────────────────────────────────
  {
    id: 'alias-localhost',
    input: 'http://localhost/',
    category: 'hostname-alias',
    expect: 'block',
    normalisedHost: 'localhost',
    rationale: 'The name, not the address — a filter that only checks IP ranges allows it and lets the resolver do the work.',
  },
  {
    id: 'alias-localhost-uppercase',
    input: 'http://LOCALHOST/',
    category: 'hostname-alias',
    expect: 'block',
    normalisedHost: 'localhost',
    rationale: 'The parser lowercases hosts, so case variation is not a bypass — provided the comparison happens after parsing.',
  },
  {
    id: 'alias-localhost-port',
    input: 'http://LocalHost:8080/',
    category: 'hostname-alias',
    expect: 'block',
    normalisedHost: 'localhost',
    rationale: 'Mixed case with a port: the port belongs to the URL, not the hostname, which filters splitting on ":" get wrong.',
  },
  {
    id: 'alias-localhost-subdomain',
    input: 'http://foo.localhost/',
    category: 'hostname-alias',
    expect: 'block',
    normalisedHost: 'foo.localhost',
    rationale: 'RFC 6761 reserves the whole .localhost tree for loopback, so an exact-match deny-list is insufficient.',
  },
  {
    id: 'alias-localhost-deep',
    input: 'http://api.staging.localhost/',
    category: 'hostname-alias',
    expect: 'block',
    normalisedHost: 'api.staging.localhost',
    rationale: 'A multi-label .localhost name, which looks like an ordinary internal hostname to a suffix check written for one label.',
  },

  // ── Userinfo: what the authority actually is ──────────────────────────────
  {
    id: 'userinfo-at-loopback',
    input: 'http://example.com@127.0.0.1/',
    category: 'userinfo-confusion',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Everything before the last @ is credentials: the host is 127.0.0.1, though the string begins with an allowlisted domain.',
  },
  {
    id: 'userinfo-credentials-metadata',
    input: 'http://user:pass@169.254.169.254/latest/meta-data/',
    category: 'userinfo-confusion',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'A user:password pair in front of the metadata address, which makes a naive "starts with http://169.254" check fail open.',
  },
  {
    id: 'userinfo-at-v4mapped',
    input: 'http://example.com@[::ffff:127.0.0.1]/',
    category: 'userinfo-confusion',
    expect: 'block',
    normalisedHost: '::ffff:7f00:1',
    rationale: 'Userinfo plus v4-mapped IPv6 — two independent tricks that each defeat a different half of a textual filter.',
  },
  {
    id: 'userinfo-backslash-terminates-authority',
    input: 'http://127.0.0.1\\@example.com/',
    category: 'userinfo-confusion',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'In special schemes a backslash ends the authority, so the host is 127.0.0.1 and the @example.com is path — a regex that reads up to the @ gets the opposite answer.',
  },
  {
    id: 'userinfo-fragment-after-host',
    input: 'http://127.0.0.1#@example.com/',
    category: 'userinfo-confusion',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'The fragment begins at # and cannot contain userinfo, so the trailing @example.com never affects the host.',
  },
  {
    id: 'userinfo-encoded-slash-in-userinfo',
    input: 'http://127.0.0.1%2f@example.com/',
    category: 'userinfo-confusion',
    expect: 'needs-resolution',
    normalisedHost: 'example.com',
    rationale: 'Here the loopback address really is userinfo: a percent-encoded slash does not end the authority, so the host is example.com and blocking it is an over-block.',
  },
  {
    id: 'userinfo-port-then-at',
    input: 'http://169.254.169.254:80@example.com/',
    category: 'userinfo-confusion',
    expect: 'needs-resolution',
    normalisedHost: 'example.com',
    rationale: 'Looks like the metadata address with a port, but the whole thing is userinfo — the mirror image of the attack and a genuine over-block risk.',
  },
  {
    id: 'userinfo-bracketed-then-at',
    input: 'http://[::1]@example.com/',
    category: 'userinfo-confusion',
    expect: 'needs-resolution',
    normalisedHost: 'example.com',
    rationale: 'A bracketed loopback literal in userinfo position; the destination is example.com.',
  },

  // ── IDN mapping happens before you see the host ───────────────────────────
  {
    id: 'idn-circled-digits-metadata',
    input: 'http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/latest/meta-data/',
    category: 'idn',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Circled digits map to ASCII digits during IDNA processing, so this input arrives as the metadata address.',
  },
  {
    id: 'idn-fullwidth-loopback',
    input: 'http://１２７.０.０.１/',
    category: 'idn',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'Full-width digits become ASCII, then the result is parsed as an address — a filter rejecting non-ASCII hosts outright would be safe here, but one passing them through is not.',
  },
  {
    id: 'idn-fullwidth-short-form',
    input: 'http://１２７.1/',
    category: 'idn',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'IDNA mapping and short-form address expansion compose: two transformations before the filter runs.',
  },
  {
    id: 'idn-circled-letter-localhost',
    input: 'http://ⓛocalhost/',
    category: 'idn',
    expect: 'block',
    normalisedHost: 'localhost',
    rationale: 'The circled letter maps to "l", producing the literal name localhost from input that contains no ASCII "l".',
  },
  {
    id: 'idn-small-letter-localhost',
    input: 'http://ⅼocalhost/',
    category: 'idn',
    expect: 'block',
    normalisedHost: 'localhost',
    rationale: 'A second codepoint that maps to "l" — mapping is a table, so enumerating lookalikes is the wrong defence.',
  },
  {
    id: 'idn-digits-public-domain',
    input: 'http://⑦⑦.com/',
    category: 'idn',
    expect: 'needs-resolution',
    normalisedHost: '77.com',
    rationale: 'Mapping also produces perfectly ordinary public hostnames, so non-ASCII input is not by itself evidence of an attack.',
  },

  // ── Trailing dots ─────────────────────────────────────────────────────────
  {
    id: 'trailing-dot-loopback',
    input: 'http://127.0.0.1./',
    category: 'trailing-dot',
    expect: 'block',
    normalisedHost: '127.0.0.1',
    rationale: 'One trailing dot on an address-shaped host is stripped by the parser, so this case is already handled.',
  },
  {
    id: 'trailing-dot-localhost',
    input: 'http://localhost./',
    category: 'trailing-dot',
    expect: 'block',
    normalisedHost: 'localhost.',
    rationale: 'On a name the dot survives parsing, so "localhost." is not equal to "localhost" and an exact-match deny-list fails.',
  },
  {
    id: 'trailing-dot-gcp-metadata',
    input: 'http://metadata.google.internal./computeMetadata/v1/',
    category: 'trailing-dot',
    expect: 'block',
    normalisedHost: 'metadata.google.internal.',
    rationale: 'The fully qualified metadata name still resolves with the root label present, so name comparisons must normalise it away.',
  },
  {
    id: 'trailing-dot-double-metadata',
    input: 'http://169.254.169.254../',
    category: 'trailing-dot',
    expect: 'block',
    normalisedHost: '169.254.169.254..',
    rationale: 'Two trailing dots stop the parser treating the host as an address at all: it stays a domain, so every IPv4 range check is skipped.',
  },
  {
    id: 'trailing-dot-octal-metadata',
    input: 'http://0251.0376.0251.0376./',
    category: 'trailing-dot',
    expect: 'block',
    normalisedHost: '169.254.169.254',
    rationale: 'Octal octets plus a trailing dot, to confirm the two normalisations do not interfere.',
  },

  // ── Names a lexical filter cannot decide ──────────────────────────────────
  {
    id: 'rebinding-localtest-me',
    input: 'http://localtest.me/',
    category: 'rebinding',
    expect: 'needs-resolution',
    normalisedHost: 'localtest.me',
    rationale: 'A real public domain whose A record is 127.0.0.1: lexically indistinguishable from any other hostname, which is why resolution must precede the decision.',
  },
  {
    id: 'rebinding-nip-io-loopback',
    input: 'http://127.0.0.1.nip.io/',
    category: 'rebinding',
    expect: 'needs-resolution',
    normalisedHost: '127.0.0.1.nip.io',
    rationale: 'A wildcard DNS service that resolves any embedded address; the host contains "127.0.0.1" but blocking on that substring is matching the wrong thing for the wrong reason.',
  },
  {
    id: 'rebinding-nip-io-metadata',
    input: 'http://169.254.169.254.nip.io/latest/meta-data/',
    category: 'rebinding',
    expect: 'needs-resolution',
    normalisedHost: '169.254.169.254.nip.io',
    rationale: 'The same service pointed at the metadata address — the resolved answer is what must be classified and then pinned.',
  },
  {
    id: 'rebinding-plain-domain',
    input: 'http://example.com/',
    category: 'rebinding',
    expect: 'needs-resolution',
    normalisedHost: 'example.com',
    rationale: 'An ordinary hostname is in this bucket too: nothing lexical separates it from localtest.me, and a filter that answers "allow" without resolving is guessing.',
  },

  // ── Public destinations that must not be blocked ──────────────────────────
  {
    id: 'public-google-dns',
    input: 'http://8.8.8.8/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '8.8.8.8',
    rationale: 'A public address literal; blocking it means the filter is denying by shape rather than by range.',
  },
  {
    id: 'public-cloudflare-dns',
    input: 'http://1.1.1.1/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '1.1.1.1',
    rationale: 'Short-looking but complete address, included because it is frequently caught by over-eager "is this suspicious" heuristics.',
  },
  {
    id: 'public-172-15-below-rfc1918',
    input: 'http://172.15.0.1/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '172.15.0.1',
    rationale: 'Just below 172.16/12 and globally routable — catches a filter that blocks all of 172/8.',
  },
  {
    id: 'public-172-32-above-rfc1918',
    input: 'http://172.32.0.1/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '172.32.0.1',
    rationale: 'Just above 172.16/12, the other side of the boundary most often implemented wrongly.',
  },
  {
    id: 'public-198-20-above-benchmark',
    input: 'http://198.20.0.1/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '198.20.0.1',
    rationale: 'Immediately above 198.18/15, confirming that range is matched at /15 and not rounded to /14 or /8.',
  },
  {
    id: 'public-ipv6-cloudflare',
    input: 'http://[2606:4700:4700::1111]/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '2606:4700:4700::1111',
    rationale: 'A global IPv6 address: filters that cannot reason about IPv6 often block every bracketed host, which breaks IPv6-only clients.',
  },
  {
    id: 'public-ipv6-google',
    input: 'http://[2001:4860:4860::8888]/',
    category: 'public-allow',
    expect: 'allow',
    normalisedHost: '2001:4860:4860::8888',
    rationale: 'A second global IPv6 address, in 2001::/16 where filters sometimes confuse Teredo (2001:0::/32) with the whole prefix.',
  },
  {
    id: 'public-domain-github-api',
    input: 'https://api.github.com/meta',
    category: 'public-allow',
    expect: 'needs-resolution',
    normalisedHost: 'api.github.com',
    rationale: 'The ordinary case an SSRF filter exists to permit, and still a name: it has to be resolved before it can be cleared.',
  },

  // ── Input that does not parse ─────────────────────────────────────────────
  {
    id: 'malformed-ipv6-zone-id',
    input: 'http://[fe80::1%25eth0]/',
    category: 'malformed',
    expect: 'block',
    rationale: 'The WHATWG parser rejects zone identifiers, so this never reaches a host check — the filter must fail closed instead of throwing or defaulting to allow.',
  },
  {
    id: 'malformed-no-scheme',
    input: '//169.254.169.254/latest/meta-data/',
    category: 'malformed',
    expect: 'block',
    rationale: 'A scheme-relative reference has no host until it is resolved against a base URL; treating it as a bare string is how metadata fetches get through.',
  },
];

/** Entries in one category, in corpus order. */
export function byCategory(category: Category): readonly CorpusEntry[] {
  return CORPUS.filter((e) => e.category === category);
}

/** Look up a single entry by its stable id. */
export function entryById(id: string): CorpusEntry | undefined {
  return CORPUS.find((e) => e.id === id);
}
