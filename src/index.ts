/**
 * ssrf-filter-corpus — a verified corpus and harness for SSRF destination filters.
 *
 * Start with {@link runCorpus} to score your own filter, or {@link classifyTarget}
 * for the reference blocklist this corpus is built against. {@link normaliseHost}
 * and {@link extractEmbeddedIPv4} are the two pieces worth lifting into your own
 * code if you only want the parsing.
 */

export {
  normaliseHost,
  isDottedQuad,
  expandIPv6,
  extractEmbeddedIPv4,
  type HostKind,
  type NormalisedHost,
  type EmbeddedIPv4,
} from './normalize.js';

export {
  classifyTarget,
  classifyHost,
  referenceFilter,
  isPrivateIPv4,
  ipv4Reservation,
  ipv4ToInt,
  IPV4_RESERVED,
  DANGEROUS_NAMES,
  DANGEROUS_SUFFIXES,
  type Verdict,
  type BlockVerdict,
  type AllowVerdict,
  type NeedsResolutionVerdict,
  type BlockCategory,
  type Ipv4Reservation,
} from './classify.js';

export {
  CORPUS,
  CATEGORIES,
  byCategory,
  entryById,
  type Category,
  type CorpusEntry,
  type Expectation,
} from './corpus.js';

export {
  runCorpus,
  formatReport,
  type FilterFn,
  type Outcome,
  type EntryResult,
  type CategoryStats,
  type CorpusReport,
  type RunOptions,
} from './harness.js';
