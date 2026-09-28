/**
 * Turns the findings ten steps produced independently into one document's
 * worth: stable ids, one entry per real problem, a citation proved against
 * disk, and a total order that two runs over an unchanged repository agree on
 * byte for byte.
 *
 * The four passes, in the order they run:
 *
 * 1. **Identity** — every finding carries a hash of *what it is about*
 *    (domain, rule, file, symbol) and of nothing else. Not the message, not the
 *    line: the id hashes the symbol rather than the line, so an edit above a
 *    finding does not change its identity, and a diff between two runs shows
 *    the findings that changed rather than every finding in the file.
 * 2. **Verification** — every finding goes through `src/verify`, which resolves
 *    the citation against the repository and replaces the snippet with one it
 *    read itself. Anything that does not resolve is dropped and counted.
 * 3. **Severity** — `severity.ts` applies the escalation rules uniformly, so a
 *    secret graded by its file and a CVE graded by its band both get Sentinel's
 *    judgement rather than the tool's. `_file-kind.ts` then applies the one
 *    policy that can *lower* a severity: a finding in test or fixture code is
 *    capped, says so in its title, and names the severity it came from.
 * 4. **Deduplication and ordering** — two tools reporting the same problem
 *    become one finding that names both, and the result is sorted by severity,
 *    domain, file and line.
 */

import {
  type CodeRef,
  type Confidence,
  type Domain,
  DomainSchema,
  type Finding,
  type Severity,
} from "../contracts/findings.ts";
import type { DropReason, VerifyFileSystem } from "../verify/index.ts";
import { DROP_REASONS, resolveRepoPath, verifyFindings } from "../verify/index.ts";
import { type FileKind, decideFileKind } from "./_file-kind.ts";
import { HADOLINT_OVERLAP, TRIVY_CONFIG_OVERLAP } from "./rules/container.ts";
import { HADOLINT_STEP } from "./runners/hadolint.ts";
import { TRIVY_STEP } from "./runners/trivy.ts";
import { type SignalOptions, compareSeverity, escalateFinding, severityRank } from "./severity.ts";

/**
 * Separator for the hashed identity of a finding. ASCII 31 (unit separator)
 * cannot occur in a domain, a rule id, a path or a symbol name, so no two
 * different identities can collide by concatenation.
 */
const ID_SEPARATOR = String.fromCharCode(31);

/** Characters of the sha-256 kept. 64 bits is plenty to keep a repo's findings apart. */
const ID_LENGTH = 16;

/**
 * The canonical finding id: stable across runs and machines, and deliberately
 * blind to the message and the line number so an edit elsewhere in the file
 * does not retire a finding and mint a new one in its place.
 */
export function stableFindingId(
  domain: Domain,
  rule: string,
  file: string,
  symbol: string,
): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update([domain, rule, file, symbol].join(ID_SEPARATOR));
  return hasher.digest("hex").slice(0, ID_LENGTH);
}

/**
 * Steps that extract their own snippet and must not be re-verified.
 *
 * gitleaks is the only one. Its citations are deliberately not re-readable:
 * the snippet is masked before it is stored, so re-extracting it would print
 * the credential the report exists to warn about, and a secret that lives only
 * in git history cites a file that is *supposed* to be absent from the working
 * tree. Both of those look like verification failures and are not. Its findings
 * still get the containment check below, so a citation can never point outside
 * the repository.
 */
export const SELF_VERIFIED_SOURCES: ReadonlySet<string> = new Set(["gitleaks"]);

/** The filesystem operations normalisation needs; the real port satisfies it. */
export interface NormaliseFileSystem {
  readFileBytes(path: string): Promise<Uint8Array>;
  realpath(path: string): Promise<string>;
}

/** What {@link normaliseFindings} needs to resolve a citation and grade a finding. */
export interface NormaliseOptions extends SignalOptions {
  /** Absolute path of the repository every citation is resolved against. */
  readonly targetDir: string;
  readonly fs: NormaliseFileSystem;
}

/** A finding that was refused, kept so the run can report what it threw away. */
export interface NormaliseDrop {
  readonly id: string;
  readonly rule: string;
  readonly file: string;
  readonly reason: DropReason;
  readonly detail: string;
}

/** Two tools that reported one problem, and which of them the document kept. */
export interface MergedFinding {
  readonly id: string;
  readonly rule: string;
  readonly file: string;
  readonly line: number;
  /** The source whose finding survived, because it carried the most. */
  readonly kept: string;
  /** Every other source that reported the same thing, sorted. */
  readonly alsoReportedBy: readonly string[];
}

/** A finding whose severity the policy moved, and the rule that moved it. */
export interface Escalation {
  readonly id: string;
  readonly rule: string;
  readonly from: string;
  readonly to: string;
}

/**
 * A finding the file-kind policy lowered: the only downgrade in the pipeline,
 * and therefore the one that has to be counted.
 *
 * The finding itself is never removed and never loses what it was: the title
 * says where the code lives, the description names the severity it came from and
 * the rule that capped it, and the analyzer's own grade is untouched in `raw/`.
 */
export interface SeverityCap {
  readonly id: string;
  readonly rule: string;
  readonly file: string;
  /** What the path was classified as, e.g. `test`. */
  readonly fileKind: FileKind;
  /** The shape that decided the classification, e.g. `*.test.*`. */
  readonly pattern: string;
  /** What the finding carried before the cap. */
  readonly from: Severity;
  readonly to: Severity;
}

/** Everything normalisation produced, including what it refused. */
export interface NormaliseResult {
  /** Verified, deduplicated and sorted. This is what `findings.json` carries. */
  readonly findings: readonly Finding[];
  /** Findings whose citation did not resolve; feeds `FindingsDocument.droppedFindings`. */
  readonly droppedFindings: number;
  readonly dropped: readonly NormaliseDrop[];
  /** Drop count per reason, for the coverage section of the report. */
  readonly dropReasons: Readonly<Record<DropReason, number>>;
  /** Evidence pointers removed from otherwise valid findings. */
  readonly droppedEvidence: number;
  /** Findings whose cited line the verifier had to correct. */
  readonly relocated: number;
  readonly merged: readonly MergedFinding[];
  readonly escalations: readonly Escalation[];
  /**
   * Findings the file-kind policy lowered, one entry each.
   *
   * Phase 1's own artifact (`scan-report.json`) has no field for these yet, so
   * the count a reader sees today is the one in the findings themselves — every
   * capped finding's title starts with the policy's prefix. Adding
   * `capped: normalised.capped` to the scan report is a one-line change in
   * `scan.ts` and one field in `artifacts.ts`.
   */
  readonly capped: readonly SeverityCap[];
}

/** Adapts the filesystem port to the narrower seam the citation verifier takes. */
function verifyFileSystem(fs: NormaliseFileSystem): VerifyFileSystem {
  return {
    readBytes: (path: string) => fs.readFileBytes(path),
    realpath: (path: string) => fs.realpath(path),
  };
}

/** A zeroed counter for every drop reason, so the report never shows a gap. */
function emptyReasons(): Record<DropReason, number> {
  const reasons = {} as Record<DropReason, number>;
  for (const reason of DROP_REASONS) reasons[reason] = 0;
  return reasons;
}

/** Gives a finding an id when its producer left one out; never rewrites a good one. */
function withStableId(finding: Finding): Finding {
  if (finding.id.trim() !== "") return finding;
  // No symbol survives into the finding, so the file is all the identity there
  // is left. A producer that wants a sharper id assigns one at construction.
  return {
    ...finding,
    id: stableFindingId(finding.domain, finding.rule, finding.location.file, ""),
  };
}

// ---------------------------------------------------------------------------
// Pass 2 — verification
// ---------------------------------------------------------------------------

/** What the verification pass produced, before severity and deduplication. */
interface VerifiedBatch {
  readonly kept: Finding[];
  readonly dropped: NormaliseDrop[];
  readonly reasons: Record<DropReason, number>;
  readonly droppedEvidence: number;
  readonly relocated: number;
}

/**
 * Proves a self-verified step's citation without reading the file: the path
 * must resolve inside the repository, and that is the only claim Sentinel can
 * make about a line that exists in a commit rather than on disk.
 */
function checkContainment(finding: Finding, targetDir: string): NormaliseDrop | null {
  const resolved = resolveRepoPath(finding.location.file, targetDir);
  if (resolved.ok) return null;
  return {
    id: finding.id,
    rule: finding.rule,
    file: finding.location.file,
    reason: resolved.reason,
    detail: resolved.detail,
  };
}

/** Runs pass 2 over the whole batch, splitting self-verified sources out first. */
async function verifyBatch(
  findings: readonly Finding[],
  options: NormaliseOptions,
): Promise<VerifiedBatch> {
  const selfVerified: Finding[] = [];
  const toVerify: Finding[] = [];
  for (const finding of findings) {
    (SELF_VERIFIED_SOURCES.has(finding.source.name) ? selfVerified : toVerify).push(finding);
  }

  const reasons = emptyReasons();
  const dropped: NormaliseDrop[] = [];
  const kept: Finding[] = [];

  for (const finding of selfVerified) {
    const failure = checkContainment(finding, options.targetDir);
    if (failure === null) {
      kept.push(finding);
    } else {
      dropped.push(failure);
      reasons[failure.reason] += 1;
    }
  }

  const verified = await verifyFindings(toVerify, {
    fs: verifyFileSystem(options.fs),
    targetDir: options.targetDir,
  });
  kept.push(...verified.kept);
  for (const entry of verified.dropped) {
    dropped.push({
      id: entry.finding.id,
      rule: entry.finding.rule,
      file: entry.finding.location.file,
      reason: entry.reason,
      detail: entry.detail,
    });
    reasons[entry.reason] += 1;
  }

  return {
    kept,
    dropped,
    reasons,
    droppedEvidence: verified.droppedEvidence,
    relocated: verified.relocated,
  };
}

// ---------------------------------------------------------------------------
// Pass 3b — the file-kind policy
// ---------------------------------------------------------------------------

/**
 * Applies `_file-kind.ts` to one finding: the title gains its prefix, the
 * description gains the sentence naming the rule, and the severity moves only
 * downwards and only to the cap.
 *
 * Runs *after* escalation on purpose. R1 puts a floor of `high` under every
 * committed secret, and for a heuristic gitleaks match in a test file this
 * policy is allowed to overrule that floor — T3 is the list of secrets it may
 * not overrule, and it is decided from gitleaks' own rule id. Running the two in
 * this order is what makes that sentence true rather than order-dependent.
 */
function applyFileKind(finding: Finding, capped: SeverityCap[]): Finding {
  const decision = decideFileKind(finding);
  if (decision.titlePrefix === "" && decision.rationale === null) return finding;

  if (decision.capped && decision.pattern !== null) {
    capped.push({
      id: finding.id,
      rule: finding.rule,
      file: finding.location.file,
      fileKind: decision.kind,
      pattern: decision.pattern,
      from: finding.severity,
      to: decision.severity,
    });
  }

  return {
    ...finding,
    severity: decision.severity,
    title: finding.title.startsWith(decision.titlePrefix)
      ? finding.title
      : `${decision.titlePrefix}${finding.title}`,
    description:
      decision.rationale === null
        ? finding.description
        : `${finding.description} ${decision.rationale}`,
  };
}

// ---------------------------------------------------------------------------
// Pass 4 — deduplication
// ---------------------------------------------------------------------------

/** How much a finding carries. The richer of two duplicates is the one kept. */
export function richness(finding: Finding): number {
  return (
    (finding.location.snippet === undefined ? 0 : 8) +
    Math.min(finding.evidence.length, 4) * 4 +
    Math.min(finding.acceptanceCriteria.length, 4) * 2 +
    Math.min(finding.cwe.length + finding.owasp.length, 4) +
    (finding.exploitability === undefined ? 0 : 3) +
    (finding.location.endLine === undefined ? 0 : 1)
  );
}

/** High first; used only to break a tie between equally rich duplicates. */
const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = { high: 0, medium: 1, low: 2 };

/**
 * Orders duplicates best-first. Every tiebreak is a property of the findings
 * themselves, never of the order they arrived in, so which one survives does
 * not depend on which step finished first.
 */
function compareDuplicates(left: Finding, right: Finding): number {
  const byRichness = richness(right) - richness(left);
  if (byRichness !== 0) return byRichness;
  const bySeverity = compareSeverity(left.severity, right.severity);
  if (bySeverity !== 0) return bySeverity;
  const byConfidence = CONFIDENCE_RANK[left.confidence] - CONFIDENCE_RANK[right.confidence];
  if (byConfidence !== 0) return byConfidence;
  const byDescription = right.description.length - left.description.length;
  if (byDescription !== 0) return byDescription;
  const byRecommendation = right.recommendation.length - left.recommendation.length;
  if (byRecommendation !== 0) return byRecommendation;
  const bySource = left.source.name.localeCompare(right.source.name);
  if (bySource !== 0) return bySource;
  return left.id.localeCompare(right.id);
}

/** Identity of a code pointer, for merging two findings' evidence without repeats. */
function refKey(ref: CodeRef): string {
  return [ref.file, ref.line, ref.endLine ?? "", ref.note ?? ""].join(ID_SEPARATOR);
}

/** The sentence a survivor carries when another tool reported the same problem. */
const ALSO_REPORTED_BY = (sources: readonly string[]): string =>
  `Also reported by ${sources.join(", ")}; Sentinel keeps one finding per problem.`;

/** Union of two lists, first occurrence wins, order preserved. */
function union(first: readonly string[], rest: readonly string[]): string[] {
  const seen = new Set(first);
  const merged = [...first];
  for (const value of rest) {
    if (seen.has(value)) continue;
    seen.add(value);
    merged.push(value);
  }
  return merged;
}

/** Folds a list of duplicates into the richest of them. */
function fold(ordered: readonly Finding[]): { finding: Finding; merged: MergedFinding | null } {
  const winner = ordered[0];
  if (winner === undefined) throw new Error("fold was given an empty group");
  if (ordered.length === 1) return { finding: winner, merged: null };

  const others = ordered.slice(1);
  const alsoReportedBy = [...new Set(others.map((finding) => finding.source.name))]
    .filter((name) => name !== winner.source.name)
    .sort();

  const evidence: CodeRef[] = [...winner.evidence];
  const seenRefs = new Set(evidence.map(refKey));
  for (const other of others) {
    for (const ref of other.evidence) {
      const key = refKey(ref);
      if (seenRefs.has(key)) continue;
      seenRefs.add(key);
      evidence.push(ref);
    }
  }

  const note = alsoReportedBy.length === 0 ? "" : ` ${ALSO_REPORTED_BY(alsoReportedBy)}`;

  const finding: Finding = {
    ...winner,
    description: `${winner.description}${note}`,
    evidence,
    acceptanceCriteria: union(
      winner.acceptanceCriteria,
      others.flatMap((other) => other.acceptanceCriteria),
    ),
    cwe: union(
      winner.cwe,
      others.flatMap((other) => other.cwe),
    ).sort(),
    owasp: union(
      winner.owasp,
      others.flatMap((other) => other.owasp),
    ).sort(),
  };

  return {
    finding,
    merged: {
      id: finding.id,
      rule: finding.rule,
      file: finding.location.file,
      line: finding.location.line,
      kept: winner.source.name,
      alsoReportedBy,
    },
  };
}

/** Groups by `(rule, file, line)` — one problem with one fix is one finding. */
function duplicateKey(finding: Finding): string {
  return [finding.rule, finding.location.file, finding.location.line].join(ID_SEPARATOR);
}

/**
 * Collapses a `(rule, file, line)` group.
 *
 * `(rule, file, line)` is where two tools describing one problem meet, but it
 * is not fine enough to be an identity on its own: trivy reports every CVE of a
 * package at the line that resolves the package, so `CVE-2024-45590` and
 * `CVE-2024-29041` in the same `body-parser` share all three fields, and knip
 * reports every symbol of a barrel re-export at the line it is re-exported on.
 * Collapsing those would silently delete a real finding.
 *
 * So the group is only folded when **every source in it contributed exactly one
 * finding**. A producer that emitted two entries at one location considers them
 * two problems, and Sentinel is in no position to overrule it from three fields.
 * Exact repeats of one finding — same id — are still collapsed, because those
 * are the same finding by construction.
 */
function collapseGroup(group: readonly Finding[]): {
  findings: Finding[];
  merged: MergedFinding[];
} {
  // Same id, same place: one finding reported twice.
  const byId = new Map<string, Finding[]>();
  for (const finding of group) {
    const existing = byId.get(finding.id);
    if (existing === undefined) byId.set(finding.id, [finding]);
    else existing.push(finding);
  }
  const distinct = [...byId.values()].map((same) => {
    const ordered = [...same].sort(compareDuplicates);
    return ordered[0] as Finding;
  });

  const perSource = tally(distinct.map((finding) => finding.source.name));
  const ambiguous = [...perSource.values()].some((count) => count > 1);
  if (ambiguous) {
    return { findings: [...distinct].sort(compareDuplicates), merged: [] };
  }

  const folded = fold([...distinct].sort(compareDuplicates));
  return {
    findings: [folded.finding],
    merged: folded.merged === null ? [] : [folded.merged],
  };
}

// ---------------------------------------------------------------------------
// Pass 4a — subsumption between tools
// ---------------------------------------------------------------------------

/**
 * Sentinel rules that subsume a *whole rule id* from another tool.
 *
 * The Dockerfile overlaps are declared by the pack that owns them
 * (`HADOLINT_OVERLAP`, keyed by hadolint code, and `TRIVY_CONFIG_OVERLAP`,
 * keyed by trivy check id) and merged in below. This table is for the rest: the
 * one place a Sentinel rule and a tool rule are known to be the same finding
 * under two names. Adding an entry is a claim that the two are interchangeable
 * and that Sentinel's version says strictly more.
 */
export const RULE_OVERLAP: Readonly<Record<string, readonly string[]>> = {
  // Both fire on `${{ github.event.* }}` reaching a `run:` script. Sentinel's
  // carries the attack path, the impact and the acceptance criteria;
  // actionlint's carries the message.
  "delivery.ci.script-injection": ["delivery.workflow.script-injection"],
};

/**
 * The tool's own code for a finding, when the finding carries one.
 *
 * hadolint puts it in the rule id (`delivery.dockerfile.DL3008`); trivy's
 * configuration checks all share one rule id and put the check id at the front
 * of the title (`DS-0029: 'apt-get' missing …`), which is why each is read from
 * a different place. Both overlap tables are written in their tool's own
 * vocabulary and must not have to know the rule-id prefix the runner picked.
 */
function toolCode(finding: Finding): string | null {
  if (finding.source.name === HADOLINT_STEP) {
    return /\.(DL\d{4})$/.exec(finding.rule)?.[1] ?? null;
  }
  if (finding.source.name === TRIVY_STEP) {
    return /^(DS-\d{4})\b/.exec(finding.title)?.[1] ?? null;
  }
  return null;
}

/** Every alias a finding can be subsumed under: its rule id, and its tool code. */
function overlapKeys(finding: Finding): string[] {
  const code = toolCode(finding);
  return code === null ? [finding.rule] : [finding.rule, code];
}

/** subsumed key (rule id or tool code) -> the Sentinel rules that subsume it. */
const SUBSUMED_BY: ReadonlyMap<string, readonly string[]> = (() => {
  const table = new Map<string, string[]>();
  const add = (key: string, owner: string): void => {
    const existing = table.get(key);
    if (existing === undefined) table.set(key, [owner]);
    else if (!existing.includes(owner)) existing.push(owner);
  };
  for (const [owner, codes] of Object.entries(HADOLINT_OVERLAP)) {
    for (const code of codes) add(code, owner);
  }
  for (const [owner, codes] of Object.entries(TRIVY_CONFIG_OVERLAP)) {
    for (const code of codes) add(code, owner);
  }
  for (const [owner, rules] of Object.entries(RULE_OVERLAP)) {
    for (const rule of rules) add(rule, owner);
  }
  return table;
})();

/** Counts how often a key appears, so "the only one in this file" can be asked. */
function tally(values: readonly string[]): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return counts;
}

/**
 * `file|kind`, the granularity at which "is this the only one?" is asked.
 *
 * The kind is the tool's own code where there is one, not the rule id: every
 * trivy configuration check shares the rule id `delivery.dockerfile-misconfig`,
 * so keying on the rule would count four unrelated checks in one Dockerfile as
 * four of a kind and defeat the fallback for all of them.
 */
function fileRuleKey(finding: Finding): string {
  return `${finding.location.file}${ID_SEPARATOR}${toolCode(finding) ?? finding.rule}`;
}

/**
 * Drops the tool finding that a Sentinel rule already reports in full.
 *
 * The suppressed tool is recorded on the survivor, so nothing disappears from
 * the audit trail — the report still says hadolint agreed. A finding is only
 * suppressed when the two point at the same line, or when each is the only one
 * of its kind in that file: a Dockerfile with three unpinned `apt-get install`
 * lines keeps all three, because collapsing them by file would hide two real
 * instructions.
 */
function suppressSubsumed(findings: readonly Finding[]): {
  kept: Finding[];
  merged: MergedFinding[];
} {
  const owners = findings.filter(
    (finding) =>
      finding.rule in HADOLINT_OVERLAP ||
      finding.rule in TRIVY_CONFIG_OVERLAP ||
      finding.rule in RULE_OVERLAP,
  );
  if (owners.length === 0) return { kept: [...findings], merged: [] };

  const ownerCounts = tally(owners.map(fileRuleKey));
  const subsumedCounts = tally(findings.map(fileRuleKey));

  const suppressedBy = new Map<string, Set<string>>();
  const kept: Finding[] = [];

  for (const finding of findings) {
    const rules = overlapKeys(finding).flatMap((key) => SUBSUMED_BY.get(key) ?? []);
    const covering =
      rules.length === 0
        ? undefined
        : owners.find((owner) => {
            if (owner.location.file !== finding.location.file) return false;
            if (!rules.includes(owner.rule)) return false;
            if (owner.location.line === finding.location.line) return true;
            return (
              ownerCounts.get(fileRuleKey(owner)) === 1 &&
              subsumedCounts.get(fileRuleKey(finding)) === 1
            );
          });
    if (covering === undefined) {
      kept.push(finding);
      continue;
    }
    const sources = suppressedBy.get(covering.id) ?? new Set<string>();
    sources.add(finding.source.name);
    suppressedBy.set(covering.id, sources);
  }

  const merged: MergedFinding[] = [];
  const annotated = kept.map((finding) => {
    const sources = suppressedBy.get(finding.id);
    if (sources === undefined) return finding;
    const alsoReportedBy = [...sources].filter((name) => name !== finding.source.name).sort();
    merged.push({
      id: finding.id,
      rule: finding.rule,
      file: finding.location.file,
      line: finding.location.line,
      kept: finding.source.name,
      alsoReportedBy,
    });
    if (alsoReportedBy.length === 0) return finding;
    return {
      ...finding,
      description: `${finding.description} ${ALSO_REPORTED_BY(alsoReportedBy)}`,
    };
  });

  return { kept: annotated, merged };
}

// ---------------------------------------------------------------------------
// Pass 4b — ordering
// ---------------------------------------------------------------------------

/** Domain order in the report: the declaration order of the contract's enum. */
const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/**
 * The total order of `findings.json`: severity, then domain, then file, then
 * line. Every tiebreak below `line` exists only to make the order total, so two
 * runs over an unchanged repository cannot disagree about it.
 */
export function compareFindings(left: Finding, right: Finding): number {
  const bySeverity = severityRank(left.severity) - severityRank(right.severity);
  if (bySeverity !== 0) return bySeverity;
  const byDomain =
    (DOMAIN_RANK.get(left.domain) ?? Number.MAX_SAFE_INTEGER) -
    (DOMAIN_RANK.get(right.domain) ?? Number.MAX_SAFE_INTEGER);
  if (byDomain !== 0) return byDomain;
  const byFile = left.location.file.localeCompare(right.location.file);
  if (byFile !== 0) return byFile;
  const byLine = left.location.line - right.location.line;
  if (byLine !== 0) return byLine;
  const byRule = left.rule.localeCompare(right.rule);
  if (byRule !== 0) return byRule;
  return left.id.localeCompare(right.id);
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/**
 * Runs the four passes over everything phase 1 collected and returns the
 * document's findings plus the accounting the report needs.
 */
export async function normaliseFindings(
  input: readonly Finding[],
  options: NormaliseOptions,
): Promise<NormaliseResult> {
  const identified = input.map(withStableId);
  const verified = await verifyBatch(identified, options);

  const escalations: Escalation[] = [];
  const graded = verified.kept.map((finding) => {
    const decision = escalateFinding(finding, options);
    if (!decision.escalated) return finding;
    escalations.push({
      id: finding.id,
      rule: finding.rule,
      from: decision.base,
      to: decision.severity,
    });
    return {
      ...finding,
      severity: decision.severity,
      description:
        decision.rationale === undefined
          ? finding.description
          : `${finding.description} ${decision.rationale}`,
    };
  });

  const capped: SeverityCap[] = [];
  const policed = graded.map((finding) => applyFileKind(finding, capped));

  const overlap = suppressSubsumed(policed);

  const groups = new Map<string, Finding[]>();
  for (const finding of overlap.kept) {
    const key = duplicateKey(finding);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [finding]);
    else group.push(finding);
  }

  const merged: MergedFinding[] = [...overlap.merged];
  const findings: Finding[] = [];
  for (const group of groups.values()) {
    const collapsed = collapseGroup(group);
    findings.push(...collapsed.findings);
    merged.push(...collapsed.merged);
  }

  findings.sort(compareFindings);
  merged.sort((left, right) => left.id.localeCompare(right.id));
  escalations.sort((left, right) => left.id.localeCompare(right.id));
  capped.sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.rule.localeCompare(right.rule) ||
      left.id.localeCompare(right.id),
  );

  return {
    findings,
    droppedFindings: verified.dropped.length,
    dropped: verified.dropped,
    dropReasons: verified.reasons,
    droppedEvidence: verified.droppedEvidence,
    relocated: verified.relocated,
    merged,
    escalations,
    capped,
  };
}
