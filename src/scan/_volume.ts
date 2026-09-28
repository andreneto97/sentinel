/**
 * The volume policy: what the dossier does when one rule speaks two thousand times.
 *
 * knip over a monorepo, or dependency-cruiser over a cyclic graph, can report
 * more findings of a single rule than any reader will scroll through. Left alone
 * they bury the criticals: one dead-code rule can outnumber every other finding
 * in the report by an order of magnitude, and the severe ones then sit under
 * thousands of "unused export candidate" blocks nobody scrolls past.
 *
 * This module is the only place that decides when a rule's findings are
 * *rendered* as one counted group instead of one block each. It is a rendering
 * decision and nothing else: `findings.json` always carries every finding,
 * `raw/` always carries the tool output the group came from, and the group
 * states its own size in the report.
 *
 * Three invariants, each with a test of its own:
 *
 * 1. **Nothing above `low` is ever collapsed.** A group is built out of `low`
 *    and `info` findings only, so a `medium` finding of a collapsed rule is
 *    still rendered on its own, in full.
 * 2. **A group is never silent about its size.** It carries the total, the
 *    number of files it spans, how many examples are shown, how many are not,
 *    and where the rest can be read.
 *
 * 3. **A group is reproducible.** Members, examples and groups are ordered by
 *    fields the findings already carry, so two runs over unchanged code collapse
 *    the same way and `report.md` still diffs cleanly.
 *
 * It sits beside phase 1 because phase 1 is where volume is produced: the
 * runner that emits the findings discloses that the dossier will group them,
 * and the renderers ask this module what to collapse, so the scan report and
 * the dossier cannot disagree about the threshold.
 */

import type { Confidence, Domain, Finding, Severity } from "../contracts/findings.ts";
import { ConfidenceSchema } from "../contracts/findings.ts";
import { withoutFileKindPrefix } from "./_file-kind.ts";
import { severityRank } from "./severity.ts";

/**
 * How many findings one rule may contribute to one domain before the dossier
 * renders them as a counted group.
 *
 * 25 is deliberately low enough to fire on the volume a whole-repository
 * dead-code or cycle rule produces, and high enough that no rule in a report of
 * a few dozen findings reaches it — so a small repository never collapses
 * anything and never has to explain a group it did not need.
 */
export const VOLUME_THRESHOLD = 25;

/** How many members of a collapsed group are still rendered individually. */
export const VOLUME_EXAMPLES = 5;

/**
 * The only severities a group may contain.
 *
 * The list is the whole of invariant 1: a finding that is not `low` or `info`
 * never enters a group, whatever its rule and however many siblings it has.
 */
export const COLLAPSIBLE_SEVERITIES: readonly Severity[] = ["low", "info"];

/** True when a finding of this severity may be rendered inside a counted group. */
export function isCollapsibleSeverity(severity: Severity): boolean {
  return COLLAPSIBLE_SEVERITIES.includes(severity);
}

const CONFIDENCE_RANK: ReadonlyMap<Confidence, number> = new Map(
  ConfidenceSchema.options.map((confidence, index) => [confidence, index]),
);

/** The weakest confidence among the members, so a group never reads stronger than its worst. */
function weakestConfidence(findings: readonly Finding[]): Confidence {
  let weakest: Confidence = "high";
  for (const finding of findings) {
    const rank = CONFIDENCE_RANK.get(finding.confidence) ?? 0;
    if (rank >= (CONFIDENCE_RANK.get(weakest) ?? 0)) weakest = finding.confidence;
  }
  return weakest;
}

/**
 * Where the untouched output that produced a finding lives, relative to the run
 * directory, or null when no tool produced it.
 *
 * A group is only allowed to summarise because this pointer exists: the reader
 * who wants the members the group did not render can open the file the tool
 * actually wrote.
 */
export function rawLocationOf(finding: Finding): string | null {
  return finding.source.kind === "tool" ? `raw/${finding.source.name}/` : null;
}

/** One rule's findings in one domain, rendered as a count plus a few examples. */
export interface VolumeGroup {
  /** `<domain>|<rule>`; unique per group and stable across runs. */
  readonly key: string;
  readonly domain: Domain;
  readonly rule: string;
  /** The worst severity among the members; `low` or `info` by invariant 1. */
  readonly severity: Severity;
  /** The weakest confidence among the members, so the group never reads stronger. */
  readonly confidence: Confidence;
  /** Every member, in the order they are listed. */
  readonly findings: readonly Finding[];
  readonly findingIds: readonly string[];
  /** Total members. The number a group must never round or omit. */
  readonly count: number;
  /** Distinct files the members cite. */
  readonly fileCount: number;
  /** The members still rendered individually, most concentrated file first. */
  readonly examples: readonly Finding[];
  /** Members that are not rendered individually: `count - examples.length`. */
  readonly hidden: number;
  /** `raw/<tool>/`, or null when no tool produced these findings. */
  readonly rawLocation: string | null;
  /** Headline for the group's block, e.g. "120 Unused export candidates". */
  readonly title: string;
  /** The whole disclosure, in one paragraph a reader can check. */
  readonly summary: string;
}

/** The collapse decision for one set of findings; the renderers take it as given. */
export interface VolumePlan {
  readonly threshold: number;
  readonly exampleLimit: number;
  /** Collapsed groups, worst severity first, then rule. */
  readonly groups: readonly VolumeGroup[];
  /** The group covering a finding, keyed by finding id. */
  readonly groupByFinding: ReadonlyMap<string, VolumeGroup>;
  /** Ids of the findings still rendered individually inside their group. */
  readonly exampleIds: ReadonlySet<string>;
  /** Findings inside a group, examples included. */
  readonly collapsedFindings: number;
  /** Findings inside a group that are not rendered individually. */
  readonly hiddenFindings: number;
}

/** Overrides for {@link planVolume}; both default to this module's constants. */
export interface VolumeOptions {
  readonly threshold?: number | undefined;
  readonly exampleLimit?: number | undefined;
}

/** Member order inside a group: severity, then file, line, and finally the id. */
function byLocation(left: Finding, right: Finding): number {
  const bySeverity = severityRank(left.severity) - severityRank(right.severity);
  if (bySeverity !== 0) return bySeverity;
  const byFile = left.location.file.localeCompare(right.location.file);
  if (byFile !== 0) return byFile;
  const byLine = left.location.line - right.location.line;
  if (byLine !== 0) return byLine;
  return left.id.localeCompare(right.id);
}

/**
 * The examples, spread across files rather than taken off the top.
 *
 * Five unused exports from one file say only that one file is unusual; five
 * from the five files carrying the most of them say where the work is. Files
 * are ranked by how many members they carry, and the members are taken one file
 * at a time, so no single file can supply every example while another is unseen.
 */
function selectExamples(members: readonly Finding[], limit: number): Finding[] {
  const byFile = new Map<string, Finding[]>();
  for (const finding of members) {
    const bucket = byFile.get(finding.location.file);
    if (bucket === undefined) byFile.set(finding.location.file, [finding]);
    else bucket.push(finding);
  }
  const files = [...byFile.entries()].sort(
    (left, right) => right[1].length - left[1].length || left[0].localeCompare(right[0]),
  );
  const deepest = files.reduce((most, [, bucket]) => Math.max(most, bucket.length), 0);
  const examples: Finding[] = [];
  for (let round = 0; round < deepest && examples.length < limit; round += 1) {
    for (const [, bucket] of files) {
      const pick = bucket[round];
      if (pick === undefined) continue;
      examples.push(pick);
      if (examples.length >= limit) break;
    }
  }
  return examples;
}

/**
 * The noun the members already agree on, plural.
 *
 * Every finding of one rule opens its title with the same phrase — "Unused
 * export candidate: parseRow" — so the group can borrow it instead of inventing
 * prose. When the titles disagree, the rule id is used verbatim: a wrong noun
 * in a headline is worse than a dotted rule name.
 */
function groupNoun(rule: string, members: readonly Finding[]): string {
  const prefixes = new Set(
    members.map((finding) => {
      // The file-kind cap prefixes a title with `In test code: `, which is a
      // fact about the file rather than a second noun. Reading it as the noun
      // made the members of one rule look like three rules.
      const title = withoutFileKindPrefix(finding.title);
      const index = title.indexOf(": ");
      return index === -1 ? "" : title.slice(0, index);
    }),
  );
  const [only] = [...prefixes];
  if (prefixes.size !== 1 || only === undefined || only === "") return `\`${rule}\` findings`;
  return only.endsWith("s") ? only : `${only}s`;
}

/** Builds one group, including the sentence that discloses what it does not show. */
function buildGroup(
  domain: Domain,
  rule: string,
  members: readonly Finding[],
  threshold: number,
  exampleLimit: number,
): VolumeGroup {
  const findings = [...members].sort(byLocation);
  // Sorted by severity first, so the head of the list is the worst member.
  const [worst] = findings;
  const severity: Severity = worst?.severity ?? "info";
  const files = new Set(findings.map((finding) => finding.location.file));
  const examples = selectExamples(findings, exampleLimit);
  const hidden = findings.length - examples.length;
  const rawLocation = worst === undefined ? null : rawLocationOf(worst);
  const title = `${findings.length} ${groupNoun(rule, findings)}`;
  const whereRaw =
    rawLocation === null ? "" : ` The tool's untouched output is in \`${rawLocation}\`.`;
  const uniform = findings.every((finding) => finding.severity === severity);
  const summary = [
    `${findings.length} findings of rule \`${rule}\` across ${files.size} ${files.size === 1 ? "file" : "files"}, ${uniform ? `all of them \`${severity}\` severity` : `the worst of them \`${severity}\` severity`}.`,
    `The dossier renders a rule as a counted group once it passes ${threshold} findings in a domain, so ${examples.length} ${examples.length === 1 ? "example is" : "examples are"} shown here and ${hidden} ${hidden === 1 ? "is" : "are"} not.`,
    `Nothing was dropped: every one of the ${findings.length} is in \`findings.json\` with its own id, citation and snippet.${whereRaw}`,
    "A finding above `low` is never grouped, so this block cannot be hiding one.",
  ].join(" ");
  return {
    key: `${domain}|${rule}`,
    domain,
    rule,
    severity,
    confidence: weakestConfidence(findings),
    findings,
    findingIds: findings.map((finding) => finding.id),
    count: findings.length,
    fileCount: files.size,
    examples,
    hidden,
    rawLocation,
    title,
    summary,
  };
}

/**
 * Decides which rules the dossier renders as counted groups.
 *
 * Findings are bucketed by (domain, rule) over the collapsible severities only;
 * a bucket past the threshold becomes a group. Everything else — every bucket
 * below the threshold, and every finding above `low` whatever its rule — is
 * absent from the plan and is rendered as it always was.
 */
export function planVolume(findings: readonly Finding[], options: VolumeOptions = {}): VolumePlan {
  const threshold = options.threshold ?? VOLUME_THRESHOLD;
  const exampleLimit = options.exampleLimit ?? VOLUME_EXAMPLES;
  const buckets = new Map<string, { domain: Domain; rule: string; members: Finding[] }>();
  for (const finding of findings) {
    if (!isCollapsibleSeverity(finding.severity)) continue;
    const key = `${finding.domain}|${finding.rule}`;
    const bucket = buckets.get(key);
    if (bucket === undefined) {
      buckets.set(key, { domain: finding.domain, rule: finding.rule, members: [finding] });
    } else {
      bucket.members.push(finding);
    }
  }

  const groups: VolumeGroup[] = [];
  for (const bucket of buckets.values()) {
    if (bucket.members.length <= threshold) continue;
    groups.push(buildGroup(bucket.domain, bucket.rule, bucket.members, threshold, exampleLimit));
  }
  groups.sort(
    (left, right) =>
      severityRank(left.severity) - severityRank(right.severity) ||
      right.count - left.count ||
      left.key.localeCompare(right.key),
  );

  const groupByFinding = new Map<string, VolumeGroup>();
  const exampleIds = new Set<string>();
  let collapsedFindings = 0;
  let hiddenFindings = 0;
  for (const group of groups) {
    for (const finding of group.findings) groupByFinding.set(finding.id, group);
    for (const example of group.examples) exampleIds.add(example.id);
    collapsedFindings += group.count;
    hiddenFindings += group.hidden;
  }
  return {
    threshold,
    exampleLimit,
    groups,
    groupByFinding,
    exampleIds,
    collapsedFindings,
    hiddenFindings,
  };
}

/** The group a finding is rendered inside, or undefined when it is rendered alone. */
export function volumeGroupOf(plan: VolumePlan, finding: Finding): VolumeGroup | undefined {
  return plan.groupByFinding.get(finding.id);
}

/** True when the finding belongs to a collapsed group, example or not. */
export function isCollapsed(plan: VolumePlan, finding: Finding): boolean {
  return plan.groupByFinding.has(finding.id);
}

/** True when the finding is one of its group's rendered examples. */
export function isVolumeExample(plan: VolumePlan, finding: Finding): boolean {
  return plan.exampleIds.has(finding.id);
}

/** True when the finding is inside a group and is not one of its examples. */
export function isHiddenByVolume(plan: VolumePlan, finding: Finding): boolean {
  return isCollapsed(plan, finding) && !isVolumeExample(plan, finding);
}

/**
 * The plan in one paragraph, for the top of a section that collapses anything.
 *
 * An empty plan still returns a sentence: "nothing was collapsed" is a fact the
 * reader of a small report should be told, so the absence of grouping is never
 * something they have to infer.
 */
export function volumeDisclosure(plan: VolumePlan): string {
  if (plan.groups.length === 0) {
    return `No rule passed ${plan.threshold} findings in a domain, so every finding below is rendered on its own.`;
  }
  const rules = plan.groups.map((group) => `\`${group.rule}\` (${group.count})`).join(", ");
  return [
    `${plan.groups.length} ${plan.groups.length === 1 ? "rule" : "rules"} passed ${plan.threshold} findings in a domain and ${plan.groups.length === 1 ? "is" : "are"} rendered as a counted group instead of one block per finding: ${rules}.`,
    `That covers ${plan.collapsedFindings} findings, of which ${plan.collapsedFindings - plan.hiddenFindings} are shown as examples and ${plan.hiddenFindings} are not shown here.`,
    "All of them are in `findings.json` and in the raw tool output; only the rendering is collapsed, and only `low` and `info` findings can be.",
  ].join(" ");
}

/** One line per collapsed group, for the scan report and the coverage table. */
export function volumeLogLines(plan: VolumePlan): string[] {
  return plan.groups.map(
    (group) =>
      `${group.rule}: ${group.count} findings in ${group.domain} across ${group.fileCount} file(s) rendered as a counted group (${group.examples.length} shown, ${group.hidden} not shown, full set in findings.json${group.rawLocation === null ? "" : ` and ${group.rawLocation}`})`,
  );
}
