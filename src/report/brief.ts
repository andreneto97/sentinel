/**
 * The executive brief: the second document, for the reader who will not open a
 * dossier hundreds of pages long.
 *
 * The full dossier prints every finding in full, which is the only honest way to
 * publish thousands of them and the reason nobody reads it end to end. This module
 * decides what a short version is allowed to be, and the whole design is one
 * rule: **detail what someone has to act on, count everything else, and state
 * the omission in numbers.**
 *
 * So the brief has exactly three kinds of content.
 *
 * 1. **Every `critical` and `high`, in full.** Same snippet, same
 *    preconditions, same impact, same fix, same human verdict as the dossier —
 *    not a summary of them. A brief that paraphrased the findings it is meant to
 *    be acted on would be a worse document than the long one, not a shorter one.
 * 2. **Everything at `medium` and below as grouped counts.** One row per
 *    (domain, rule): the count, the severity mix, how many files it spans, and
 *    one representative citation. `85 locking migrations` is the shape of the
 *    debt; eighty-five blocks of prose is not.
 * 3. **A page that states what is missing, counted.** How many findings are not
 *    detailed here, how many carry no human review, and where all of them are.
 *
 * The grouping here is deliberately *not* {@link planVolume}. That policy exists
 * to stop one loud rule burying the criticals inside the full dossier, so it
 * only collapses `low` and `info` past a threshold of 25. The brief collapses on
 * severity alone and at no threshold: a single `medium` gets a counted row, not
 * a block, because the brief's promise is a fixed ceiling on length rather than
 * a readable long document. Both documents stay truthful about the same
 * findings; they draw the line in different places, and each says where.
 *
 * Nothing is computed twice: the brief is built from the same
 * {@link ReportModel} the dossier renders, so the two cannot disagree about a
 * count, a severity or a score. What the brief adds is the split and the
 * disclosure of it.
 */

import type { Domain, Finding, Severity } from "../contracts/findings.ts";
import { DomainSchema } from "../contracts/findings.ts";
import { withoutFileKindPrefix } from "../scan/_file-kind.ts";
import { rawLocationOf } from "../scan/_volume.ts";
import { REPORT_MARKDOWN_FILE } from "./markdown.ts";
import {
  DOMAIN_CODE,
  DOMAIN_LABEL,
  type ReportModel,
  type SeverityCounts,
  compareFindings,
  countSeverities,
} from "./pdf/model.ts";
import { capitalise, citation, plural } from "./pdf/text.ts";
import { domainRank, severityRank } from "./plan.ts";
import { type ReviewedFinding, reviewIndex, reviewLabel } from "./triage.ts";

/** File name of the rendered brief markdown inside a run directory. */
export const REPORT_BRIEF_MARKDOWN_FILE = "report-brief.md";

/**
 * The severities the brief prints in full.
 *
 * The boundary is the same one the plan's P1 tier uses, and for the same
 * reason: these are the findings whose exposure window matters, so they are the
 * ones a reader is being asked to act on this week.
 */
export const BRIEF_DETAILED_SEVERITIES: readonly Severity[] = ["critical", "high"];

/** True when a finding is printed in full in the brief rather than counted. */
export function isBriefDetailed(finding: Finding): boolean {
  return BRIEF_DETAILED_SEVERITIES.includes(finding.severity);
}

/** One rule's findings in one domain, as the brief counts them. */
export interface BriefGroup {
  /** `<domain>|<rule>`; stable across runs, like a volume group's key. */
  readonly key: string;
  readonly domain: Domain;
  readonly rule: string;
  /** The worst severity among the members: `medium` at most, by construction. */
  readonly severity: Severity;
  readonly count: number;
  /** Distinct files the members cite. */
  readonly fileCount: number;
  /** Counts per severity, so a mixed group never reads as uniform. */
  readonly severities: SeverityCounts;
  /**
   * What the rule is about, in one phrase and without the count.
   *
   * Singular and uncounted on purpose: every table that prints it carries the
   * count in a column of its own, and a label that repeated the number produced
   * `1 findings of ...` and `8 Undeclared dependencys`. Borrowed from the
   * members' own shared title prefix when they agree on one, and read off the
   * rule id otherwise — `data.locking-migration` becomes `Locking migration`,
   * which is the phrase the count in the next column is about.
   */
  readonly label: string;
  /** `83 medium, 2 low across 85 files`: the mix, in one line. */
  readonly mix: string;
  /** One member, printed so the row points at real code. */
  readonly example: Finding;
  /** Members a human examined; almost always 0, and worth saying when it is not. */
  readonly reviewed: number;
  /** `raw/<tool>/`, or null when no tool produced these findings. */
  readonly rawLocation: string | null;
}

/** One domain's counted rows, with the domain's own totals above them. */
export interface BriefDomainGroups {
  readonly domain: Domain;
  readonly code: string;
  readonly label: string;
  /** Findings of this domain that the brief counts rather than details. */
  readonly count: number;
  readonly severities: SeverityCounts;
  readonly groups: readonly BriefGroup[];
  /** Where the counted findings are printed in full, for this domain. */
  readonly fullListSentence: string;
}

/** What the brief leaves out, in the numbers that make it checkable. */
export interface BriefOmissions {
  /** Findings printed in full here. */
  readonly detailed: number;
  /** Findings counted but not printed: the number this page exists to state. */
  readonly counted: number;
  /** Counted rows those findings were reduced to, one per (domain, rule). */
  readonly groups: number;
  /** Findings in the dossier this brief was built from. */
  readonly total: number;
  /** Counted findings that carry a human verdict. */
  readonly countedReviewed: number;
  /** Counted findings nobody examined. */
  readonly countedUnreviewed: number;
  /** Detailed findings that carry a human verdict. */
  readonly detailedReviewed: number;
  /** Detailed findings nobody examined; zero is the claim worth making. */
  readonly detailedUnreviewed: number;
  /** Assurances the brief does not reproduce. */
  readonly assurances: number;
  /** Findings a review withheld, which are in neither document's counts. */
  readonly withheld: number;
  /** The page, paragraph by paragraph, in the words both renderers print. */
  readonly paragraphs: readonly string[];
}

/** Everything the brief prints, computed from the dossier's own model. */
export interface BriefModel {
  /** The dossier this brief summarises; the cover and scorecard are read off it. */
  readonly report: ReportModel;
  /** Every `critical` and `high`, worst first — the part someone acts on. */
  readonly detailed: readonly Finding[];
  readonly detailedSeverities: SeverityCounts;
  /** Counted rows, by domain, worst domain first. */
  readonly domains: readonly BriefDomainGroups[];
  /** Counted rows across every domain, worst severity then largest first. */
  readonly groups: readonly BriefGroup[];
  readonly omissions: BriefOmissions;
  /** Every reviewed finding by id, so a detail block can print its verdict. */
  readonly reviews: ReadonlyMap<string, ReviewedFinding>;
  /**
   * What a human verified, in one sentence, or `null` when nobody did.
   *
   * Two sentences in one string, deliberately: how far the review reached and
   * what the rest therefore is. A brief that carried the first without the
   * second would be the shortest possible way to mislead a reader.
   */
  readonly verification: string | null;
  /**
   * True when every finding the brief details carries a human verdict.
   *
   * The one claim a brief may make that the dossier cannot: *the part you are
   * reading in full was checked by a person*. It is false the moment one
   * critical or high went unexamined, and the omission page says so either way.
   */
  readonly detailedFullyReviewed: boolean;
  /**
   * What the review concluded about the findings the brief details, counted.
   *
   * "Verified by hand" flattens four different outcomes into one word, and one
   * of them — `unclear` — means the reviewer looked and could not decide. A brief
   * whose detail section is introduced as verified while two of its findings are
   * contested has overstated the strongest claim in the document, so the counts
   * are kept and the sentence below is built from them.
   */
  readonly detailedVerdicts: DetailedVerdictCounts;
  /** The detail section's verification sentence, or `null` with no review. */
  readonly detailedVerificationSentence: string | null;
}

/** How the review decided the findings the brief details. */
export interface DetailedVerdictCounts {
  /** Checked and held at the severity printed. */
  readonly confirmed: number;
  /** Real, but re-graded — these are the ones that arrived here from critical. */
  readonly corrected: number;
  /** Examined and undecided; kept at the reported severity, not confirmed. */
  readonly contested: number;
  /** Not examined by anybody. */
  readonly unreviewed: number;
}

/** `1,234`, so a five-figure count is readable at a glance. */
function group(count: number): string {
  return count.toLocaleString("en-US");
}

/**
 * What a rule is about, in the members' own words when they agree on them.
 *
 * Every finding of one rule usually opens its title with the same phrase —
 * `Unused export candidate: parseRow` — so the label borrows it rather than
 * inventing prose. When the titles disagree, the rule id is turned into the same
 * kind of phrase: `data.locking-migration` reads as `Locking migration`, and
 * `appsec.injection.sql-built-from-variables` as `Injection SQL built from
 * variables`. Printing the dotted id here instead — which is what the first
 * version did — filled the column with a copy of the column beside it and told a
 * non-engineer nothing.
 *
 * Never pluralised, and never prefixed with the count: the tables that print it
 * carry the count in their own column.
 */
export function groupLabel(rule: string, members: readonly Finding[]): string {
  const prefixes = new Set(
    members.map((finding) => {
      const title = withoutFileKindPrefix(finding.title);
      const index = title.indexOf(": ");
      return index === -1 ? "" : title.slice(0, index);
    }),
  );
  const [only] = [...prefixes];
  if (prefixes.size === 1 && only !== undefined && only !== "") return only;
  // The domain prefix is dropped: the table is already grouped under the
  // domain's own heading, so repeating it in every row buys nothing.
  const words = rule
    .split(".")
    .slice(1)
    .join(" ")
    .replace(/[-_]+/g, " ")
    .trim()
    .split(" ")
    .map((word) => ACRONYMS[word.toLowerCase()] ?? word)
    .join(" ");
  return words === "" ? rule : capitalise(words);
}

/**
 * Words a rule id spells in lower case that a reader expects in capitals.
 *
 * Sentence-casing alone turned `delivery.ci.unpinned-action` into `Ci unpinned
 * action` and `appsec.idor` into `Idor`, which look like typographic errors in a
 * document a client reads. Deliberately short: a word that is not here is left
 * exactly as the rule id spells it, which is the safe direction to be wrong in.
 */
const ACRONYMS: Readonly<Record<string, string>> = {
  api: "API",
  ci: "CI",
  cors: "CORS",
  csrf: "CSRF",
  fk: "FK",
  graphql: "GraphQL",
  iac: "IaC",
  iam: "IAM",
  idor: "IDOR",
  jwt: "JWT",
  rls: "RLS",
  sql: "SQL",
  ssrf: "SSRF",
  tls: "TLS",
  ttl: "TTL",
  url: "URL",
  xss: "XSS",
};

/** `83 medium, 2 low`, in palette order and with the zeros left out. */
export function severityMix(counts: SeverityCounts): string {
  const parts = (["critical", "high", "medium", "low", "info"] as const)
    .filter((severity) => counts.counts[severity] > 0)
    .map((severity) => `${counts.counts[severity]} ${severity}`);
  return parts.join(", ");
}

/**
 * The one member a counted row points at.
 *
 * Worst severity first, then the file carrying the most of this rule. A row that
 * cited whichever finding happened to sort first would send the reader to an
 * outlier; the file with fourteen of them is where the work actually is.
 */
export function representativeOf(members: readonly Finding[]): Finding {
  const perFile = new Map<string, number>();
  for (const finding of members) {
    perFile.set(finding.location.file, (perFile.get(finding.location.file) ?? 0) + 1);
  }
  const ranked = [...members].sort(
    (left, right) =>
      severityRank(left.severity) - severityRank(right.severity) ||
      (perFile.get(right.location.file) ?? 0) - (perFile.get(left.location.file) ?? 0) ||
      left.location.file.localeCompare(right.location.file) ||
      left.location.line - right.location.line ||
      left.id.localeCompare(right.id),
  );
  const [first] = ranked;
  // Unreachable: a group is only built from a non-empty bucket. The throw is
  // here because a non-null assertion is not allowed in this codebase, and a
  // silently fabricated example would be a citation nobody verified.
  if (first === undefined) throw new Error("a brief group cannot be built from no findings");
  return first;
}

/** Builds one counted row out of one (domain, rule) bucket. */
function buildGroup(
  domain: Domain,
  rule: string,
  members: readonly Finding[],
  reviewed: ReadonlySet<string>,
): BriefGroup {
  const severities = countSeverities(members);
  const files = new Set(members.map((finding) => finding.location.file));
  const example = representativeOf(members);
  const worst = members.reduce<Severity>(
    (severity, finding) =>
      severityRank(finding.severity) < severityRank(severity) ? finding.severity : severity,
    "info",
  );
  return {
    key: `${domain}|${rule}`,
    domain,
    rule,
    severity: worst,
    count: members.length,
    fileCount: files.size,
    severities,
    label: groupLabel(rule, members),
    mix: `${severityMix(severities)} across ${group(files.size)} ${plural(files.size, "file")}`,
    example,
    reviewed: members.filter((finding) => reviewed.has(finding.id)).length,
    rawLocation: rawLocationOf(example),
  };
}

/** Counted-row order: worst severity, then the biggest group, then the rule. */
function compareGroups(left: BriefGroup, right: BriefGroup): number {
  return (
    severityRank(left.severity) - severityRank(right.severity) ||
    right.count - left.count ||
    left.key.localeCompare(right.key)
  );
}

/** Where a domain's counted findings can be read in full. */
function fullListSentence(domain: Domain, count: number, raws: readonly string[]): string {
  const where = raws.length === 0 ? "" : ` The tool output behind them is in ${raws.join(", ")}.`;
  return `All ${group(count)} ${plural(count, "finding")} of ${DOMAIN_LABEL[domain].toLowerCase()} counted above ${count === 1 ? "is" : "are"} printed in full — snippet, preconditions, impact and fix — in the findings section of the full dossier, and ${count === 1 ? "carries" : "carry"} an id, a citation and a verified snippet in \`findings.json\`.${where}`;
}

/**
 * The omission page, in the numbers that let a reader check it.
 *
 * This is the page the whole feature is answerable for. A summary that does not
 * state its own omissions is the failure mode Sentinel exists to refuse, so
 * every sentence here carries a count, and the counts add up to the dossier's
 * own total in front of the reader.
 */
function buildOmissions(
  model: ReportModel,
  detailed: readonly Finding[],
  counted: readonly Finding[],
  groups: number,
  reviewed: ReadonlySet<string>,
  verdicts: DetailedVerdictCounts,
): BriefOmissions {
  const detailedReviewed = detailed.filter((finding) => reviewed.has(finding.id)).length;
  const countedReviewed = counted.filter((finding) => reviewed.has(finding.id)).length;
  const total = model.findings.length;
  const withheld = model.triage?.withheld.length ?? 0;
  const detailedUnreviewed = detailed.length - detailedReviewed;
  const countedUnreviewed = counted.length - countedReviewed;

  const paragraphs: string[] = [
    `This brief is not the audit. The audit is \`report.pdf\` and \`${REPORT_MARKDOWN_FILE}\` in the same run directory, and the machine-readable record is \`findings.json\`. This document reproduces ${group(detailed.length)} of the dossier's ${group(total)} ${plural(total, "finding")} in full and counts the other ${group(counted.length)} without printing ${counted.length === 1 ? "it" : "them"}.`,
    `${group(counted.length)} ${plural(counted.length, "finding")} ${counted.length === 1 ? "is" : "are"} not detailed here. ${counted.length === 1 ? "It appears" : "They appear"} only inside ${group(groups)} counted ${plural(groups, "row")}: a total, a severity mix, a file count and one representative citation per rule. Each one has a description, preconditions, an impact, a fix and a verified snippet that this document does not show. Reading a count is not reading a finding.`,
  ];

  if (detailed.length === 0) {
    paragraphs.push(
      "No finding in this run is critical or high, so this brief details nothing. That is a statement about severity, not about health: read it against the coverage section of the full dossier, which says how much of the repository was examined at all.",
    );
  }

  if (model.triage === null) {
    paragraphs.push(
      `Nobody reviewed this run. Every one of the ${group(total)} ${plural(total, "finding")} in it — the ${group(detailed.length)} printed in full here included — is this run's own output as generated, and no sentence in this document says a person checked ${total === 1 ? "it" : "any of them"}.`,
    );
  } else {
    paragraphs.push(
      `${detailedVerificationSentence(detailed.length, verdicts)} That covers this document's detailed section and nothing beyond it.`,
    );
    paragraphs.push(
      countedUnreviewed === 0
        ? `All ${group(counted.length)} counted ${plural(counted.length, "finding")} also carry a human verdict.`
        : `Of the ${group(counted.length)} counted ${plural(counted.length, "finding")}, ${group(countedReviewed)} ${countedReviewed === 1 ? "carries" : "carry"} a human verdict and ${group(countedUnreviewed)} ${countedUnreviewed === 1 ? "carries" : "carry"} none. The counts in the tables above are therefore mostly unreviewed output, correct about the shape of the debt and unverified finding by finding.`,
    );
    if (withheld > 0) {
      paragraphs.push(
        `A further ${group(withheld)} ${plural(withheld, "claim")} this run made ${withheld === 1 ? "was" : "were"} withheld by that review and ${withheld === 1 ? "is" : "are"} in neither document's counts. ${withheld === 1 ? "It is" : "They are"} listed, with the reviewer's reason for each, in the human-verification section of the full dossier — a withdrawn claim a reader cannot see is indistinguishable from one that was never made.`,
      );
    }
  }

  if (model.assurances.length > 0) {
    paragraphs.push(
      `${group(model.assurances.length)} ${plural(model.assurances.length, "assurance")} — checks that ran and passed, with the evidence that proves ${model.assurances.length === 1 ? "it" : "them"} — ${model.assurances.length === 1 ? "is" : "are"} not reproduced here. ${model.assurances.length === 1 ? "It is" : "They are"} in section 3 of the full dossier, and ${model.assurances.length === 1 ? "it covers" : "they cover"} ${group(model.unitsAssured)} unit ${plural(model.unitsAssured, "check")}.`,
    );
  }

  paragraphs.push(
    "Not in this brief at all: the methodology page that says what each domain was taken to mean for this stack, the coverage section that states how many enumerated units a verdict actually examined, the per-domain assurances, the prioritised plan, the GitHub-issues checklist and the run appendix. Every score and count on the summary page was computed from the full findings set, not from the part printed here, so the numbers are the dossier's — only the prose is shorter.",
  );

  return {
    detailed: detailed.length,
    counted: counted.length,
    groups,
    total,
    countedReviewed,
    countedUnreviewed,
    detailedReviewed,
    detailedUnreviewed,
    assurances: model.assurances.length,
    withheld,
    paragraphs,
  };
}

/** How the review decided the findings the brief details. */
export function countDetailedVerdicts(
  detailed: readonly Finding[],
  reviews: ReadonlyMap<string, ReviewedFinding>,
): DetailedVerdictCounts {
  const verdicts = detailed.map((finding) => reviews.get(finding.id)?.verdict);
  return {
    confirmed: verdicts.filter((verdict) => verdict === "true").length,
    corrected: verdicts.filter((verdict) => verdict === "overstated").length,
    contested: verdicts.filter((verdict) => verdict === "unclear").length,
    unreviewed: verdicts.filter((verdict) => verdict === undefined).length,
  };
}

/**
 * What a reader may conclude from the review about the detail section, exactly.
 *
 * The clauses are additive and each one is a different claim: confirmed means a
 * person agreed at this severity, corrected means they re-graded it and it
 * arrived here from higher up, contested means they looked and could not decide,
 * and unreviewed means nobody looked. Collapsing them into "verified" would make
 * the contested ones read as confirmed, which is the one direction this sentence
 * must not round in.
 */
export function detailedVerificationSentence(
  detailed: number,
  counts: DetailedVerdictCounts,
): string {
  const examined = detailed - counts.unreviewed;
  if (examined === 0) {
    return `None of the ${group(detailed)} ${plural(detailed, "finding")} this brief details carries a human verdict: ${detailed === 1 ? "it is" : "they are"} this run's own output as generated.`;
  }
  const parts = [
    `${group(counts.confirmed)} confirmed at the severity shown`,
    `${group(counts.corrected)} kept but re-graded`,
    `${group(counts.contested)} contested — examined, and the reviewer could not decide`,
  ];
  const head =
    counts.unreviewed === 0
      ? `Every one of the ${group(detailed)} ${plural(detailed, "finding")} this brief details was examined against the code by hand`
      : `${group(examined)} of the ${group(detailed)} ${plural(detailed, "finding")} this brief details ${examined === 1 ? "was" : "were"} examined against the code by hand`;
  const tail =
    counts.unreviewed === 0
      ? ""
      : ` The other ${group(counts.unreviewed)} ${counts.unreviewed === 1 ? "carries" : "carry"} no verdict and ${counts.unreviewed === 1 ? "was" : "were"} not examined by a person.`;
  return `${head}: ${parts.join(", ")}.${tail}`;
}

/** Builds everything the brief prints from the dossier's own model. */
export function buildBriefModel(model: ReportModel): BriefModel {
  const reviews =
    model.triage === null ? new Map<string, ReviewedFinding>() : reviewIndex(model.triage);
  const reviewed = new Set(reviews.keys());

  const detailed = model.findings.filter(isBriefDetailed).sort(compareFindings);
  const counted = model.findings.filter((finding) => !isBriefDetailed(finding));
  const detailedVerdicts = countDetailedVerdicts(detailed, reviews);

  const buckets = new Map<string, { domain: Domain; rule: string; members: Finding[] }>();
  for (const finding of counted) {
    const key = `${finding.domain}|${finding.rule}`;
    const bucket = buckets.get(key);
    if (bucket === undefined) {
      buckets.set(key, { domain: finding.domain, rule: finding.rule, members: [finding] });
    } else {
      bucket.members.push(finding);
    }
  }
  const groups = [...buckets.values()]
    .map((bucket) => buildGroup(bucket.domain, bucket.rule, bucket.members, reviewed))
    .sort(compareGroups);

  const domains: BriefDomainGroups[] = DomainSchema.options
    .map((domain) => {
      const owned = groups.filter((entry) => entry.domain === domain);
      const members = counted.filter((finding) => finding.domain === domain);
      const raws = [
        ...new Set(owned.map((entry) => entry.rawLocation).filter((raw) => raw !== null)),
      ]
        .sort()
        .map((raw) => `\`${raw}\``);
      return {
        domain,
        code: DOMAIN_CODE[domain],
        label: DOMAIN_LABEL[domain],
        count: members.length,
        severities: countSeverities(members),
        groups: owned,
        fullListSentence: fullListSentence(domain, members.length, raws),
      };
    })
    .filter((entry) => entry.count > 0)
    .sort((left, right) => domainRank(left.domain) - domainRank(right.domain));

  const triage = model.triage;
  return {
    report: model,
    detailed,
    detailedSeverities: countSeverities(detailed),
    domains,
    groups,
    omissions: buildOmissions(model, detailed, counted, groups.length, reviewed, detailedVerdicts),
    reviews,
    verification: triage === null ? null : `${triage.statement} ${triage.unreviewedStatement}`,
    detailedFullyReviewed:
      triage !== null &&
      detailed.length > 0 &&
      detailed.every((finding) => reviewed.has(finding.id)),
    detailedVerdicts,
    detailedVerificationSentence:
      triage === null || detailed.length === 0
        ? null
        : detailedVerificationSentence(detailed.length, detailedVerdicts),
  };
}

// ---------------------------------------------------------------------------
// report-brief.md
// ---------------------------------------------------------------------------

/** Escapes a cell and flattens it to one line, as the dossier's tables do. */
function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

/** A markdown table, or nothing when there are no rows to put in one. */
function table(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
  if (rows.length === 0) return [];
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(cell).join(" | ")} |`),
  ];
}

/** One detailed finding, in the same order of fields the PDF prints. */
function detailMarkdown(finding: Finding, review: ReviewedFinding | undefined): string[] {
  const lines = [
    `### ${finding.title}`,
    "",
    `\`${finding.severity}\` · \`${finding.rule}\` · ${finding.confidence} confidence · source \`${finding.source.kind}:${finding.source.name}\` · id \`${finding.id}\``,
    "",
    `\`${citation(finding.location.file, finding.location.line, finding.location.endLine)}\``,
    "",
    finding.description,
    "",
  ];
  if (review !== undefined) {
    lines.push(`**Human review** — ${reviewLabel(review)}. ${review.note}`, "");
  }
  if (finding.location.snippet !== undefined && finding.location.snippet.trim() !== "") {
    lines.push("```text", finding.location.snippet.replace(/\n+$/, ""), "```", "");
  }
  lines.push(
    `**Preconditions:** ${finding.exploitability ?? "Not stated for this finding; treat the impact below as conditional."}`,
    "",
    `**Impact:** ${finding.impact}`,
    "",
    `**Fix:** ${finding.recommendation}`,
  );
  if (finding.acceptanceCriteria.length > 0) {
    lines.push("", "**Done when:**", ...finding.acceptanceCriteria.map((line) => `- ${line}`));
  }
  if (finding.evidence.length > 0) {
    lines.push(
      "",
      "**Also at:**",
      ...finding.evidence.map(
        (ref) =>
          `- \`${citation(ref.file, ref.line, ref.endLine)}\`${ref.note === undefined || ref.note === "" ? "" : ` — ${ref.note}`}`,
      ),
    );
  }
  const tags = [...finding.cwe, ...finding.owasp];
  if (tags.length > 0) lines.push("", `**References:** ${tags.join(" · ")}`);
  return lines;
}

/**
 * Renders `report-brief.md`.
 *
 * The same content as the brief PDF in the same order, because the two are read
 * by different people about the same run and a difference between them would be
 * a difference nobody could explain.
 */
export function renderBriefMarkdown(brief: BriefModel): string {
  const model = brief.report;
  const lines: string[] = [
    `# Sentinel executive brief — \`${model.target}\``,
    "",
    `A short read over the full dossier. ${brief.omissions.paragraphs[0] ?? ""}`,
    "",
    ...table(
      ["", ""],
      [
        ["Repository", `\`${model.repository}\``],
        ["Run id", `\`${model.runId}\``],
        ["Commit", model.commitLabel],
        ["Findings in the dossier", group(brief.omissions.total)],
        ["Detailed in full here", `${group(brief.omissions.detailed)} (critical and high)`],
        ["Counted, not detailed", group(brief.omissions.counted)],
      ],
    ),
    "",
    "## Executive summary",
    "",
    ...table(
      ["Severity", "Findings"],
      (["critical", "high", "medium", "low", "info"] as const).map((severity) => [
        severity,
        group(model.severity.counts[severity]),
      ]),
    ),
    "",
    ...table(
      ["Domain", "Score", "Band", "Findings"],
      model.domains.map((domain) => {
        const row = model.scorecard.domains.find((entry) => entry.domain === domain.domain);
        return [
          `${domain.code} ${domain.label}`,
          row?.score ?? "not assessed",
          row?.band ?? "—",
          domain.severity.total === 0 ? "none" : severityMix(domain.severity),
        ];
      }),
    ),
    "",
  ];

  if (brief.verification !== null) lines.push(`**Human verification** — ${brief.verification}`, "");
  else
    lines.push(
      "**Human verification** — none. No reviewer verdicts were applied to this run, so every finding below is unreviewed output.",
      "",
    );

  lines.push(
    `## Critical and high, in full (${group(brief.detailed.length)})`,
    "",
    brief.detailed.length === 0
      ? "No finding in this run is critical or high. That is a statement about severity, not about coverage: the full dossier's coverage section says how much of the repository was examined."
      : `Every critical and high finding in this run, reproduced from the dossier without abridgement.${brief.detailedVerificationSentence === null ? "" : ` ${brief.detailedVerificationSentence}`}`,
    "",
  );
  for (const finding of brief.detailed) {
    lines.push(...detailMarkdown(finding, brief.reviews.get(finding.id)), "");
  }

  lines.push(
    `## Medium and below, counted (${group(brief.omissions.counted)})`,
    "",
    `${group(brief.omissions.counted)} ${plural(brief.omissions.counted, "finding")} at \`medium\` or lower, grouped by domain and rule. One row per rule: the count, the severity mix, the files it spans and one representative citation. No row is a finding — each one stands for every member of its rule, and every member is in the full dossier and in \`findings.json\`.`,
    "",
  );
  for (const domain of brief.domains) {
    lines.push(
      `### ${domain.code} ${domain.label} — ${group(domain.count)} ${plural(domain.count, "finding")}`,
      "",
      severityMix(domain.severities),
      "",
      ...table(
        ["Count", "Worst", "What it is", "Rule", "Representative example"],
        domain.groups.map((entry) => [
          group(entry.count),
          entry.severity,
          `${entry.label} — ${entry.mix}`,
          `\`${entry.rule}\``,
          `\`${citation(entry.example.location.file, entry.example.location.line)}\``,
        ]),
      ),
      "",
      domain.fullListSentence,
      "",
    );
  }

  lines.push(
    "## What this brief leaves out",
    "",
    ...brief.omissions.paragraphs.flatMap((paragraph) => [paragraph, ""]),
  );

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}
