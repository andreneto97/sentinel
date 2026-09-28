/**
 * GitHub issues, ready to paste.
 *
 * Every finding in the dossier already carries what an issue needs — a
 * description, the preconditions, verified evidence, an impact, a
 * recommendation and acceptance criteria — so this module does not invent
 * prose. It arranges what is there into the shape a maintainer can drop into
 * a tracker without reading the rest of the report, and it does two things the
 * finding itself cannot:
 *
 * 1. **It groups the trivia.** Fifteen unused exports are one issue, not
 *    fifteen. The rule is explicit, narrow and tested — see {@link groupKeyFor}
 *    — because a grouping rule that drifts turns a dossier into spam.
 * 2. **It emits twice.** {@link renderIssuesMarkdown} writes the standalone
 *    `issues.md`, and every issue also carries a `sections` tree of typed
 *    blocks so the PDF's last section can lay the same content out without
 *    parsing markdown back.
 *
 * Every issue is delimited by `<!-- sentinel:issue:start ... -->` and its
 * matching end marker, in both outputs, so one issue can be copied whole
 * without taking its neighbours with it.
 */

import type { CodeRef, Domain, Finding, Severity } from "../contracts/findings.ts";
import { VOLUME_EXAMPLES, VOLUME_THRESHOLD, rawLocationOf } from "../scan/_volume.ts";
import type { PlanPriority } from "./plan.ts";
import {
  PRIORITY_LABEL,
  classifyPriority,
  comparePlanOrder,
  priorityReason,
  worstPriority,
  worstSeverity,
} from "./plan.ts";

/** File name of the standalone issues artifact inside a run directory. */
export const ISSUES_FILE = "issues.md";

/** Marker namespace for the copy delimiters around each issue. */
export const ISSUE_MARKER = "sentinel:issue";

// ---------------------------------------------------------------------------
// Titles and labels
// ---------------------------------------------------------------------------

/**
 * Title prefix per domain.
 *
 * `serverless` shares `[Security]` with `appsec` because an open cron endpoint
 * or an unverified webhook is a security issue to whoever triages the tracker,
 * whatever internal domain produced it. `api` and `reliability` get prefixes of
 * their own: neither is a security bucket, and folding them into one would lose
 * the only routing information the title carries.
 */
export const TITLE_PREFIX: Readonly<Record<Domain, string>> = {
  appsec: "[Security]",
  serverless: "[Security]",
  data: "[Data]",
  dependencies: "[Deps]",
  delivery: "[Delivery]",
  deadcode: "[Dead code]",
  api: "[API]",
  reliability: "[Reliability]",
};

/** Domains whose issues also get the cross-cutting `security` label. */
const SECURITY_LABELLED: ReadonlySet<Domain> = new Set<Domain>(["appsec", "serverless"]);

/** The labels to suggest: the domain, the severity, and `security` where it applies. */
export function labelsFor(domain: Domain, severity: Severity): readonly string[] {
  const labels = [domain, `severity:${severity}`];
  if (SECURITY_LABELLED.has(domain)) labels.push("security");
  return labels;
}

/** Longest an issue title may be before it is cut on a word boundary. */
const TITLE_LIMIT = 120;

function truncateTitle(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit - 1);
  const space = cut.lastIndexOf(" ");
  return `${(space > limit / 2 ? cut.slice(0, space) : cut).trimEnd()}…`;
}

/** `[Security] Sign-in handler has no attempt limiter` — prefix plus description. */
export function issueTitle(domain: Domain, description: string): string {
  const prefix = TITLE_PREFIX[domain];
  return `${prefix} ${truncateTitle(description.trim(), TITLE_LIMIT - prefix.length - 1)}`;
}

// ---------------------------------------------------------------------------
// The grouping rule
// ---------------------------------------------------------------------------

/** What a group covers: the whole run, one database table, or one file. */
export type GroupScope =
  | { readonly kind: "run" }
  | { readonly kind: "table"; readonly table: string }
  | { readonly kind: "file"; readonly file: string };

/** The identity of a group: one issue is filed per (family, scope). */
export interface GroupKey {
  /** Rule family; two rules in one family share an issue. */
  readonly family: string;
  readonly scope: GroupScope;
  /** Stable key string, unique per issue. */
  readonly id: string;
}

type ScopeKind = GroupScope["kind"];

interface GroupDefinition {
  readonly family: string;
  /** `run` groups everything of the family; `table` groups per table it can name. */
  readonly scopeKind: Extract<ScopeKind, "run" | "table">;
  /** Title of the grouped issue; `count` is always 2 or more. */
  readonly title: (count: number, scope: GroupScope) => string;
}

/**
 * The groupable rules, and nothing else.
 *
 * A rule is on this table when its findings are interchangeable enough that
 * one task closes all of them: the same fix, the same reviewer, the same
 * verification. Everything absent from the table is filed one issue per
 * finding, which is the safe default — a security finding merged into a batch
 * is a security finding nobody triages.
 *
 * Two rules may share a `family`, which is how "a patch bump" and "a major
 * upgrade" stay apart (different work) while "copyleft" and "unknown licence"
 * come together (one legal review).
 */
const GROUPABLE: ReadonlyMap<string, GroupDefinition> = new Map<string, GroupDefinition>([
  [
    "deadcode.unused-export",
    {
      family: "deadcode.unused-export",
      scopeKind: "run",
      title: (count) => `${count} exported symbols have no importer`,
    },
  ],
  [
    "deadcode.unused-type-export",
    {
      family: "deadcode.unused-export",
      scopeKind: "run",
      title: (count) => `${count} exported symbols have no importer`,
    },
  ],
  [
    "deadcode.unused-file",
    {
      family: "deadcode.unused-file",
      scopeKind: "run",
      title: (count) => `${count} files are not reachable from any entry point`,
    },
  ],
  [
    "deadcode.orphan-module",
    {
      family: "deadcode.orphan-module",
      scopeKind: "run",
      title: (count) => `${count} modules are orphaned in the dependency graph`,
    },
  ],
  [
    "deadcode.circular-dependency",
    {
      family: "deadcode.circular-dependency",
      scopeKind: "run",
      title: (count) => `${count} circular dependencies in the module graph`,
    },
  ],
  [
    "dependencies.unused-dependency",
    {
      family: "dependencies.unused-dependency",
      scopeKind: "run",
      title: (count) => `${count} declared dependencies are never imported`,
    },
  ],
  [
    "dependencies.unused-dev-dependency",
    {
      family: "dependencies.unused-dependency",
      scopeKind: "run",
      title: (count) => `${count} declared dependencies are never imported`,
    },
  ],
  [
    "dependencies.outdated-patch",
    {
      family: "dependencies.outdated-patch",
      scopeKind: "run",
      title: (count) => `${count} packages are a patch release behind`,
    },
  ],
  [
    "dependencies.outdated-minor",
    {
      family: "dependencies.outdated-minor",
      scopeKind: "run",
      title: (count) => `${count} packages are a minor release behind`,
    },
  ],
  [
    "dependencies.outdated-major",
    {
      family: "dependencies.outdated-major",
      scopeKind: "run",
      title: (count) => `${count} packages are a major release behind`,
    },
  ],
  [
    "dependencies.copyleft-license",
    {
      family: "dependencies.license",
      scopeKind: "run",
      title: (count) => `${count} dependency licences need a decision`,
    },
  ],
  [
    "dependencies.unknown-license",
    {
      family: "dependencies.license",
      scopeKind: "run",
      title: (count) => `${count} dependency licences need a decision`,
    },
  ],
  [
    "data.missing-index-on-fk",
    {
      family: "data.missing-index",
      scopeKind: "table",
      title: (count, scope) =>
        `${count} columns ${scopePhrase(scope)} are queried without an index`,
    },
  ],
  [
    "data.missing-index-on-filter",
    {
      family: "data.missing-index",
      scopeKind: "table",
      title: (count, scope) =>
        `${count} columns ${scopePhrase(scope)} are queried without an index`,
    },
  ],
]);

/** File extensions a `name.name` token in a title is allowed to be, and is not a table. */
const NOT_A_TABLE: ReadonlySet<string> = new Set([
  "ts",
  "tsx",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "json",
  "sql",
  "yml",
  "yaml",
  "md",
  "env",
  "lock",
]);

const TABLE_COLUMN = /\b([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)\b/;

/**
 * The table a schema finding is about, read from the first `table.column`
 * token in its title, or null when the title names none.
 *
 * Findings carry no structured table field, so this is the only place the
 * report guesses — and it guesses conservatively: no token, or a token that is
 * really a file extension, means no table, and the group falls back to the
 * file the finding cites. Two tables never merge by accident, which is the
 * failure that would matter.
 */
export function tableOf(finding: Finding): string | null {
  const match = TABLE_COLUMN.exec(finding.title);
  if (match === null) return null;
  const [, table, column] = match;
  if (table === undefined || column === undefined) return null;
  return NOT_A_TABLE.has(column) ? null : table;
}

function scopePhrase(scope: GroupScope): string {
  switch (scope.kind) {
    case "run":
      return "in this repository";
    case "table":
      return `on \`${scope.table}\``;
    case "file":
      return `in \`${scope.file}\``;
  }
}

function scopeId(scope: GroupScope): string {
  switch (scope.kind) {
    case "run":
      return "repo";
    case "table":
      return `table:${scope.table}`;
    case "file":
      return `file:${scope.file}`;
  }
}

/**
 * The group a finding belongs to, or null when it gets an issue of its own.
 *
 * Two conditions, both required. The finding must be **P3 hygiene** — anything
 * a release should not ship with is filed on its own, however repetitive it
 * looks — and its rule must be on the groupable table. Scope then decides how
 * wide the group is: repository-wide for dependency and dead-code trivia,
 * per-table for missing indexes, so two tables never share one issue.
 */
export function groupKeyFor(finding: Finding): GroupKey | null {
  if (classifyPriority(finding) !== "P3") return null;
  const definition = GROUPABLE.get(finding.rule);
  if (definition === undefined) return null;
  const scope = resolveScope(definition, finding);
  return { family: definition.family, scope, id: `${definition.family}@${scopeId(scope)}` };
}

function resolveScope(definition: GroupDefinition, finding: Finding): GroupScope {
  if (definition.scopeKind === "run") return { kind: "run" };
  const table = tableOf(finding);
  return table === null ? { kind: "file", file: finding.location.file } : { kind: "table", table };
}

// ---------------------------------------------------------------------------
// The issue model
// ---------------------------------------------------------------------------

/** A block of issue body content, typed so the PDF never parses markdown back. */
export type IssueBlock =
  | { readonly kind: "paragraph"; readonly label?: string | undefined; readonly text: string }
  | { readonly kind: "bullets"; readonly items: readonly string[] }
  | { readonly kind: "checklist"; readonly items: readonly string[] }
  | {
      readonly kind: "code";
      /** `file:line`, plus the pointer's note when it has one. */
      readonly caption: string;
      readonly language: string;
      readonly code: string;
    };

/** One headed part of an issue body. */
export interface IssueSection {
  readonly heading: string;
  readonly blocks: readonly IssueBlock[];
}

/** One finding inside an issue; a single-finding issue has exactly one. */
export interface IssueMember {
  readonly findingId: string;
  /** `file:line` — short, unique and checkable by someone who was not here. */
  readonly subject: string;
  readonly title: string;
  readonly rule: string;
  readonly severity: Severity;
  readonly location: CodeRef;
  readonly evidence: readonly CodeRef[];
  readonly acceptanceCriteria: readonly string[];
}

/** Whether an issue covers one finding or a group, and under which rule. */
export type IssueGrouping =
  | { readonly kind: "single" }
  | {
      readonly kind: "grouped";
      readonly family: string;
      readonly scope: GroupScope;
      /** The grouping rule as applied here, printed in the issue body. */
      readonly reason: string;
    };

/** One issue, ready to paste: structured for the PDF, rendered for the clipboard. */
export interface IssueDraft {
  /** Stable across runs: a finding id, or `family@scope` for a group. */
  readonly key: string;
  readonly title: string;
  readonly domain: Domain;
  /** The worst severity among the members. */
  readonly severity: Severity;
  /** The worst plan priority among the members. */
  readonly priority: PlanPriority;
  readonly labels: readonly string[];
  readonly rules: readonly string[];
  readonly findingIds: readonly string[];
  readonly grouping: IssueGrouping;
  readonly members: readonly IssueMember[];
  readonly sections: readonly IssueSection[];
  /** The body as markdown, without the copy delimiters. */
  readonly body: string;
}

/** Options for {@link buildIssues}. */
export interface BuildIssuesOptions {
  /**
   * Drop findings below this severity. Default `info` — everything. Every
   * finding carries a recommendation and acceptance criteria by contract, so
   * all of them are actionable; this exists for a caller who wants the tail cut.
   */
  readonly minSeverity?: Severity | undefined;
}

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

function meetsFloor(severity: Severity, floor: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(floor);
}

/**
 * Turns findings into issues: one per finding, except where the grouping rule
 * merges hygiene findings of the same family and scope into one.
 *
 * A group needs at least two members. A family with a single member in this
 * run is filed as an ordinary single issue, because "1 package is a patch
 * release behind" is a worse issue than the finding it came from.
 */
export function buildIssues(
  findings: readonly Finding[],
  options: BuildIssuesOptions = {},
): readonly IssueDraft[] {
  const floor = options.minSeverity ?? "info";
  const eligible = [...findings]
    .filter((finding) => meetsFloor(finding.severity, floor))
    .sort(comparePlanOrder);

  const groups = new Map<string, { key: GroupKey; members: Finding[] }>();
  const singles: Finding[] = [];
  for (const finding of eligible) {
    const key = groupKeyFor(finding);
    if (key === null) {
      singles.push(finding);
      continue;
    }
    const bucket = groups.get(key.id);
    if (bucket === undefined) groups.set(key.id, { key, members: [finding] });
    else bucket.members.push(finding);
  }

  const built: BuiltIssue[] = [];
  for (const bucket of groups.values()) {
    if (bucket.members.length < 2) {
      const [only] = bucket.members;
      if (only !== undefined) singles.push(only);
      continue;
    }
    built.push(groupedIssue(bucket.key, bucket.members));
  }
  for (const finding of singles) built.push(singleIssue(finding));

  // Issue order: the plan order of the issue's worst member, then its key, so
  // the sequence is total and two runs over unchanged code emit it identically.
  built.sort((left, right) => {
    const byOrder = comparePlanOrder(left.representative, right.representative);
    return byOrder !== 0 ? byOrder : left.draft.key.localeCompare(right.draft.key);
  });
  return built.map((entry) => entry.draft);
}

/** An issue plus the member that decides where it sorts; the pair is internal. */
interface BuiltIssue {
  readonly draft: IssueDraft;
  readonly representative: Finding;
}

// ---------------------------------------------------------------------------
// Building one issue
// ---------------------------------------------------------------------------

function memberOf(finding: Finding): IssueMember {
  return {
    findingId: finding.id,
    subject: `${finding.location.file}:${finding.location.line}`,
    title: finding.title,
    rule: finding.rule,
    severity: finding.severity,
    location: finding.location,
    evidence: finding.evidence,
    acceptanceCriteria: finding.acceptanceCriteria,
  };
}

function singleIssue(finding: Finding): BuiltIssue {
  const sections = singleSections(finding);
  const draft: IssueDraft = {
    key: finding.id,
    title: issueTitle(finding.domain, finding.title),
    domain: finding.domain,
    severity: finding.severity,
    priority: classifyPriority(finding),
    labels: labelsFor(finding.domain, finding.severity),
    rules: [finding.rule],
    findingIds: [finding.id],
    grouping: { kind: "single" },
    members: [memberOf(finding)],
    sections,
    body: renderSections(sections, 2),
  };
  return { draft, representative: finding };
}

function groupedIssue(key: GroupKey, members: readonly Finding[]): BuiltIssue {
  const ordered = [...members].sort(comparePlanOrder);
  const [first] = ordered;
  if (first === undefined) throw new Error("a group cannot be empty");
  const definition = GROUPABLE.get(first.rule);
  const title = definition?.title(ordered.length, key.scope) ?? key.family;
  const severity = ordered.reduce<Severity>(
    (worst, finding) => worstSeverity(worst, finding.severity),
    "info",
  );
  const priority = ordered.reduce<PlanPriority>(
    (worst, finding) => worstPriority(worst, classifyPriority(finding)),
    "P3",
  );
  const reason = `Sentinel files one issue per rule family and scope for hygiene findings. These ${ordered.length} findings share the family \`${key.family}\` ${scopePhrase(key.scope)}, so they close as one task instead of ${ordered.length}.`;
  const sections = groupSections(ordered, reason);
  const draft: IssueDraft = {
    key: key.id,
    title: issueTitle(first.domain, title),
    domain: first.domain,
    severity,
    priority,
    labels: labelsFor(first.domain, severity),
    rules: unique(ordered.map((finding) => finding.rule)),
    findingIds: ordered.map((finding) => finding.id),
    grouping: { kind: "grouped", family: key.family, scope: key.scope, reason },
    members: ordered.map(memberOf),
    sections,
    body: renderSections(sections, 2),
  };
  return { draft, representative: first };
}

function singleSections(finding: Finding): readonly IssueSection[] {
  const problem: IssueBlock[] = [
    { kind: "paragraph", text: finding.description },
    {
      kind: "paragraph",
      label: "Preconditions",
      text:
        finding.exploitability ??
        "None recorded by this run: treat the preconditions as unknown rather than as none.",
    },
    priorityParagraph(finding),
  ];
  const sections: IssueSection[] = [
    { heading: "Problem", blocks: problem },
    { heading: "Evidence", blocks: evidenceBlocks(finding) },
    { heading: "Impact", blocks: [{ kind: "paragraph", text: finding.impact }] },
    { heading: "Suggested fix", blocks: [{ kind: "paragraph", text: finding.recommendation }] },
    {
      heading: "Acceptance criteria",
      blocks: [{ kind: "checklist", items: checklistFor([finding], false) }],
    },
  ];
  const references = referenceItems(finding);
  if (references.length > 0) {
    sections.push({ heading: "References", blocks: [{ kind: "bullets", items: references }] });
  }
  return sections;
}

/** Why the issue sits where the plan put it, in the words of `plan.ts`. */
function priorityParagraph(finding: Finding): IssueBlock {
  const priority = classifyPriority(finding);
  return {
    kind: "paragraph",
    label: `Why ${priority}`,
    text: `${PRIORITY_LABEL[priority]}. ${priorityReason(finding)}`,
  };
}

/**
 * The members an issue body prints in full, and how many it does not.
 *
 * A group of eighteen is printed as eighteen: every bullet, every snippet,
 * every box. A group of nine hundred is not — an issue with nine hundred code
 * fences is an issue nobody opens twice, and one rule firing across a generated
 * directory is enough to push `issues.md` past the size a tracker will render
 * and a reader will scroll. Past
 * {@link VOLUME_THRESHOLD} the body prints {@link VOLUME_EXAMPLES} members and
 * says, in the body itself, how many it did not print and where every one of
 * them is: the issue's own `findingIds` still lists all of them, and so does
 * `findings.json`.
 */
function listedMembers(members: readonly Finding[]): {
  listed: readonly Finding[];
  unlisted: number;
} {
  if (members.length <= VOLUME_THRESHOLD) return { listed: members, unlisted: 0 };
  return { listed: members.slice(0, VOLUME_EXAMPLES), unlisted: members.length - VOLUME_EXAMPLES };
}

/** "…and 900 more" — the sentence that keeps a shortened list honest. */
function remainderSentence(members: readonly Finding[], unlisted: number): string {
  const rules = unique(members.map((finding) => finding.rule))
    .map((rule) => `\`${rule}\``)
    .join(", ");
  const raw = unique(
    members
      .map(rawLocationOf)
      .filter((location): location is string => location !== null)
      .map((location) => `\`${location}\``),
  ).join(", ");
  return `…and ${unlisted} more of the same kind, not printed here because this issue covers more than ${VOLUME_THRESHOLD} findings. All ${members.length} are in \`findings.json\` under ${rules}${raw === "" ? "" : `, and in the tool output under ${raw}`}; this issue's own "Covers" line counts every one of them.`;
}

function groupSections(members: readonly Finding[], reason: string): readonly IssueSection[] {
  const descriptions = unique(members.map((finding) => finding.description));
  const [first] = members;
  const { listed, unlisted } = listedMembers(members);
  const problem: IssueBlock[] = [{ kind: "paragraph", label: "Grouping", text: reason }];
  if (first !== undefined) problem.push(priorityParagraph(first));
  if (descriptions.length === 1 && descriptions[0] !== undefined) {
    problem.push({ kind: "paragraph", text: descriptions[0] });
  }
  problem.push({
    kind: "bullets",
    items: [
      ...listed.map((finding) => `\`${locationOf(finding)}\` — ${finding.title}`),
      ...(unlisted === 0 ? [] : [remainderSentence(members, unlisted)]),
    ],
  });
  const preconditions = unique(
    members
      .map((finding) => finding.exploitability)
      .filter((value): value is string => value !== undefined),
  );
  if (preconditions.length > 0) {
    problem.push({ kind: "paragraph", label: "Preconditions", text: preconditions.join(" ") });
  }

  const evidence: IssueBlock[] = [];
  for (const finding of listed) evidence.push(...evidenceBlocks(finding));
  if (unlisted > 0) {
    evidence.push({
      kind: "paragraph",
      text: `Evidence is shown for ${listed.length} of the ${members.length} findings this issue covers; the citation and the verified snippet of every other one are in \`findings.json\`.`,
    });
  }

  return [
    { heading: "Problem", blocks: problem },
    { heading: "Evidence", blocks: evidence },
    { heading: "Impact", blocks: prose(listed, (finding) => finding.impact) },
    { heading: "Suggested fix", blocks: prose(listed, (finding) => finding.recommendation) },
    {
      heading: "Acceptance criteria",
      blocks: [{ kind: "checklist", items: checklistFor(members, true) }],
    },
  ];
}

/**
 * Shared prose printed once, or per member when the members disagree — the
 * difference between "these fifteen exports are unreachable" and fifteen
 * copies of the same sentence.
 */
function prose(members: readonly Finding[], pick: (finding: Finding) => string): IssueBlock[] {
  const values = unique(members.map(pick));
  if (values.length === 1 && values[0] !== undefined)
    return [{ kind: "paragraph", text: values[0] }];
  return [
    {
      kind: "bullets",
      items: members.map((finding) => `\`${locationOf(finding)}\` — ${pick(finding)}`),
    },
  ];
}

/**
 * The checklist.
 *
 * Every item comes from the finding's own `acceptanceCriteria`, which are
 * written to be checked by someone who was not in the audit. A single-finding
 * issue lists them as they are.
 *
 * A grouped issue splits them in two, because a batch has two kinds of
 * criterion. The **first** criterion of each member is that member's own fix,
 * so it gets a box of its own, prefixed with the `file:line` it belongs to —
 * eighteen unused exports are eighteen tickable boxes, not one. Every other
 * criterion is a verification of the batch ("the lockfile is regenerated and
 * the test suite passes"), which is done once however many members there are,
 * so it is stated once at the end.
 */
function checklistFor(members: readonly Finding[], grouped: boolean): readonly string[] {
  if (!grouped) {
    const [only] = members;
    if (only === undefined) return [];
    return unique(
      only.acceptanceCriteria.length > 0
        ? only.acceptanceCriteria
        : [`The condition described at ${locationOf(only)} no longer holds.`],
    );
  }
  const { listed, unlisted } = listedMembers(members);
  const perMember: string[] = [];
  const shared: string[] = [];
  for (const finding of members) {
    const criteria =
      finding.acceptanceCriteria.length > 0
        ? finding.acceptanceCriteria
        : [`The condition described at ${locationOf(finding)} no longer holds.`];
    const [first, ...rest] = criteria;
    // A box per member up to the volume threshold; past it, one box for the
    // batch, because nine hundred checkboxes is not a checklist.
    if (first !== undefined && listed.includes(finding)) {
      perMember.push(`\`${locationOf(finding)}\` — ${first}`);
    }
    shared.push(...rest);
  }
  return unique([
    ...perMember,
    ...(unlisted === 0
      ? []
      : [
          `The remaining ${unlisted} findings this issue covers are triaged the same way; they are listed in \`findings.json\` and none of them is closed by ticking the boxes above.`,
        ]),
    ...unique(shared),
    "A re-run of Sentinel reports none of the findings listed above, or records why each one stays.",
  ]);
}

function evidenceBlocks(finding: Finding): IssueBlock[] {
  const refs = dedupeRefs([finding.location, ...finding.evidence]);
  const blocks: IssueBlock[] = [];
  const bare: string[] = [];
  for (const ref of refs) {
    const caption = captionFor(ref);
    if (ref.snippet === undefined || ref.snippet.trim() === "") {
      bare.push(`\`${refLabel(ref)}\`${ref.note === undefined ? "" : ` — ${ref.note}`}`);
      continue;
    }
    blocks.push({ kind: "code", caption, language: SNIPPET_LANGUAGE, code: ref.snippet });
  }
  if (bare.length > 0) blocks.push({ kind: "bullets", items: bare });
  if (blocks.length === 0) {
    blocks.push({
      kind: "paragraph",
      text: `No snippet survived verification for ${locationOf(finding)}; the pointer is the whole evidence.`,
    });
  }
  return blocks;
}

/**
 * Snippets arrive gutter-numbered (`> 26 | const { error } = ...`), extracted
 * from disk by `src/verify`. Tagging that as TypeScript would highlight the
 * line numbers as code, so every snippet fence is plain text — the fence is
 * there to preserve the evidence, not to colour it.
 */
const SNIPPET_LANGUAGE = "text";

function captionFor(ref: CodeRef): string {
  return ref.note === undefined ? refLabel(ref) : `${refLabel(ref)} — ${ref.note}`;
}

function refLabel(ref: CodeRef): string {
  return ref.endLine === undefined || ref.endLine === ref.line
    ? `${ref.file}:${ref.line}`
    : `${ref.file}:${ref.line}-${ref.endLine}`;
}

function locationOf(finding: Finding): string {
  return refLabel(finding.location);
}

function referenceItems(finding: Finding): readonly string[] {
  const items: string[] = [];
  if (finding.cwe.length > 0) items.push(`CWE: ${finding.cwe.join(", ")}`);
  if (finding.owasp.length > 0) items.push(`OWASP: ${finding.owasp.join(", ")}`);
  items.push(
    `Sentinel finding \`${finding.id}\` (rule \`${finding.rule}\`, ${finding.confidence} confidence, source \`${finding.source.kind}:${finding.source.name}\`).`,
  );
  return items;
}

function dedupeRefs(refs: readonly CodeRef[]): readonly CodeRef[] {
  const seen = new Set<string>();
  const kept: CodeRef[] = [];
  for (const ref of refs) {
    const key = `${ref.file}:${ref.line}:${ref.endLine ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    kept.push(ref);
  }
  return kept;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** Renders typed blocks as markdown; the single source of every issue body. */
export function renderSections(sections: readonly IssueSection[], level: number): string {
  const hashes = "#".repeat(Math.max(1, Math.min(6, level + 1)));
  const lines: string[] = [];
  for (const section of sections) {
    lines.push(`${hashes} ${section.heading}`, "");
    for (const block of section.blocks) {
      lines.push(...renderBlock(block), "");
    }
  }
  return lines.join("\n").trimEnd();
}

function renderBlock(block: IssueBlock): string[] {
  switch (block.kind) {
    case "paragraph":
      return [block.label === undefined ? block.text : `**${block.label}:** ${block.text}`];
    case "bullets":
      return block.items.map((item) => `- ${item}`);
    case "checklist":
      return block.items.map((item) => `- [ ] ${item}`);
    case "code":
      return [`\`${block.caption}\``, "", `\`\`\`${block.language}`, block.code, "```"];
  }
}

/** The metadata lines under an issue title: labels, priority, and what it covers. */
function metaLines(issue: IssueDraft): string[] {
  const labels = issue.labels.map((label) => `\`${label}\``).join(" ");
  const lines = [
    `**Labels:** ${labels}`,
    `**Priority:** ${issue.priority} · **Severity:** ${issue.severity}`,
  ];
  lines.push(
    issue.grouping.kind === "grouped"
      ? `**Covers:** ${issue.findingIds.length} findings (\`${issue.rules.join("`, `")}\`)`
      : `**Rule:** \`${issue.rules[0] ?? ""}\``,
  );
  return lines;
}

/**
 * One issue between its copy delimiters.
 *
 * The delimiters are HTML comments, so they are invisible wherever the
 * markdown is rendered and unambiguous wherever it is parsed: select from
 * `start` to `end` and the whole issue comes with it, and nothing else does.
 */
export function renderIssueDocument(issue: IssueDraft, level = 2): string {
  const hashes = "#".repeat(Math.max(1, Math.min(6, level)));
  return [
    `<!-- ${ISSUE_MARKER}:start key=${issue.key} -->`,
    `${hashes} ${issue.title}`,
    "",
    ...metaLines(issue),
    "",
    renderSections(issue.sections, level),
    "",
    `<!-- ${ISSUE_MARKER}:end key=${issue.key} -->`,
  ].join("\n");
}

/** Run identity for the header of `issues.md`. */
export interface IssuesDocumentMeta {
  readonly runId: string;
  readonly target: string;
}

/**
 * The standalone `issues.md`: a header that says how to use the file, an index
 * of every issue, then the issues themselves, each independently copyable.
 */
export function renderIssuesMarkdown(
  issues: readonly IssueDraft[],
  meta: IssuesDocumentMeta,
): string {
  const grouped = issues.filter((issue) => issue.grouping.kind === "grouped");
  const groupedFindings = grouped.reduce((total, issue) => total + issue.findingIds.length, 0);
  const lines: string[] = [
    "# GitHub issues",
    "",
    `Run \`${meta.runId}\` · target \`${meta.target}\``,
    "",
    `${issues.length} issue(s) covering ${issues.reduce((total, issue) => total + issue.findingIds.length, 0)} finding(s).`,
    "",
    "Each issue sits between a `sentinel:issue` start and end comment: select from one to the other and paste the whole thing into a tracker. Titles, labels and checklists are ready as they stand — nothing below needs the rest of the dossier to be understood.",
    "",
  ];
  if (grouped.length > 0) {
    lines.push(
      `${grouped.length} of them group ${groupedFindings} hygiene findings that share a rule family and a scope, so the tracker gets one task per fix rather than one per occurrence.`,
      "",
    );
  }
  lines.push("| # | Priority | Severity | Issue | Covers |", "| --- | --- | --- | --- | --- |");
  issues.forEach((issue, index) => {
    const covers =
      issue.grouping.kind === "grouped" ? `${issue.findingIds.length} findings` : "1 finding";
    lines.push(
      `| ${index + 1} | ${issue.priority} | ${issue.severity} | ${escapeCell(issue.title)} | ${covers} |`,
    );
  });
  lines.push("");
  for (const issue of issues) {
    lines.push(renderIssueDocument(issue, 2), "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/** Every issue keyed by the findings it covers, so the plan can link to it. */
export function indexIssuesByFinding(
  issues: readonly IssueDraft[],
): ReadonlyMap<string, IssueDraft> {
  const index = new Map<string, IssueDraft>();
  for (const issue of issues) {
    for (const findingId of issue.findingIds) index.set(findingId, issue);
  }
  return index;
}
