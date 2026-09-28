/**
 * opengrep runner: Sentinel's own rule pack (`assets/rules/opengrep/`) over the
 * target, normalised through the shared SARIF parser.
 *
 * The routing metadata travels in `metadata.tags` because the SARIF converter
 * keeps `tags` and drops every other custom metadata key -- a rule declares its
 * domain, severity, confidence, title, impact and fix there, and this runner
 * reads them back. A rule that carries none of that still lands somewhere
 * sensible: the first segment of its dotted id is the domain, and the SARIF
 * level gives the severity.
 */

import { join } from "node:path";
import {
  type Confidence,
  type Domain,
  DomainSchema,
  type Finding,
  type Severity,
  SeveritySchema,
} from "../../contracts/findings.ts";
import { resolveRepoPath } from "../../verify/index.ts";
import {
  type ProvenanceClass,
  type ProvenanceReader,
  createProvenanceReader,
  decideProvenance,
  gatedRule,
  isAnalysableFile,
} from "../_provenance.ts";
import { type SarifFinding, levelToSeverity, parseSarif, tagValue } from "../parsers/sarif.ts";
import type { StepOutcome, StepStatus } from "../types.ts";
import {
  type RunnerContext,
  briefly,
  failedStep,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
  verifyStepFindings,
} from "./_runner-support.ts";

/** Step name, matching the tool it drives. */
export const OPENGREP_STEP = "opengrep";

/** A pattern scan over a repository is minutes, not tens of minutes. */
export const OPENGREP_DEFAULT_TIMEOUT_MS = 600_000;

/** Extra options this runner accepts on top of the shared context. */
export interface OpengrepContext extends RunnerContext {
  /** Rule pack to run. Defaults to the pack shipped in `assets/rules/opengrep`. */
  readonly rulesDir?: string | undefined;
  /** Extra path globs to keep out of the scan, on top of {@link DEFAULT_EXCLUDES}. */
  readonly excludes?: readonly string[] | undefined;
  /** Ambient environment, read only for the locale check. Defaults to `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
}

/**
 * Directories that are never the customer's code. Build output and vendored
 * dependencies would otherwise dominate the findings with problems nobody in
 * this repository can fix.
 */
export const DEFAULT_EXCLUDES: readonly string[] = [
  "node_modules",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".output",
  "out",
  "coverage",
  "vendor",
  ".venv",
  "*.min.js",
  "*.bundle.js",
];

/** The pack that ships with Sentinel: `<repo>/assets/rules/opengrep`. */
export function defaultRulesDir(): string {
  // src/scan/runners/opengrep.ts -> the package root is three levels up.
  return join(import.meta.dir, "..", "..", "..", "assets", "rules", "opengrep");
}

/** Builds the opengrep argument list. The target is `.`, so SARIF uris stay repo-relative. */
export function opengrepArgs(
  rulesDir: string,
  reportPath: string,
  excludes: readonly string[],
): string[] {
  const args = [
    "scan",
    "--config",
    rulesDir,
    "--sarif",
    `--sarif-output=${reportPath}`,
    // Without this, a rule loaded from a directory is renamed after its path.
    "--no-rewrite-rule-ids",
    "--disable-version-check",
    "--quiet",
  ];
  for (const exclude of excludes) args.push(`--exclude=${exclude}`);
  args.push(".");
  return args;
}

/**
 * opengrep reads its rule files with the locale's encoding, so a non-UTF-8
 * locale -- the default in most CI containers -- aborts the whole scan on the
 * first rule file containing a non-ASCII byte. Sentinel's own pack is ASCII and
 * a test keeps it that way, but a user-supplied pack need not be.
 */
export function localeEnv(
  ambient: Readonly<Record<string, string | undefined>>,
): Record<string, string | undefined> {
  const current = ambient.LC_ALL ?? ambient.LC_CTYPE ?? ambient.LANG ?? "";
  return /utf-?8$/i.test(current) ? {} : { LC_ALL: "C.UTF-8" };
}

/** Reads a tag's value and keeps it only when it is one of the allowed literals. */
function enumTag<T extends string>(
  tags: readonly string[],
  prefix: string,
  allowed: { safeParse(value: unknown): { success: boolean; data?: unknown } },
): T | null {
  const value = tagValue(tags, prefix);
  if (value === null) return null;
  const parsed = allowed.safeParse(value);
  return parsed.success ? (parsed.data as T) : null;
}

/** The domain a rule routes to: its tag, else the first segment of its dotted id. */
export function domainOf(finding: SarifFinding): Domain | null {
  const tagged = enumTag<Domain>(finding.tags, "sentinel-domain", DomainSchema);
  if (tagged !== null) return tagged;
  const prefix = finding.ruleId.split(".")[0];
  if (prefix === undefined) return null;
  const parsed = DomainSchema.safeParse(prefix);
  return parsed.success ? parsed.data : null;
}

/** The severity a rule declares, else the one its SARIF level implies. */
export function severityOf(finding: SarifFinding): Severity {
  return (
    enumTag<Severity>(finding.tags, "sentinel-severity", SeveritySchema) ??
    levelToSeverity(finding.level)
  );
}

/** Confidence a rule declares; an undeclared pattern match is a lead, not proof. */
export function confidenceOf(finding: SarifFinding): Confidence {
  const value = tagValue(finding.tags, "sentinel-confidence");
  return value === "high" || value === "medium" || value === "low" ? value : "medium";
}

/** CWE identifiers, which the SARIF converter emits as plain tags. */
function cweOf(tags: readonly string[]): string[] {
  return tags.filter((tag) => /^CWE-\d+/.test(tag));
}

/** OWASP categories, which the SARIF converter prefixes with `OWASP-`. */
function owaspOf(tags: readonly string[]): string[] {
  return tags
    .filter((tag) => tag.startsWith("OWASP-"))
    .map((tag) => tag.slice("OWASP-".length))
    .filter((tag) => tag !== "");
}

/** Turns `appsec.xss.inner-html-assignment` into `Inner html assignment`. */
function humanise(ruleId: string): string {
  const words = (ruleId.split(".").at(-1) ?? ruleId).split("-").join(" ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * The stable part of a match. opengrep's `matchBasedId` hashes the matched
 * syntax rather than its position, so it survives the reformat that would churn
 * a line-number-based id.
 */
function symbolOf(finding: SarifFinding, line: number): string {
  const fingerprint = finding.fingerprints["matchBasedId/v1"];
  return fingerprint === undefined || fingerprint === "" ? `L${line}` : fingerprint;
}

/** Turns one opengrep SARIF result into a Sentinel finding, without its snippet. */
function toFinding(sarif: SarifFinding, domain: Domain): Finding | null {
  const location = sarif.primary;
  if (location === null) return null;

  const message = sarif.message.trim();
  const title = tagValue(sarif.tags, "sentinel-title") ?? humanise(sarif.ruleId);
  const impact = tagValue(sarif.tags, "sentinel-impact");
  const fix = tagValue(sarif.tags, "sentinel-fix");

  return makeFinding({
    domain,
    rule: sarif.ruleId,
    severity: severityOf(sarif),
    confidence: confidenceOf(sarif),
    title: `${title} in ${location.file}`,
    description: message === "" ? `The rule \`${sarif.ruleId}\` matched this code.` : message,
    impact: impact ?? message,
    recommendation: fix ?? "See the description: the rule states the change it expects.",
    file: location.file,
    line: location.startLine,
    ...(location.endLine !== null && location.endLine > location.startLine
      ? { endLine: location.endLine }
      : {}),
    symbol: symbolOf(sarif, location.startLine),
    evidence: sarif.locations
      .slice(1)
      .map((extra) => ({ file: extra.file, line: extra.startLine })),
    acceptanceCriteria: [
      `The pattern \`${sarif.ruleId}\` no longer matches at ${location.file}:${location.startLine}.`,
      "The change was made at the sink, not by suppressing the rule.",
    ],
    cwe: cweOf(sarif.tags),
    owasp: owaspOf(sarif.tags),
    // The step, not the rule id: `rule` already carries that, and every other
    // producer names its step here, so a reader can map a finding back to its
    // line in the step table and to its untouched output under `raw/`.
    source: { kind: "rule", name: OPENGREP_STEP },
  });
}

// ---------------------------------------------------------------------------
// The provenance pass
// ---------------------------------------------------------------------------

/** A finding with the SARIF result it came from, which is what carries the span. */
interface Candidate {
  readonly finding: Finding;
  readonly sarif: SarifFinding;
}

/** The sentence a folded group carries, so the count is never silently reduced. */
function occurrenceNote(count: number): string {
  return `Sentinel folded ${count} further ${count === 1 ? "statement" : "statements"} in the same function that interpolate the same expression: one value with one fix is one finding, and the other ${count === 1 ? "site is" : "sites are"} listed as evidence.`;
}

/** The note on each folded sibling's evidence ref. */
const OCCURRENCE_EVIDENCE = "the same interpolated expression reaches another statement here";

/** Rewrites a finding with what the provenance policy decided. */
function applyProvenance(finding: Finding, decision: ReturnType<typeof decideProvenance>): Finding {
  return {
    ...finding,
    severity: decision.severity,
    confidence: decision.confidence,
    title:
      decision.titlePrefix === "" || finding.title.startsWith(decision.titlePrefix)
        ? finding.title
        : `${decision.titlePrefix}${finding.title}`,
    description: `${finding.description} ${decision.rationale}`,
    exploitability: decision.exploitability,
    ...(decision.impact === null ? {} : { impact: decision.impact }),
    ...(decision.recommendation === null ? {} : { recommendation: decision.recommendation }),
    ...(decision.acceptanceCriteria === null
      ? {}
      : { acceptanceCriteria: [...decision.acceptanceCriteria] }),
  };
}

/** What the provenance pass produced, and the counts it has to disclose. */
interface GradedFindings {
  readonly findings: Finding[];
  /** One sentence per movement, for the step's `reason`. */
  readonly notes: string[];
}

/** How each class is worded in the step's reason. */
const CLASS_NOTE: Readonly<Record<ProvenanceClass, (count: number, plural: string) => string>> = {
  closed: (count, plural) =>
    `${count} injection match${plural} resolved to values this code fixes and ${count === 1 ? "was" : "were"} restated as \`info\` with the provenance named (P1) rather than dropped`,
  config: (count, plural) =>
    `${count} injection match${plural} interpolate only deploy-time configuration and ${count === 1 ? "was" : "were"} capped at \`low\` (P2)`,
  unresolved: (count, plural) =>
    `${count} injection match${plural} could not be resolved inside their own file, so ${count === 1 ? "it was" : "they were"} capped at \`medium\` with low confidence to say reachability is not established (P3)`,
  reachable: (count, plural) =>
    `${count} injection match${plural} trace to request input and ${count === 1 ? "was" : "were"} kept at full severity and high confidence (P4)`,
};

/**
 * Grades every match of a provenance-gated rule by where its interpolated
 * expressions come from.
 *
 * A pattern match proves that a value was interpolated, never that a caller
 * controls it. This pass reads the file the match sits in and decides which of
 * the two it is — and says so in the finding, in the step's reason, and in the
 * counts, so a suppression is a visible decision rather than a missing row.
 */
async function gradeProvenance(
  candidates: readonly Candidate[],
  ctx: OpengrepContext,
): Promise<GradedFindings> {
  const reader: ProvenanceReader = createProvenanceReader();
  const texts = new Map<string, string | null>();
  const counts: Record<ProvenanceClass, number> = {
    closed: 0,
    config: 0,
    unresolved: 0,
    reachable: 0,
  };
  let ungraded = 0;
  let folded = 0;

  const readText = async (file: string): Promise<string | null> => {
    const cached = texts.get(file);
    if (cached !== undefined) return cached;
    const resolved = resolveRepoPath(file, ctx.targetDir);
    let text: string | null = null;
    if (resolved.ok) {
      try {
        text = await ctx.fs.readFile(resolved.value.absolute);
      } catch {
        text = null;
      }
    }
    texts.set(file, text);
    return text;
  };

  /** The graded findings, with the group each one belongs to. */
  const graded: { finding: Finding; key: string | null }[] = [];

  for (const candidate of candidates) {
    const rule = gatedRule(candidate.finding.rule);
    const location = candidate.sarif.primary;
    const file = candidate.finding.location.file;
    if (rule === null || location === null || !isAnalysableFile(file)) {
      graded.push({ finding: candidate.finding, key: null });
      continue;
    }
    const text = await readText(file);
    if (text === null) {
      ungraded += 1;
      graded.push({ finding: candidate.finding, key: null });
      continue;
    }
    const result = reader.analyse(
      { file, text },
      {
        startLine: location.startLine,
        startColumn: location.startColumn,
        endLine: location.endLine,
        endColumn: location.endColumn,
      },
      rule.scope,
    );
    if (!result.analysed) {
      ungraded += 1;
      graded.push({ finding: candidate.finding, key: null });
      continue;
    }
    counts[result.klass] += 1;
    const decision = decideProvenance(candidate.finding, result, rule.subject);
    graded.push({
      finding: applyProvenance(candidate.finding, decision),
      key: `${candidate.finding.rule}\u0000${file}\u0000${result.signature}`,
    });
  }

  // One interpolated value with one fix is one finding; its other sinks become
  // evidence on it. Slots keep the original order: a finding stands where it
  // arrived, and a group stands where its first member arrived.
  const slots: { finding: Finding; siblings: Finding[] }[] = [];
  const groups = new Map<string, number>();
  for (const entry of graded) {
    const slot = entry.key === null ? undefined : groups.get(entry.key);
    if (slot !== undefined) {
      slots[slot]?.siblings.push(entry.finding);
      folded += 1;
      continue;
    }
    if (entry.key !== null) groups.set(entry.key, slots.length);
    slots.push({ finding: entry.finding, siblings: [] });
  }

  const findings: Finding[] = slots.map(({ finding, siblings }) =>
    siblings.length === 0
      ? finding
      : {
          ...finding,
          description: `${finding.description} ${occurrenceNote(siblings.length)}`,
          evidence: [
            ...finding.evidence,
            ...siblings.map((sibling) => ({
              file: sibling.location.file,
              line: sibling.location.line,
              note: OCCURRENCE_EVIDENCE,
            })),
          ],
        },
  );

  const notes: string[] = [];
  for (const klass of ["reachable", "unresolved", "config", "closed"] as const) {
    const count = counts[klass];
    if (count === 0) continue;
    notes.push(CLASS_NOTE[klass](count, count === 1 ? "" : "es"));
  }
  if (folded > 0) {
    notes.push(
      `${folded} match${folded === 1 ? "" : "es"} ${folded === 1 ? "was" : "were"} folded into a sibling that reports the same interpolated expression in the same function`,
    );
  }
  if (ungraded > 0) {
    notes.push(
      `${ungraded} injection match${ungraded === 1 ? "" : "es"} could not be graded for provenance -- the file could not be read or the match does not sit on a call -- and ${ungraded === 1 ? "was" : "were"} left exactly as the rule reported ${ungraded === 1 ? "it" : "them"}`,
    );
  }

  return { findings, notes };
}

/**
 * Runs Sentinel's opengrep rule pack over the target and normalises every match
 * into a finding routed by the rule's own metadata.
 */
export async function runOpengrep(ctx: OpengrepContext): Promise<StepOutcome> {
  const startedAt = performance.now();

  const binary = await ctx.tools.resolve("opengrep", { allowPath: ctx.allowPathTools ?? false });
  if (binary === null) {
    return skipped(
      OPENGREP_STEP,
      startedAt,
      "opengrep is not installed, so the injection, XSS, crypto and misconfiguration rules did not " +
        "run; run `sentinel setup`",
    );
  }

  const rulesDir = ctx.rulesDir ?? defaultRulesDir();
  if (!(await ctx.fs.exists(rulesDir))) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `the opengrep rule pack is missing at ${rulesDir}, so this step had nothing to run`,
    );
  }

  const reportPath = join(ctx.runDir, "raw", OPENGREP_STEP, "report.sarif");
  await ctx.fs.mkdirp(join(ctx.runDir, "raw", OPENGREP_STEP));

  const excludes = [...DEFAULT_EXCLUDES, ...(ctx.excludes ?? [])];
  const result = await ctx.exec.run(binary, opengrepArgs(rulesDir, reportPath, excludes), {
    // Running from inside the target is what keeps the SARIF uris relative.
    cwd: ctx.targetDir,
    env: localeEnv(ctx.env ?? process.env),
    timeoutMs: ctx.timeoutMs ?? OPENGREP_DEFAULT_TIMEOUT_MS,
  });

  if (result.notFound) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `the opengrep binary at ${binary} could not be run`,
    );
  }
  if (result.timedOut) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `opengrep did not finish within the time budget. ${briefly(result.stderr)}`,
    );
  }
  if (!(await ctx.fs.exists(reportPath))) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `opengrep exited with code ${result.exitCode} and wrote no report at ${reportPath}: ${briefly(result.stderr)}`,
    );
  }

  let raw: string;
  try {
    raw = await ctx.fs.readFile(reportPath);
  } catch (error) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `the opengrep report could not be read: ${briefly(error instanceof Error ? error.message : String(error))}`,
      [reportPath],
    );
  }

  const parsed = parseSarif(raw);
  if (!parsed.ok) {
    return failedStep(OPENGREP_STEP, startedAt, `opengrep: ${parsed.error}`, [reportPath]);
  }
  // An unreadable rule file makes opengrep write an empty report whose
  // invocation still claims success. Reading that as "no findings" would turn a
  // broken scan into a clean bill of health.
  if (parsed.errors.length > 0 && parsed.findings.length === 0) {
    return failedStep(
      OPENGREP_STEP,
      startedAt,
      `opengrep could not run its rules: ${briefly(parsed.errors.join("; "))}`,
      [reportPath],
    );
  }

  const candidates: Candidate[] = [];
  const seen = new Set<string>();
  let unrouted = 0;
  for (const sarif of parsed.findings) {
    const domain = domainOf(sarif);
    if (domain === null) {
      unrouted += 1;
      continue;
    }
    const finding = toFinding(sarif, domain);
    if (finding === null) continue;
    // Two patterns of one rule can match overlapping ranges on the same line;
    // that is one problem with one fix, not two findings.
    const key = `${finding.rule}\u0000${finding.location.file}\u0000${finding.location.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push({ finding, sarif });
  }

  // What a pattern cannot tell apart, provenance can: an interpolation the code
  // fixes from one a caller controls.
  const graded = await gradeProvenance(candidates, ctx);

  const verified = await verifyStepFindings(graded.findings, ctx);
  const status: StepStatus = parsed.errors.length > 0 || result.truncated ? "degraded" : "ok";
  const reason = joinReasons([
    ...parsed.errors.map((error) => `opengrep reported: ${error}`),
    ...graded.notes,
    unrouted === 0
      ? null
      : `${unrouted} match${unrouted === 1 ? "" : "es"} came from a rule with no Sentinel domain and could not be routed; give the rule a \`sentinel-domain:\` tag or a dotted id`,
    verified.droppedFindings === 0
      ? null
      : `${verified.droppedFindings} match${verified.droppedFindings === 1 ? "" : "es"} cited code that could not be read back from disk and ${verified.droppedFindings === 1 ? "was" : "were"} dropped`,
    result.truncated ? "the tool's output was truncated at the capture limit" : null,
  ]);

  return outcome(OPENGREP_STEP, status, reason, verified.kept, [reportPath], startedAt);
}
