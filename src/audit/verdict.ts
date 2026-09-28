/**
 * Decoding an audit reply — the second gate, after the schema.
 *
 * `src/contracts/verdict.ts` proves the reply is the right *shape*.
 * This module proves it is about the right *work*: the verdicts belong to units
 * that were in the batch, the checks are the ones the prompt demanded, the rules
 * are ones the prompt offered, the severities are inside the rubric's ceilings,
 * and — the rule the whole design turns on — every citation falls inside a slice
 * the model was actually shown.
 *
 * Nothing here trusts the model, and nothing here hides a disagreement. A
 * verdict for a unit that was never in the batch is a bug in the run, not data,
 * so it is rejected and named. A unit with no verdict is a hole in the coverage
 * claim, so it comes back in `missing` in the shape `Coverage.skipped` takes. A
 * finding citing a line that was elided out of its own slice is dropped, because
 * the model did not read that line — and a citation outside the slice is the
 * shape a finding takes when it rests on what the model already believed rather
 * than on the code it was handed.
 *
 * What survives is still not a `Finding`: `src/verify/` re-opens every cited file
 * and extracts the snippet itself, and anything that no longer resolves on disk
 * is dropped there and counted in `report.droppedFindings`.
 */

import {
  type AuditUnit,
  type CodeRef,
  type Confidence,
  type Domain,
  DomainSchema,
  type Severity,
} from "../contracts/findings.ts";
import type { AuditUnitKind } from "../contracts/inventory.ts";
import {
  type AgentCheckOutcome,
  type AgentCodeRef,
  type AgentFinding,
  type AgentUnitVerdict,
  type AgentVerdictReport,
  AgentVerdictReportSchema,
  type CheckResult,
} from "../contracts/verdict.ts";
import { truncate } from "../verify/text.ts";
import {
  type AuditBatch,
  type CitedRanges,
  type SkippedUnit,
  citedRanges,
  shownRangesOf,
  wasShown,
} from "./batch.ts";
import {
  ceilingFor,
  ceilingOfRule,
  checkById,
  checkIdOf,
  checkIdsFor,
  checksFor,
  rulesFor,
} from "./prompts/index.ts";

/**
 * Everything the decoder can object to.
 *
 * They are all disclosures rather than errors: a batch with issues still
 * contributes its good verdicts, and the issues are what the report and the run
 * log quote when they explain why a number is what it is.
 */
export const VERDICT_ISSUE_KINDS = [
  /** A verdict for a unit id that was not in the batch. The verdict is rejected. */
  "unknown-unit",
  /** Two verdicts for the same unit. The first is kept. */
  "duplicate-unit",
  /** The reply echoed a different batch id. */
  "batch-id-mismatch",
  /** A check the prompt demanded was not answered. */
  "missing-check",
  /** A check name the prompt never asked for. It is dropped. */
  "unknown-check",
  /** A `not-applicable` with no reason, so it cannot be read as either answer. */
  "unexplained-not-applicable",
  /** A check said `fail` and no finding was filed under its rule. */
  "fail-without-finding",
  /** A finding under a rule this kind's prompt never offered. It is dropped. */
  "unknown-rule",
  /** A finding whose location was not in any slice the batch showed. It is dropped. */
  "citation-not-shown",
  /** An evidence pointer that was not in any slice. It is dropped; the finding stays. */
  "evidence-not-shown",
  /** A severity above the rule's ceiling. It is lowered to the ceiling. */
  "severity-clamped",
  /** A field longer than the report will carry. It is truncated. */
  "text-clamped",
] as const;

/** One of the decoder's objections; see {@link VERDICT_ISSUE_KINDS}. */
export type VerdictIssueKind = (typeof VERDICT_ISSUE_KINDS)[number];

/** Something the decoder refused, changed or missed, with enough detail to quote. */
export interface VerdictIssue {
  readonly kind: VerdictIssueKind;
  /** The unit it concerns, when it concerns one. */
  readonly unitId?: string | undefined;
  readonly detail: string;
}

/** One check's decoded outcome, normalised out of either accepted wire form. */
export interface DecodedCheck {
  /** The dotted check id the prompt demanded an answer under. */
  readonly checkId: string;
  readonly result: CheckResult;
  /** The line that proves a `pass`; only ever a line the batch showed. */
  readonly evidence?: CodeRef | undefined;
  readonly note?: string | undefined;
}

/**
 * A finding the model reported, once it has survived every gate here.
 *
 * Deliberately not a `Finding`: it has no id, no domain and no snippet, because
 * those are Sentinel's to assign — the id from `(domain, rule, file, symbol)`,
 * the snippet from disk. The audit phase builds the `Finding` from this and the
 * unit it belongs to.
 */
export interface DecodedFinding {
  readonly unitId: string;
  readonly kind: AuditUnitKind;
  readonly rule: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly location: CodeRef;
  readonly evidence: readonly CodeRef[];
  readonly exploitability?: string | undefined;
  readonly impact: string;
  readonly recommendation: string;
  readonly acceptanceCriteria: readonly string[];
  readonly cwe: readonly string[];
  readonly owasp: readonly string[];
}

/** One unit's decoded verdict. */
export interface DecodedVerdict {
  readonly unitId: string;
  readonly unit: AuditUnit;
  /** Every check the prompt demanded that was answered, in the prompt's order. */
  readonly checks: readonly DecodedCheck[];
  /** Checks the prompt demanded and the reply did not answer. */
  readonly missingChecks: readonly string[];
  readonly findings: readonly DecodedFinding[];
  readonly notes?: string | undefined;
  /** True when every check the prompt demanded was answered. */
  readonly complete: boolean;
}

/** What one batch's reply amounted to. */
export interface DecodedBatch {
  readonly batchId: string;
  readonly kind: AuditUnitKind;
  readonly verdicts: readonly DecodedVerdict[];
  /** Every kept finding across the batch, in unit order. */
  readonly findings: readonly DecodedFinding[];
  /** Units in the batch with no usable verdict, ready for `Coverage.skipped`. */
  readonly missing: readonly SkippedUnit[];
  readonly issues: readonly VerdictIssue[];
  /** Notes the model made about the batch as a whole. */
  readonly notes?: string | undefined;
}

/** Longest text the report carries per field; anything longer is truncated. */
const MAX_TEXT: Readonly<Record<string, number>> = {
  title: 160,
  description: 4_000,
  impact: 2_000,
  recommendation: 2_000,
  exploitability: 1_000,
  acceptanceCriterion: 400,
  note: 1_000,
  notes: 4_000,
};

/** Severities from weakest to strongest, for comparison against a ceiling. */
const SEVERITY_ORDER: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/** True when `value` is stronger than `ceiling`. */
function exceeds(value: Severity, ceiling: Severity): boolean {
  return SEVERITY_ORDER.indexOf(value) > SEVERITY_ORDER.indexOf(ceiling);
}

/** Normalises either accepted check form into one shape. */
function readOutcome(outcome: AgentCheckOutcome): {
  result: CheckResult;
  evidence?: AgentCodeRef | undefined;
  note?: string | undefined;
} {
  if (typeof outcome === "string") return { result: outcome };
  return {
    result: outcome.result,
    ...(outcome.evidence === undefined ? {} : { evidence: outcome.evidence }),
    ...(outcome.note === undefined ? {} : { note: outcome.note }),
  };
}

/** Collects issues while decoding, so every rejection reaches the caller. */
class IssueLog {
  readonly #issues: VerdictIssue[] = [];

  /** Records one objection. */
  add(kind: VerdictIssueKind, detail: string, unitId?: string): void {
    this.#issues.push({ kind, ...(unitId === undefined ? {} : { unitId }), detail });
  }

  /** Everything recorded, in the order it was found. */
  get issues(): VerdictIssue[] {
    return this.#issues;
  }
}

/** Truncates a field to what the report will carry, recording the cut once. */
function clamp(text: string, limit: number, field: string, unitId: string, log: IssueLog): string {
  const cut = truncate(text, limit);
  if (cut !== text) {
    log.add("text-clamped", `\`${field}\` was ${text.length} characters, cut to ${limit}`, unitId);
  }
  return cut;
}

/**
 * Turns a model citation into a `CodeRef`, or rejects it.
 *
 * The test is not "does this file exist" — that is `src/verify/`'s job — but
 * "was this line in the prompt". A line the batch did not print cannot have been
 * read, whatever it says about it.
 */
function readRef(
  ref: AgentCodeRef,
  ranges: CitedRanges,
  unitId: string,
  log: IssueLog,
  kind: "citation-not-shown" | "evidence-not-shown",
): CodeRef | undefined {
  if (!wasShown(ranges, ref.file, ref.line)) {
    log.add(
      kind,
      `${ref.file}:${ref.line} was not in the slices provided (${shownRangesOf(ranges, ref.file)})`,
      unitId,
    );
    return undefined;
  }
  return {
    file: ref.file,
    line: ref.line,
    ...(ref.endLine === undefined || ref.endLine < ref.line ? {} : { endLine: ref.endLine }),
    ...(ref.note === undefined ? {} : { note: truncate(ref.note, MAX_TEXT.note ?? 1_000) }),
  };
}

/** Decodes one finding, or drops it and says why. */
function readFinding(
  raw: AgentFinding,
  unit: AuditUnit,
  allowedRules: ReadonlySet<string>,
  ranges: CitedRanges,
  log: IssueLog,
): DecodedFinding | undefined {
  if (!allowedRules.has(raw.rule)) {
    log.add(
      "unknown-rule",
      `rule \`${raw.rule}\` was not offered to the ${unit.kind} audit; the finding is dropped`,
      unit.id,
    );
    return undefined;
  }
  const location = readRef(raw.location, ranges, unit.id, log, "citation-not-shown");
  if (location === undefined) return undefined;

  const evidence: CodeRef[] = [];
  for (const ref of raw.evidence) {
    const decoded = readRef(ref, ranges, unit.id, log, "evidence-not-shown");
    if (decoded !== undefined) evidence.push(decoded);
  }

  const ceiling = ceilingFor(unit.kind, raw.rule);
  let severity = raw.severity;
  if (ceiling !== undefined && exceeds(severity, ceiling)) {
    log.add(
      "severity-clamped",
      `\`${raw.rule}\` was reported as ${severity}; the rubric caps it at ${ceiling}`,
      unit.id,
    );
    severity = ceiling;
  }

  return {
    unitId: unit.id,
    kind: unit.kind,
    rule: raw.rule,
    title: clamp(raw.title, MAX_TEXT.title ?? 160, "title", unit.id, log),
    description: clamp(raw.description, MAX_TEXT.description ?? 4_000, "description", unit.id, log),
    severity,
    confidence: raw.confidence,
    location,
    evidence,
    ...(raw.exploitability === undefined
      ? {}
      : {
          exploitability: clamp(
            raw.exploitability,
            MAX_TEXT.exploitability ?? 1_000,
            "exploitability",
            unit.id,
            log,
          ),
        }),
    impact: clamp(raw.impact, MAX_TEXT.impact ?? 2_000, "impact", unit.id, log),
    recommendation: clamp(
      raw.recommendation,
      MAX_TEXT.recommendation ?? 2_000,
      "recommendation",
      unit.id,
      log,
    ),
    acceptanceCriteria: raw.acceptanceCriteria.map((criterion) =>
      truncate(criterion, MAX_TEXT.acceptanceCriterion ?? 400),
    ),
    cwe: [...raw.cwe],
    owasp: [...raw.owasp],
  };
}

/**
 * Decodes one unit's verdict: its checks, then the findings its failures owe.
 *
 * `domain` is the batch's, and it is what separates the two questions the
 * registry answers about a check id. **Permitted** is the union of every check
 * any prompt asks of this kind, because a reply may legitimately carry an answer
 * the batch did not insist on. **Obliged** is `checkIdsFor(kind, domain)` — only
 * the checks this batch's prompt actually printed. Reading the obligation off the
 * union instead is how a route's `api` batch, which asks five questions, came to
 * be judged against all twenty-three a route is ever asked: eighteen
 * `missing-check` issues per unit and `complete: false` on a reply that answered
 * everything it was shown.
 */
function readVerdict(
  raw: AgentUnitVerdict,
  unit: AuditUnit,
  domain: Domain,
  ranges: CitedRanges,
  log: IssueLog,
): DecodedVerdict {
  const permitted = checkIdsFor(unit.kind);
  const obliged = new Set(checkIdsFor(unit.kind, domain));
  const allowedRules = new Set(rulesFor(unit.kind));
  const answered = new Map<string, ReturnType<typeof readOutcome>>();

  for (const [id, outcome] of Object.entries(raw.checks)) {
    if (!permitted.includes(id)) {
      log.add("unknown-check", `\`${id}\` is not a check of the ${unit.kind} audit`, unit.id);
      continue;
    }
    answered.set(id, readOutcome(outcome));
  }

  const checks: DecodedCheck[] = [];
  for (const id of permitted) {
    const outcome = answered.get(id);
    if (outcome === undefined) continue;
    if (outcome.result === "not-applicable" && outcome.note === undefined) {
      log.add(
        "unexplained-not-applicable",
        `\`${id}\` is not applicable with no reason given`,
        unit.id,
      );
    }
    const evidence =
      outcome.evidence === undefined
        ? undefined
        : readRef(outcome.evidence, ranges, unit.id, log, "evidence-not-shown");
    checks.push({
      checkId: id,
      result: outcome.result,
      ...(evidence === undefined ? {} : { evidence }),
      ...(outcome.note === undefined
        ? {}
        : { note: truncate(outcome.note, MAX_TEXT.note ?? 1_000) }),
    });
  }

  // The hole in the coverage claim is what this batch asked and did not get
  // answered — never a question a different domain's batch is going to ask.
  const missingChecks: string[] = [];
  for (const id of obliged) {
    if (answered.has(id)) continue;
    missingChecks.push(id);
    log.add("missing-check", `\`${id}\` was not answered`, unit.id);
  }

  const findings: DecodedFinding[] = [];
  for (const raw2 of raw.findings) {
    const finding = readFinding(raw2, unit, allowedRules, ranges, log);
    if (finding !== undefined) findings.push(finding);
  }

  // A failed check owes a finding. Without one there is nothing to report, so
  // the failure would vanish from the dossier instead of appearing in it.
  const filed = new Set(findings.map((finding) => finding.rule));
  for (const check of checks) {
    if (check.result !== "fail") continue;
    const rule = ruleOf(unit.kind, check.checkId);
    if (rule !== undefined && !filed.has(rule)) {
      log.add(
        "fail-without-finding",
        `\`${check.checkId}\` failed but no finding was filed under \`${rule}\``,
        unit.id,
      );
    }
  }

  return {
    unitId: unit.id,
    unit,
    checks,
    missingChecks,
    findings,
    ...(raw.notes === undefined ? {} : { notes: truncate(raw.notes, MAX_TEXT.notes ?? 4_000) }),
    complete: missingChecks.length === 0,
  };
}

/**
 * The rule a named check files its failures under.
 *
 * Read off the prompt registry, never restated here: the prompt told the model
 * which rule that check's failure belongs to, and a second copy of the mapping
 * in the decoder is a copy that can drift.
 */
function ruleOf(kind: AuditUnitKind, id: string): string | undefined {
  return checksFor(kind).find((check) => checkIdOf(check) === id)?.rule;
}

/**
 * Decodes one batch's reply.
 *
 * Every rejection is recorded rather than thrown: a batch that came back with
 * one hallucinated unit id and thirty good verdicts is worth thirty verdicts,
 * and the hallucination is worth a line in the run log.
 */
export function decodeVerdicts(report: AgentVerdictReport, batch: AuditBatch): DecodedBatch {
  const log = new IssueLog();
  const ranges = citedRanges(batch);
  const units = new Map(batch.units.map((unit) => [unit.id, unit]));

  if (report.batchId !== undefined && report.batchId !== batch.id) {
    log.add(
      "batch-id-mismatch",
      `the reply echoed batch id \`${report.batchId}\`, this batch is \`${batch.id}\``,
    );
  }

  const verdicts: DecodedVerdict[] = [];
  const seen = new Set<string>();
  for (const raw of report.verdicts) {
    const unit = units.get(raw.unitId);
    if (unit === undefined) {
      log.add(
        "unknown-unit",
        `\`${raw.unitId}\` is not a unit of this batch; the verdict is rejected`,
        raw.unitId,
      );
      continue;
    }
    if (seen.has(raw.unitId)) {
      log.add("duplicate-unit", "a second verdict for this unit was discarded", raw.unitId);
      continue;
    }
    seen.add(raw.unitId);
    verdicts.push(readVerdict(raw, unit, batch.domain, ranges, log));
  }

  // The batch's own order, not the reply's: the report reads units in inventory
  // order, and a model that answers out of order must not change that.
  const order = new Map(batch.units.map((unit, index) => [unit.id, index]));
  verdicts.sort((left, right) => (order.get(left.unitId) ?? 0) - (order.get(right.unitId) ?? 0));

  // The domain is the batch's, because coverage is per domain: a route the
  // `api` batch said nothing about is missing from the `api` table, and filing
  // it without a domain would have counted it out of that table's total.
  const missing: SkippedUnit[] = batch.units
    .filter((unit) => !seen.has(unit.id))
    .map((unit) => ({
      unitId: unit.id,
      kind: unit.kind,
      domain: batch.domain,
      reason: "the audit returned no verdict for this unit",
    }));

  return {
    batchId: batch.id,
    kind: batch.kind,
    verdicts,
    findings: verdicts.flatMap((verdict) => verdict.findings),
    missing,
    issues: log.issues,
    ...(report.notes === undefined
      ? {}
      : { notes: truncate(report.notes, MAX_TEXT.notes ?? 4_000) }),
  };
}

// ---------------------------------------------------------------------------
// The audit phase's verdict seam
// ---------------------------------------------------------------------------

/**
 * The shapes the audit phase consumes, mirrored structurally.
 *
 * Mirrored rather than imported: the phase owns its own seam and this module owns
 * the wire format, and the whole point of the seam is that neither has to change
 * when the other is edited. `verdictSource()` is the one place the two meet.
 */
export interface PhaseVerdictRef {
  readonly file: string;
  readonly line: number;
  readonly endLine?: number | undefined;
  readonly note?: string | undefined;
}

/** A check the agent asserts a unit passes, as the phase reads it. */
export interface PhaseVerdictCheck {
  readonly id: string;
  readonly statement: string;
  readonly subject?: string | undefined;
  readonly evidence?: readonly PhaseVerdictRef[] | undefined;
}

/** A finding the agent claims, as the phase reads it. */
export interface PhaseVerdictFinding {
  readonly rule: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly title: string;
  readonly description: string;
  readonly impact: string;
  readonly recommendation: string;
  readonly location: PhaseVerdictRef;
  readonly domain?: Domain | undefined;
  readonly evidence?: readonly PhaseVerdictRef[] | undefined;
  readonly exploitability?: string | undefined;
  readonly acceptanceCriteria?: readonly string[] | undefined;
  readonly cwe?: readonly string[] | undefined;
  readonly owasp?: readonly string[] | undefined;
}

/** One unit's answer, as the phase reads it. */
export interface PhaseUnitVerdict {
  readonly unitId: string;
  readonly status: "clean" | "flagged" | "inconclusive";
  readonly checks?: readonly PhaseVerdictCheck[] | undefined;
  readonly findings?: readonly PhaseVerdictFinding[] | undefined;
  readonly note?: string | undefined;
}

/** A whole batch reply, as the phase reads it. */
export interface PhaseBatchVerdicts {
  readonly batchId?: string | undefined;
  readonly verdicts: readonly PhaseUnitVerdict[];
}

/** The domain a rule belongs to: its own prefix, when that prefix is a real domain. */
export function domainOfRule(rule: string): Domain | undefined {
  const parsed = DomainSchema.safeParse(rule.split(".")[0] ?? "");
  return parsed.success ? parsed.data : undefined;
}

/**
 * Why a unit's answer is `inconclusive` rather than `clean`.
 *
 * A model that answered nothing, or answered every question with "not
 * applicable", has not audited the unit — and the phase counts `inconclusive` as
 * not audited, which is the honest direction to round in. A unit that really does
 * have nothing to check reads as one unit short of the coverage claim, which is
 * a disclosure; the other way round would be a false pass.
 */
function statusOf(verdict: AgentUnitVerdict, findings: number): PhaseUnitVerdict["status"] {
  if (findings > 0) return "flagged";
  const decided = Object.values(verdict.checks).filter((outcome) => {
    const result = typeof outcome === "string" ? outcome : outcome.result;
    return result === "pass" || result === "fail";
  });
  return decided.length === 0 ? "inconclusive" : "clean";
}

/** Copies a citation into the phase's shape; the phase proves it against the slices. */
function phaseRef(ref: AgentCodeRef): PhaseVerdictRef {
  return {
    file: ref.file,
    line: ref.line,
    ...(ref.endLine === undefined || ref.endLine < ref.line ? {} : { endLine: ref.endLine }),
    ...(ref.note === undefined ? {} : { note: truncate(ref.note, MAX_TEXT.note ?? 1_000) }),
  };
}

/**
 * Reads a reply into the audit phase's vocabulary, without needing the batch.
 *
 * What it can do without the batch it does: the checks are resolved against the
 * global check index so a passing one arrives with the sentence the report will
 * print, each finding's domain comes from the rule the prompt told the model to
 * use, and a severity above the rubric's ceiling for that rule is lowered.
 *
 * What it cannot do without the batch, the phase does itself: rejecting a unit id
 * that was not in the batch, and dropping a citation that was not in a slice.
 * {@link decodeVerdicts} does both as well, with a full account of every
 * rejection, for a caller that has the batch in hand.
 */
export function readBatchVerdicts(report: AgentVerdictReport): PhaseBatchVerdicts {
  const verdicts: PhaseUnitVerdict[] = [];
  for (const raw of report.verdicts) {
    const findings: PhaseVerdictFinding[] = [];
    for (const finding of raw.findings) {
      const ceiling = ceilingOfRule(finding.rule);
      const severity =
        ceiling !== undefined && exceeds(finding.severity, ceiling) ? ceiling : finding.severity;
      const domain = domainOfRule(finding.rule);
      findings.push({
        rule: finding.rule,
        severity,
        confidence: finding.confidence,
        title: truncate(finding.title, MAX_TEXT.title ?? 160),
        description: truncate(finding.description, MAX_TEXT.description ?? 4_000),
        impact: truncate(finding.impact, MAX_TEXT.impact ?? 2_000),
        recommendation: truncate(finding.recommendation, MAX_TEXT.recommendation ?? 2_000),
        location: phaseRef(finding.location),
        ...(domain === undefined ? {} : { domain }),
        evidence: finding.evidence.map(phaseRef),
        ...(finding.exploitability === undefined
          ? {}
          : {
              exploitability: truncate(finding.exploitability, MAX_TEXT.exploitability ?? 1_000),
            }),
        acceptanceCriteria: finding.acceptanceCriteria.map((criterion) =>
          truncate(criterion, MAX_TEXT.acceptanceCriterion ?? 400),
        ),
        cwe: [...finding.cwe],
        owasp: [...finding.owasp],
      });
    }

    const checks: PhaseVerdictCheck[] = [];
    for (const [id, outcome] of Object.entries(raw.checks)) {
      const read = readOutcome(outcome);
      if (read.result !== "pass") continue;
      const check = checkById(id);
      if (check === undefined) continue;
      checks.push({
        id,
        statement: check.statement,
        ...(check.subject === undefined ? {} : { subject: check.subject }),
        ...(read.evidence === undefined ? {} : { evidence: [phaseRef(read.evidence)] }),
      });
    }

    verdicts.push({
      unitId: raw.unitId,
      status: statusOf(raw, findings.length),
      checks,
      findings,
      ...(raw.notes === undefined ? {} : { note: truncate(raw.notes, MAX_TEXT.notes ?? 4_000) }),
    });
  }
  return {
    ...(report.batchId === undefined ? {} : { batchId: report.batchId }),
    verdicts,
  };
}

/** The schema and the adapter the audit phase is configured with, in one object. */
export function verdictSource(): {
  readonly schema: typeof AgentVerdictReportSchema;
  readonly read: (value: AgentVerdictReport) => PhaseBatchVerdicts;
} {
  return { schema: AgentVerdictReportSchema, read: readBatchVerdicts };
}

/**
 * The passing checks of a decoded batch, in the shape `src/audit/assurance.ts`
 * aggregates — one row per unit that asserted the check, carrying the sentence
 * the report will print and the line that proves it.
 */
export function assertedChecksOf(decoded: DecodedBatch): readonly {
  readonly unitId: string;
  readonly kind: AuditUnitKind;
  readonly domain: Domain;
  readonly checkId: string;
  readonly statement: string;
  readonly subject?: string | undefined;
  readonly evidence: readonly CodeRef[];
}[] {
  const rows: {
    unitId: string;
    kind: AuditUnitKind;
    domain: Domain;
    checkId: string;
    statement: string;
    subject?: string | undefined;
    evidence: readonly CodeRef[];
  }[] = [];
  for (const verdict of decoded.verdicts) {
    for (const check of verdict.checks) {
      if (check.result !== "pass") continue;
      const spec = checkById(check.checkId);
      if (spec === undefined) continue;
      const domain = domainOfRule(spec.rule);
      if (domain === undefined) continue;
      rows.push({
        unitId: verdict.unitId,
        kind: verdict.unit.kind,
        domain,
        checkId: check.checkId,
        statement: spec.statement,
        ...(spec.subject === undefined ? {} : { subject: spec.subject }),
        evidence: check.evidence === undefined ? [] : [check.evidence],
      });
    }
  }
  return rows;
}

/** Every check that passed with a pointer, which is what an assurance is made of. */
export function passedChecks(
  decoded: DecodedBatch,
): readonly { readonly check: string; readonly unit: AuditUnit; readonly evidence?: CodeRef }[] {
  const passed: { check: string; unit: AuditUnit; evidence?: CodeRef }[] = [];
  for (const verdict of decoded.verdicts) {
    for (const check of verdict.checks) {
      if (check.result !== "pass") continue;
      passed.push({
        check: check.checkId,
        unit: verdict.unit,
        ...(check.evidence === undefined ? {} : { evidence: check.evidence }),
      });
    }
  }
  return passed;
}
