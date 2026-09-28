/**
 * The shape phase 4 demands back from the model — the wire format of an audit
 * reply, and nothing more.
 *
 * Everything here is **untrusted input**. The agent is handed source slices and
 * a list of unit ids and must answer with one verdict per unit; what comes back
 * is prose that may or may not contain the document we asked for. This schema
 * is the first gate (`src/agents/json.ts#parseStructured` runs it), and
 * `src/audit/verdict.ts` is the second: it rejects a verdict for a unit that
 * was never in the batch, drops a citation that falls outside the slices the
 * model was given, and clamps a severity the rubric does not allow.
 *
 * Two deliberate absences:
 *
 * - **No snippet field.** Snippets are extracted from disk by `src/verify/`,
 *   never taken from model output, so there is nowhere for the model to put one.
 * - **No unit metadata.** A verdict carries a `unitId` and nothing else about
 *   the unit; the label, kind, file and attributes are Sentinel's, already in
 *   `inventory.json`, and a reply that disagreed with them would only be a way
 *   to corrupt them.
 */

import { z } from "zod";
import { SeveritySchema } from "./findings.ts";

/**
 * How one named check came out for one unit.
 *
 * - `pass` — the control the check looks for is present in the code that was
 *   provided. This is what becomes an `Assurance`.
 * - `fail` — it is absent or wrong, and the verdict must carry a finding for it.
 * - `not-applicable` — the check cannot apply to this unit (a `GET` has no mass
 *   assignment), **or** the code needed to answer it was not in the slices.
 *   Either way it is not an assurance, and the verdict is expected to say which
 *   of the two it is.
 */
export const CheckResultSchema = z.enum(["pass", "fail", "not-applicable"]);
/** How one named check came out; see {@link CheckResultSchema}. */
export type CheckResult = z.infer<typeof CheckResultSchema>;

/** Every check result, for exhaustive rendering and tests. */
export const CHECK_RESULTS: readonly CheckResult[] = CheckResultSchema.options;

/**
 * A citation as the model writes it: a file and a line, never a snippet.
 *
 * `file` is repo-relative because that is how every slice header presents it;
 * an absolute path or a `..` segment is rejected downstream by
 * `src/verify/paths.ts` rather than here, so the failure is reported in one
 * vocabulary instead of two.
 */
export const AgentCodeRefSchema = z.object({
  file: z.string().min(1),
  line: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  /** What this pointer is meant to show; rendered next to the snippet. */
  note: z.string().optional(),
});
/** A citation as the model writes it; see {@link AgentCodeRefSchema}. */
export type AgentCodeRef = z.infer<typeof AgentCodeRefSchema>;

/**
 * One check's outcome, in either of the two forms the prompt accepts.
 *
 * The bare form (`"pass"`) is what a model writes when nothing else is worth
 * saying, and refusing it would cost a retry for no information. The object
 * form carries the pointer that proves a `pass` — which is what turns a passing
 * check into an assurance with evidence — and the note that explains a
 * `not-applicable`. `src/audit/verdict.ts` normalises both into one shape.
 */
export const AgentCheckOutcomeSchema = z.union([
  CheckResultSchema,
  z.object({
    result: CheckResultSchema,
    /** The line that proves a `pass`, or the one a `not-applicable` is about. */
    evidence: AgentCodeRefSchema.optional(),
    note: z.string().optional(),
  }),
]);
/** One check's outcome, in either accepted form; see {@link AgentCheckOutcomeSchema}. */
export type AgentCheckOutcome = z.infer<typeof AgentCheckOutcomeSchema>;

/**
 * A finding as the model reports it.
 *
 * The field list is `Finding` minus everything Sentinel owns: the id (hashed
 * from the unit and the rule), the domain (fixed by the rule), the snippet
 * (read from disk) and the source (`agent:audit`). `confidence` defaults to
 * `medium` rather than being required, because a model that omits it is not
 * making a claim about certainty and a retry would buy nothing.
 */
export const AgentFindingSchema = z.object({
  /** One of the rule ids the prompt listed for this unit kind. */
  rule: z.string().min(1),
  title: z.string().min(1),
  /** What the code does and why that is wrong. */
  description: z.string().min(1),
  severity: SeveritySchema,
  confidence: z.enum(["high", "medium", "low"]).default("medium"),
  /** Must fall inside a slice the prompt provided. */
  location: AgentCodeRefSchema,
  evidence: z.array(AgentCodeRefSchema).default([]),
  /** The preconditions for exploitation: auth level, flags, config, reachability. */
  exploitability: z.string().optional(),
  impact: z.string().min(1),
  recommendation: z.string().min(1),
  acceptanceCriteria: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  owasp: z.array(z.string()).default([]),
});
/** A finding as the model reports it; see {@link AgentFindingSchema}. */
export type AgentFinding = z.infer<typeof AgentFindingSchema>;

/**
 * One unit's verdict: every check the prompt named, and a finding for every
 * check that failed.
 *
 * `checks` is a map rather than a list so the prompt's check names are the keys
 * and an omission is a missing key — which is exactly what the decoder counts
 * as a coverage hole.
 */
export const AgentUnitVerdictSchema = z.object({
  /** Must be one of the unit ids the prompt listed, copied verbatim. */
  unitId: z.string().min(1),
  checks: z.record(z.string().min(1), AgentCheckOutcomeSchema),
  findings: z.array(AgentFindingSchema).default([]),
  /** Anything worth recording that is not a finding: doubt, missing context. */
  notes: z.string().optional(),
});
/** One unit's verdict; see {@link AgentUnitVerdictSchema}. */
export type AgentUnitVerdict = z.infer<typeof AgentUnitVerdictSchema>;

/** The document the audit agent returns for one batch. */
export const AgentVerdictReportSchema = z.object({
  /**
   * The batch id, echoed back. Optional, and compared when present: a reply
   * carrying another batch's id is a replay or a crossed transcript, and the
   * decoder says so rather than filing its findings.
   */
  batchId: z.string().optional(),
  verdicts: z.array(AgentUnitVerdictSchema),
  /** Observations about the batch as a whole, not about any single unit. */
  notes: z.string().optional(),
});
/** The document the audit agent returns for one batch; see {@link AgentVerdictReportSchema}. */
export type AgentVerdictReport = z.infer<typeof AgentVerdictReportSchema>;
