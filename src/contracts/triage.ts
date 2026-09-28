/**
 * Human triage: the reviewed verdicts a person hands back after checking a run
 * by hand.
 *
 * A dossier is not finished when the model stops. Somebody reads the severe
 * findings against the real code, and some of them do not survive: the
 * interpolated value came from a validated enum, the endpoint is already
 * admin-only, the migration overwrote nothing. Those verdicts are an **input**
 * to this tool, not an edit to its output — editing `findings.json` by hand and
 * re-rendering produces a document that silently omits what a human removed,
 * and a reader cannot tell a finding that was never made from one that was
 * taken out.
 *
 * So this document is read from disk like any other, validated like any other,
 * and everything it withholds is still named in the report.
 *
 * Three properties the schema enforces rather than the code that consumes it:
 *
 * 1. **Every verdict carries a note.** A finding withheld without a stated
 *    reason is exactly the silent deletion this feature exists to refuse.
 * 2. **One verdict per finding.** Two verdicts for the same id are a
 *    contradiction, and picking one of them would be this tool choosing what a
 *    reviewer meant.
 * 3. **An `overstated` verdict names the severity it should have been.** The
 *    correction is the whole content of that verdict; without a resolvable
 *    severity it says only that the reviewer was unhappy.
 *
 * There is no run id here, deliberately: reviewers write these files against a
 * dossier, not against a directory. The binding to a run is the finding ids
 * themselves, and `src/report/triage.ts` refuses a triage whose ids do not
 * belong to the run being rendered — a stale file means the reviewer was
 * looking at different code.
 */

import { z } from "zod";
import { SCHEMA_VERSION, type Severity, SeveritySchema } from "./findings.ts";

/**
 * The adjusted findings document, written beside `findings.json` rather than
 * over it.
 *
 * The raw model output stays on disk exactly as the run produced it, so the
 * triage is auditable: a reader can diff the two and see every severity that
 * moved and every finding that left.
 */
export const TRIAGED_FINDINGS_FILE = "findings.triaged.json";

/**
 * What a reviewer concluded about one finding.
 *
 * - `true` — checked and it holds. The finding is unchanged and marked
 *   confirmed, which is the most valuable line in the document.
 * - `false` — checked and it does not hold. The finding is **withheld**: it
 *   leaves the findings and the counts, and it is listed with the reason.
 * - `overstated` — real, but not at that severity. The severity is corrected
 *   and both numbers are kept.
 * - `unclear` — could not be decided. The finding stays at its reported
 *   severity and is flagged as contested, because an undecided finding is not a
 *   confirmed one and is not a false one either.
 */
export const TriageVerdictSchema = z.enum(["true", "false", "overstated", "unclear"]);
/** One of the four reviewed verdicts; see {@link TriageVerdictSchema}. */
export type TriageVerdict = z.infer<typeof TriageVerdictSchema>;

/** Every verdict, for exhaustive rendering and tests. */
export const TRIAGE_VERDICTS: readonly TriageVerdict[] = TriageVerdictSchema.options;

/** The words a reviewer writes for a severity, including the long form of `info`. */
const SEVERITY_WORDS: Readonly<Record<string, Severity>> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "info",
  info: "info",
};

/** `informational` before `info`, so the longer word wins the match. */
const SEVERITY_WORD = /\b(critical|high|medium|low|informational|info)\b/i;

/**
 * The severity inside a reviewer's correction, or `undefined` when it names none.
 *
 * Reviewers do not write enums. The field carries `"low"`, but also
 * `"informational"`, `"drop (or low, as a note that the seed script pins one
 * station id)"` and `"medium (the description miscounts: 3 docks, not 9)"` —
 * prose with a severity in it. Refusing those would push the reviewer into
 * editing `findings.json` by hand, which is the thing this document exists to
 * prevent, so the severity is read out of the sentence and the sentence is kept
 * in the note.
 */
export function resolveSeverity(text: string | undefined): Severity | undefined {
  if (text === undefined) return undefined;
  const match = SEVERITY_WORD.exec(text);
  if (match === null) return undefined;
  return SEVERITY_WORDS[(match[1] ?? "").toLowerCase()];
}

/**
 * One reviewed finding.
 *
 * `rule`, `file`, `line` and `reportedSeverity` are the reviewer's copy of what
 * they looked at. They are not used to find the finding — `id` does that — they
 * are used to prove the reviewer and the run agree about it, which is what
 * catches a triage written against an earlier run of the same repository.
 */
export const TriageEntrySchema = z.object({
  /** The finding's id, as `findings.json` published it. */
  id: z.string().min(1),
  rule: z.string().min(1),
  file: z.string().min(1),
  line: z.number().int().positive(),
  /** The severity the run reported, as a cross-check against this run. */
  reportedSeverity: SeveritySchema,
  verdict: TriageVerdictSchema,
  /**
   * The corrected severity, in the reviewer's own words.
   *
   * Free text rather than an enum: see {@link resolveSeverity}. Required in
   * practice only for `overstated`, where it is the point of the verdict.
   */
  severity: z.string().min(1).optional(),
  /** Why. Printed verbatim beside the finding it decided. */
  note: z.string().min(1),
});
/** One reviewed finding; see {@link TriageEntrySchema}. */
export type TriageEntry = z.infer<typeof TriageEntrySchema>;

/** A reviewer's verdicts over one run, as the file on disk carries them. */
export const TriageDocumentSchema = z
  .object({
    schemaVersion: z.literal(SCHEMA_VERSION),
    /** Who reviewed, in their own words; printed in the report as given. */
    reviewer: z.string().min(1),
    verdicts: z.array(TriageEntrySchema).min(1),
  })
  .superRefine((document, ctx) => {
    const seen = new Map<string, number>();
    document.verdicts.forEach((entry, index) => {
      const first = seen.get(entry.id);
      if (first === undefined) {
        seen.set(entry.id, index);
      } else {
        ctx.addIssue({
          code: "custom",
          path: ["verdicts", index, "id"],
          message: `${entry.id} already has a verdict at verdicts[${first}]; one finding cannot carry two`,
        });
      }
      if (entry.verdict === "overstated" && resolveSeverity(entry.severity) === undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["verdicts", index, "severity"],
          message: `an overstated verdict must name the corrected severity; "${entry.severity ?? ""}" names none`,
        });
      }
    });
  });
/** A reviewer's verdicts over one run; see {@link TriageDocumentSchema}. */
export type TriageDocument = z.infer<typeof TriageDocumentSchema>;
