import type { CodeRef, Finding } from "../contracts/findings.ts";
import { DROP_REASONS, type DropReason, type RefHints, type VerifyContext } from "./context.ts";
import { type VerifyCache, createVerifyCache, verifyCodeRef } from "./verify-code-ref.ts";

/** A finding whose citations all resolved, with its verified refs substituted in. */
export interface VerifiedFinding {
  readonly ok: true;
  /** The finding with a verified location and only the evidence that resolved. */
  readonly finding: Finding;
  /** True when any of its citations had its line corrected. */
  readonly relocated: boolean;
  /** Evidence refs that did not resolve and were removed. */
  readonly droppedEvidence: number;
}

/** A finding refused because its primary location does not point at real code. */
export interface RejectedFinding {
  readonly ok: false;
  readonly reason: DropReason;
  readonly detail: string;
}

/** The outcome of verifying one finding. */
export type FindingVerification = VerifiedFinding | RejectedFinding;

/** A refused finding, kept so the run can report what it threw away. */
export interface DroppedFinding {
  readonly finding: Finding;
  readonly reason: DropReason;
  readonly detail: string;
}

/** What a batch of findings verified to, with the counters the report needs. */
export interface VerifyFindingsResult {
  /** Findings that survived, with Sentinel's own snippets. */
  readonly kept: Finding[];
  /** Findings refused, each with the reason it was refused for. */
  readonly dropped: DroppedFinding[];
  /** Feeds `FindingsDocument.droppedFindings`. */
  readonly droppedFindings: number;
  /** Evidence refs removed from otherwise valid findings. */
  readonly droppedEvidence: number;
  /** Findings whose line number had to be corrected. */
  readonly relocated: number;
  /** Drop count per reason, for the coverage section of the report. */
  readonly reasons: Record<DropReason, number>;
}

/**
 * Verifies a finding's primary location and every evidence ref. Unverifiable
 * evidence is dropped; an unverifiable location rejects the whole finding,
 * because nothing else in it can be trusted once the citation is wrong.
 */
export async function verifyFinding(
  finding: Finding,
  ctx: VerifyContext,
  hints: RefHints = {},
  cache: VerifyCache = createVerifyCache(),
): Promise<FindingVerification> {
  const location = await verifyCodeRef(finding.location, ctx, hints, cache);
  if (!location.ok) return { ok: false, reason: location.reason, detail: location.detail };

  const evidence: CodeRef[] = [];
  let droppedEvidence = 0;
  let relocated = location.relocated;
  for (const ref of finding.evidence) {
    const verified = await verifyCodeRef(ref, ctx, hints, cache);
    if (verified.ok) {
      evidence.push(verified.ref);
      relocated = relocated || verified.relocated;
    } else {
      droppedEvidence += 1;
    }
  }

  return {
    ok: true,
    finding: { ...finding, location: location.ref, evidence },
    relocated,
    droppedEvidence,
  };
}

/** A zeroed counter for every drop reason, so the report never shows a gap. */
function emptyReasons(): Record<DropReason, number> {
  const reasons = {} as Record<DropReason, number>;
  for (const reason of DROP_REASONS) reasons[reason] = 0;
  return reasons;
}

/**
 * Verifies a batch of findings against disk, splitting them into what can be
 * reported and what must be counted as dropped.
 */
export async function verifyFindings(
  findings: readonly Finding[],
  ctx: VerifyContext,
  hintsFor?: (finding: Finding) => RefHints | undefined,
): Promise<VerifyFindingsResult> {
  const cache = createVerifyCache();
  const kept: Finding[] = [];
  const dropped: DroppedFinding[] = [];
  const reasons = emptyReasons();
  let droppedEvidence = 0;
  let relocated = 0;

  for (const finding of findings) {
    const result = await verifyFinding(finding, ctx, hintsFor?.(finding) ?? {}, cache);
    if (result.ok) {
      kept.push(result.finding);
      droppedEvidence += result.droppedEvidence;
      if (result.relocated) relocated += 1;
    } else {
      dropped.push({ finding, reason: result.reason, detail: result.detail });
      reasons[result.reason] += 1;
    }
  }

  return {
    kept,
    dropped,
    droppedFindings: dropped.length,
    droppedEvidence,
    relocated,
    reasons,
  };
}
