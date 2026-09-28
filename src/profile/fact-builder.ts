import type { CodeRef, Confidence } from "../contracts/findings.ts";
import type { Absence, DetectedFact, FactKind } from "../contracts/profile.ts";

/** Builds a `CodeRef`, keeping optional keys absent rather than `undefined`. */
export function ref(file: string, line = 1, note?: string): CodeRef {
  return { file, line: line > 0 ? line : 1, ...(note === undefined ? {} : { note }) };
}

/** Arguments for `fact`, mirroring `DetectedFact` with optional keys truly optional. */
export interface FactInput {
  readonly kind: FactKind;
  readonly value: string;
  readonly confidence: Confidence;
  readonly evidence: readonly CodeRef[];
  readonly detail?: string;
}

/** Builds a `DetectedFact`; callers must supply at least one piece of evidence. */
export function fact(input: FactInput): DetectedFact {
  return {
    kind: input.kind,
    value: input.value,
    confidence: input.confidence,
    evidence: [...input.evidence],
    ...(input.detail === undefined ? {} : { detail: input.detail }),
  };
}

/** A kind a detector looked for; it becomes an `Absence` when it produced no fact. */
export interface Probe {
  readonly kind: FactKind;
  /** What was inspected: dependency names, file paths, directory names. */
  readonly searched: readonly string[];
  readonly note?: string;
}

/** What one detector returns: the facts it proved, the kinds it probed, and any caveats. */
export interface DetectionResult {
  readonly facts: readonly DetectedFact[];
  readonly probes: readonly Probe[];
  readonly warnings: readonly string[];
}

/** An empty detection result, used as the base when a detector bails out early. */
export const EMPTY_DETECTION: DetectionResult = { facts: [], probes: [], warnings: [] };

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/** Returns the stronger of two confidences. */
export function strongerConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b;
}

function refKey(codeRef: CodeRef): string {
  return `${codeRef.file}:${codeRef.line}:${codeRef.note ?? ""}`;
}

/**
 * Collapses facts that state the same `(kind, value)` into one entry.
 *
 * Two proofs of "this repo uses Prisma" are one fact with two pieces of
 * evidence, not two facts — otherwise the scope proposal would count the same
 * thing twice. The merged fact keeps the strongest confidence seen and the
 * first `detail` that was set.
 */
export function mergeFacts(facts: readonly DetectedFact[], maxEvidence = 25): DetectedFact[] {
  const merged = new Map<string, DetectedFact>();
  for (const next of facts) {
    const key = `${next.kind}\u0000${next.value}`;
    const current = merged.get(key);
    if (current === undefined) {
      merged.set(key, { ...next, evidence: [...next.evidence].slice(0, maxEvidence) });
      continue;
    }
    const seen = new Set(current.evidence.map(refKey));
    const evidence = [...current.evidence];
    for (const codeRef of next.evidence) {
      if (evidence.length >= maxEvidence) break;
      if (seen.has(refKey(codeRef))) continue;
      seen.add(refKey(codeRef));
      evidence.push(codeRef);
    }
    const detail = current.detail ?? next.detail;
    merged.set(key, {
      kind: current.kind,
      value: current.value,
      confidence: strongerConfidence(current.confidence, next.confidence),
      evidence,
      ...(detail === undefined ? {} : { detail }),
    });
  }
  return [...merged.values()];
}

/**
 * Turns the probes that produced no fact into absences.
 *
 * This is the mechanism behind "absent things are reported absent": a detector
 * declares what it looked for, and anything it looked for and did not find is
 * recorded with the list of what was inspected.
 */
export function absencesFrom(probes: readonly Probe[], facts: readonly DetectedFact[]): Absence[] {
  const proven = new Set(facts.map((f) => f.kind));
  const byKind = new Map<FactKind, Absence>();
  for (const probe of probes) {
    if (proven.has(probe.kind)) continue;
    const current = byKind.get(probe.kind);
    const searched = [...new Set([...(current?.searched ?? []), ...probe.searched])];
    const note = current?.note ?? probe.note;
    byKind.set(probe.kind, { kind: probe.kind, searched, ...(note === undefined ? {} : { note }) });
  }
  return [...byKind.values()];
}
