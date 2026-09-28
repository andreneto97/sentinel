/**
 * Parser for dependency-cruiser's JSON output (`depcruise --output-type json`).
 *
 * Two facts are taken from it, and only those two: the module rings behind the
 * `cycle` violations, and the modules the graph marks as orphans. A rule
 * violation of any other kind is somebody else's ruleset talking, not a
 * Sentinel finding.
 */

import { z } from "zod";
import { type ParseOutcome, parseJsonWith } from "./_parse-outcome.ts";

/** One hop of a cycle. Older versions emit a bare module name instead of an object. */
const CycleSegmentSchema = z.union([z.string(), z.object({ name: z.string() })]);

/**
 * One rule violation. `cycle` is present only on `type: "cycle"` violations and
 * holds the ring starting at the module after `from`.
 */
const ViolationSchema = z.object({
  type: z.string(),
  from: z.string(),
  to: z.string(),
  rule: z.object({ name: z.string(), severity: z.string().optional() }),
  cycle: z.array(CycleSegmentSchema).optional(),
});

/** One module of the cruised graph; `orphan` is computed only when a rule asks for it. */
const ModuleSchema = z.object({
  source: z.string(),
  orphan: z.boolean().optional(),
});

/**
 * A rule as dependency-cruiser echoed it back. Only the two attributes Sentinel
 * relies on are typed; everything else is stripped.
 */
const RuleDefinitionSchema = z.object({
  name: z.string().optional(),
  from: z.object({ orphan: z.boolean().optional() }).optional(),
  to: z.object({ circular: z.boolean().optional() }).optional(),
});

/** The whole `--output-type json` document, reduced to what phase 1 reads. */
export const DependencyCruiserReportSchema = z.object({
  modules: z.array(ModuleSchema).default([]),
  summary: z
    .object({
      violations: z.array(ViolationSchema).default([]),
      totalCruised: z.number().int().nonnegative().default(0),
      ruleSetUsed: z
        .object({
          forbidden: z.array(RuleDefinitionSchema).default([]),
          required: z.array(RuleDefinitionSchema).default([]),
        })
        .optional(),
    })
    .default({ violations: [], totalCruised: 0 }),
});
/** A validated dependency-cruiser report. */
export type DependencyCruiserReport = z.infer<typeof DependencyCruiserReportSchema>;

/** One circular import ring, canonicalised so the same cycle has one identity. */
export interface DependencyCycle {
  /** The ring, rotated to start at its lexicographically smallest member. */
  readonly modules: readonly string[];
  /** `a -> b -> a`; stable across runs and used as the finding's symbol. */
  readonly key: string;
}

/** Validate raw depcruise stdout; never throws. */
export function parseDependencyCruiserReport(raw: string): ParseOutcome<DependencyCruiserReport> {
  return parseJsonWith(raw, DependencyCruiserReportSchema, "dependency-cruiser");
}

/** The module name of a cycle hop, whichever shape the version emitted. */
function segmentName(segment: z.infer<typeof CycleSegmentSchema>): string {
  return typeof segment === "string" ? segment : segment.name;
}

/** Rotates a ring so it starts at its smallest member; equal rings then compare equal. */
function canonicalRing(modules: readonly string[]): string[] {
  if (modules.length === 0) return [];
  let pivot = 0;
  for (let index = 1; index < modules.length; index += 1) {
    const candidate = modules[index];
    const best = modules[pivot];
    if (candidate !== undefined && best !== undefined && candidate < best) pivot = index;
  }
  return [...modules.slice(pivot), ...modules.slice(0, pivot)];
}

/**
 * Every distinct circular-import ring in the report.
 *
 * dependency-cruiser reports the same ring once per entry point that reaches
 * it, so the rings are canonicalised and de-duplicated: one finding per cycle,
 * not one per violation.
 */
export function cyclesOf(report: DependencyCruiserReport): DependencyCycle[] {
  const seen = new Map<string, DependencyCycle>();
  for (const violation of report.summary.violations) {
    if (violation.type !== "cycle") continue;
    const ring = canonicalRing((violation.cycle ?? []).map(segmentName));
    if (ring.length === 0) continue;
    const first = ring[0];
    if (first === undefined) continue;
    const key = [...ring, first].join(" -> ");
    if (!seen.has(key)) seen.set(key, { modules: ring, key });
  }
  return [...seen.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/**
 * Every module the graph marks as an orphan.
 *
 * The module attribute is the fact; the `no-orphans` violations are one
 * ruleset's opinion about it. Both are read, because a target's own
 * configuration may exclude paths from the rule while still computing the
 * attribute, and an older report may carry the violation without the attribute.
 */
export function orphansOf(report: DependencyCruiserReport): string[] {
  const orphans = new Set<string>();
  for (const module of report.modules) {
    if (module.orphan === true) orphans.add(module.source);
  }
  for (const violation of report.summary.violations) {
    if (violation.type !== "module") continue;
    if (violation.from !== violation.to) continue;
    if (!/orphan/i.test(violation.rule.name)) continue;
    orphans.add(violation.from);
  }
  return [...orphans].sort();
}

/** True when the ruleset that ran actually looks for circular dependencies. */
export function detectsCycles(report: DependencyCruiserReport): boolean {
  const ruleSet = report.summary.ruleSetUsed;
  if (ruleSet === undefined) return true;
  return [...ruleSet.forbidden, ...ruleSet.required].some((rule) => rule.to?.circular === true);
}

/** True when the ruleset that ran actually looks for orphan modules. */
export function detectsOrphans(report: DependencyCruiserReport): boolean {
  const ruleSet = report.summary.ruleSetUsed;
  if (ruleSet === undefined) return true;
  return [...ruleSet.forbidden, ...ruleSet.required].some((rule) => rule.from?.orphan === true);
}
