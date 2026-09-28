import { z } from "zod";
import { AuditUnitSchema, CodeRefSchema, SCHEMA_VERSION } from "./findings.ts";

/**
 * The phase 2 artifact: every unit of audit, with the `file:line` that proves
 * it exists.
 *
 * This document is what makes coverage provable. Phase 3 batches the units,
 * phase 4 must return a verdict for each one, and the report states
 * `150/150 route handlers audited` because this file listed 150 of them. It is
 * also diffable: two runs over unchanged code produce identical bytes, so the
 * inventory of one commit can be compared with the inventory of the next.
 */

/** File name of the phase 2 artifact inside a run directory. */
export const INVENTORY_FILE = "inventory.json";

/**
 * The kinds of unit the inventory enumerates, taken straight from `AuditUnit`
 * so the two can never drift.
 */
export const AuditUnitKindSchema = AuditUnitSchema.shape.kind;
/** One of the eleven unit kinds; see `AuditUnitSchema`. */
export type AuditUnitKind = z.infer<typeof AuditUnitKindSchema>;

/** Every unit kind, in the order the inventory sorts and counts them. */
export const AUDIT_UNIT_KINDS: readonly AuditUnitKind[] = AuditUnitKindSchema.options;

/**
 * The noun each unit kind is counted in, singular then plural.
 *
 * It lives beside the kinds rather than in a renderer because three phases now
 * put these words in front of a reader — the score phase naming the evidence a
 * domain was not audited against, the PDF's coverage section, and the terminal
 * scorecard — and a count whose `500 migrations` become `500 migration units`
 * one page later reads like two tools arguing.
 */
export const AUDIT_UNIT_NOUN: Readonly<Record<AuditUnitKind, readonly [string, string]>> = {
  route: ["route handler", "route handlers"],
  "data-access": ["data-access call site", "data-access call sites"],
  "serverless-function": ["serverless function", "serverless functions"],
  "queue-consumer": ["queue consumer", "queue consumers"],
  cron: ["scheduled job", "scheduled jobs"],
  webhook: ["webhook receiver", "webhook receivers"],
  migration: ["migration", "migrations"],
  "role-gate": ["role gate", "role gates"],
  sink: ["unsafe-input sink", "unsafe-input sinks"],
  "workflow-job": ["CI workflow job", "CI workflow jobs"],
  container: ["container definition", "container definitions"],
};

/**
 * `12,345`: thousands grouped by hand rather than through `Intl`.
 *
 * Every artifact this project writes has to be byte-identical between two runs
 * over unchanged code, and a locale-sensitive formatter makes that a property of
 * the machine instead of the input.
 */
export function groupThousands(count: number): string {
  return String(Math.trunc(count)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** `1 scheduled job` / `500 migrations`, in the inventory's own vocabulary. */
export function countUnits(kind: AuditUnitKind, count: number): string {
  const noun = AUDIT_UNIT_NOUN[kind];
  return `${groupThousands(count)} ${count === 1 ? noun[0] : noun[1]}`;
}

/**
 * Attribute keys that cross enumerator boundaries.
 *
 * `attributes` is an open record on purpose — a queue consumer says things a
 * role gate never will — but a handful of keys are read by *another*
 * enumerator or by the audit prompt, and those have to be spelled the same
 * everywhere. A cron that hits `/api/cron/rotate` finds the route unit by
 * comparing `attributes[ATTRIBUTE.path]`, so a route enumerator that called it
 * `route` instead would silently break the cross-reference.
 */
export const ATTRIBUTE = {
  /** Request path of a route, webhook or cron target, e.g. `/api/cron/rotate`. */
  path: "path",
  /** HTTP method of a route or webhook, upper-case, e.g. `POST`. */
  method: "method",
  /** Hosting platform of a serverless function, e.g. `aws-lambda`, `vercel-edge`. */
  platform: "platform",
  /** What invokes a unit: `http`, `queue`, `schedule`, `storage`, `stream`, `event`. */
  trigger: "trigger",
  /** Library a consumer or scheduler is built on, e.g. `bullmq`, `inngest`. */
  library: "library",
  /** Queue, topic or event name a consumer reads from. */
  queue: "queue",
  /** Cron expression, exactly as written in the source. */
  schedule: "schedule",
  /** Whether the unit requires authentication: `yes`, `no`, `unknown`. */
  authenticated: "authenticated",
  /** Id of another unit this one points at, e.g. the route a cron calls. */
  targetUnitId: "targetUnitId",
  /** The enclosing function, component or class the unit sits in. */
  symbol: "symbol",
} as const;

/** How an enumerator ended; the vocabulary phase 1 steps already use. */
export const EnumeratorStatusSchema = z.enum(["ok", "degraded", "skipped", "failed"]);
/** How an enumerator ended; see {@link EnumeratorStatusSchema}. */
export type EnumeratorStatus = z.infer<typeof EnumeratorStatusSchema>;

/**
 * One enumerator's line in the inventory.
 *
 * An enumerator that could not run says so here, in its own words, and the
 * kinds it owns are listed even when it produced nothing — which is the
 * difference between "no queue consumers exist" and "nobody looked".
 */
export const EnumeratorReportSchema = z.object({
  name: z.string(),
  status: EnumeratorStatusSchema,
  /** Why the enumerator is not `ok`, or context worth disclosing when it is. */
  reason: z.string().optional(),
  kinds: z.array(AuditUnitKindSchema),
  /** Units this enumerator contributed to the document, after de-duplication. */
  units: z.number().int().nonnegative(),
});
/** One enumerator's line in the inventory; see {@link EnumeratorReportSchema}. */
export type EnumeratorReport = z.infer<typeof EnumeratorReportSchema>;

/**
 * A unit an enumerator produced that did not reach the document.
 *
 * Either its citation did not resolve against disk — the same rule that
 * governs findings applies to units — or another enumerator had already
 * claimed the same `(kind, file, symbol)`.
 */
export const DroppedUnitSchema = z.object({
  kind: AuditUnitKindSchema,
  label: z.string(),
  location: CodeRefSchema,
  /** The enumerator that produced it. */
  enumerator: z.string(),
  reason: z.string(),
});
/** A unit that did not reach the document; see {@link DroppedUnitSchema}. */
export type DroppedUnit = z.infer<typeof DroppedUnitSchema>;

/** The phase 2 artifact, written to `inventory.json`. */
export const InventoryDocumentSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  /** Absolute path of the inventoried repository. */
  target: z.string(),
  /** Every unit, sorted by kind, then file, then line. */
  units: z.array(AuditUnitSchema),
  /**
   * How many units of each kind, with every kind present even at zero: a zero
   * that was counted reads differently from a kind nobody enumerated, and the
   * enumerator reports say which of the two it is.
   */
  counts: z.record(AuditUnitKindSchema, z.number().int().nonnegative()),
  enumerators: z.array(EnumeratorReportSchema),
  dropped: z.array(DroppedUnitSchema),
});
/** The phase 2 artifact; see {@link InventoryDocumentSchema}. */
export type InventoryDocument = z.infer<typeof InventoryDocumentSchema>;

/** A zeroed count for every kind, in `AUDIT_UNIT_KINDS` order, for stable bytes. */
export function zeroCounts(): Record<AuditUnitKind, number> {
  const counts = {} as Record<AuditUnitKind, number>;
  for (const kind of AUDIT_UNIT_KINDS) counts[kind] = 0;
  return counts;
}
