/**
 * Phase 2 — the inventory.
 *
 * Runs every enumerator over the target concurrently and merges what they find
 * into one list of audit units: the complete, enumerated set of things phase 4
 * must return a verdict for. This is the artifact that lets the report say
 * `N of N route handlers audited` instead of "we looked at some handlers".
 *
 * Four properties the rest of the pipeline depends on:
 *
 * - **A failing enumerator is a reported enumerator, not a failed phase.**
 *   Every enumerator returns an outcome instead of throwing, and the
 *   aggregator additionally guards each one with a wall-clock budget and a
 *   catch, so one bad query costs one line in the report and not the phase.
 * - **Every unit's citation is proven against disk.** A unit is a promise that
 *   there is code at `file:line` to slice into the audit prompt; one that does
 *   not resolve is dropped and listed, under the same rule that governs
 *   findings.
 * - **Identity is content-addressed.** A unit's id hashes `(kind, file,
 *   symbol)`, never a line number, so two runs across an edit that only moved
 *   code still recognise the same unit.
 * - **Two runs over unchanged code produce identical bytes.** Enumerators run
 *   concurrently and finish in any order, so ids are assigned in registration
 *   order, attributes are key-sorted, and the units are sorted before they are
 *   written. Nothing that varies between two runs — a duration, a path outside
 *   the repo — goes into the document.
 */

import { join } from "node:path";
import type { AuditUnit, CodeRef } from "../contracts/findings.ts";
import { SCHEMA_VERSION } from "../contracts/findings.ts";
import {
  AUDIT_UNIT_KINDS,
  type AuditUnitKind,
  type DroppedUnit,
  type EnumeratorReport,
  INVENTORY_FILE,
  type InventoryDocument,
  InventoryDocumentSchema,
  zeroCounts,
} from "../contracts/inventory.ts";
import { RepoSnapshot } from "../profile/repo-snapshot.ts";
import { type VerifyFileSystem, createVerifyCache, verifyCodeRef } from "../verify/index.ts";
import { type StructuralSearch, createAstGrepSearch } from "./_ast-grep.ts";
import type { SchemaModelDocument } from "./_orms/schema-model.ts";
import {
  type Containment,
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryContext,
  type InventoryEnumerator,
  type InventoryFileSystem,
  attributesOf,
  carriedNote,
  containUnits,
  containmentNote,
  joinReasons,
  unitId,
} from "./_unit-support.ts";
import { ASYNC_UNIT_ENUMERATORS } from "./async-units.ts";
import { CLIENT_SURFACE_ENUMERATORS } from "./client-surface.ts";
import { CONTAINER_ENUMERATORS } from "./containers.ts";
import { DATA_ACCESS_ENUMERATORS } from "./data-access.ts";
import { MIGRATION_ENUMERATORS, buildSchemaModel, writeSchemaModel } from "./migrations.ts";
import { ROUTE_ENUMERATORS } from "./routes.ts";

export type {
  AttributePatch,
  Containment,
  ContainmentResult,
  DraftUnit,
  EnumerationContext,
  EnumerationOutcome,
  InventoryContext,
  InventoryEnumerator,
  InventoryFileSystem,
  InventoryProcessExecutor,
  InventoryToolResolver,
} from "./_unit-support.ts";

/** Budget for one enumerator, after which the phase stops waiting for it. */
export const ENUMERATOR_TIMEOUT_MS = 180_000;

/**
 * Slack between the budget an enumerator's own work is given and the guard the
 * aggregator holds over it.
 *
 * The inner timeout should always fire first, because ast-grep's killer can say
 * *which* search timed out and the enumerator can still return the units it
 * read from manifests. The guard exists only for an enumerator that hangs
 * somewhere no timeout covers.
 */
export const ENUMERATOR_GRACE_FACTOR = 1.25;

/**
 * The enumerators the phase runs.
 *
 * A function rather than a constant so registration order is fixed at call
 * time, and so a caller can splice in its own list without this module having
 * been the one to decide.
 *
 * Every kind the contract declares is claimed by one of these, `container`
 * included as of `./containers.ts` — so a count of 0 is now always a repository
 * that has none of that kind, and never a kind nobody enumerated. The registered
 * order is the order ids are assigned in, and the contract's kind order, which is
 * why the container enumerator comes last.
 */
export function defaultEnumerators(): InventoryEnumerator[] {
  return [
    ...ROUTE_ENUMERATORS,
    ...DATA_ACCESS_ENUMERATORS,
    ...MIGRATION_ENUMERATORS,
    ...ASYNC_UNIT_ENUMERATORS,
    ...CLIENT_SURFACE_ENUMERATORS,
    ...CONTAINER_ENUMERATORS,
  ];
}

/** Knobs for {@link runInventory}; every one has a working default. */
export interface RunInventoryOptions {
  /** Enumerators to run. Defaults to {@link defaultEnumerators}. */
  readonly enumerators?: readonly InventoryEnumerator[] | undefined;
  /** Repository listing to share. Built from the target when omitted. */
  readonly snapshot?: RepoSnapshot | undefined;
  /** Structural search to share. Backed by the pinned ast-grep when omitted. */
  readonly search?: StructuralSearch | undefined;
  /** Write `inventory.json` into the run directory. Default true. */
  readonly write?: boolean | undefined;
}

/** What phase 2 produced, and where it left it. */
export interface InventoryResult {
  readonly document: InventoryDocument;
  /** Absolute path of `inventory.json`, or null when writing was turned off. */
  readonly path: string | null;
  /**
   * The schema the migration pass reconstructed, or null when it produced none.
   *
   * Returned as well as written because phase 3 takes it as a value: a caller
   * that plans batches in the same process should not have to read back a file
   * it just watched being written.
   */
  readonly schema: SchemaModelDocument | null;
  /** Absolute paths this phase wrote, sorted; empty when writing was turned off. */
  readonly artifacts: readonly string[];
  /** Wall-clock time of the phase; deliberately not part of the document. */
  readonly durationMs: number;
}

/**
 * The schema the migration pass reconstructed, or null when there is none.
 *
 * Only asked for when a registered enumerator owns the `migration` kind, and
 * then it is free: that enumerator and this call share one memo keyed on the
 * context object, so the work was already done to produce the migration units.
 * A schema with no tables is reported as none — there is nothing for phase 3 to
 * excerpt from it, and writing an empty artifact would only suggest otherwise.
 *
 * The budget covers the one case the memo cannot: an enumerator the aggregator
 * gave up waiting for, whose underlying scan is still running. Phase 2 must not
 * block on it a second time, and a missing excerpt costs phase 3 a disclosure
 * rather than a verdict.
 */
async function reconstructSchema(
  enumerators: readonly InventoryEnumerator[],
  ctx: EnumerationContext,
  timeoutMs: number,
): Promise<SchemaModelDocument | null> {
  if (!enumerators.some((enumerator) => enumerator.kinds.includes("migration"))) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
    timer.unref?.();
  });
  try {
    const schema = await Promise.race([buildSchemaModel(ctx).catch(() => null), budget]);
    return schema === null || schema.tables.length === 0 ? null : schema;
  } finally {
    clearTimeout(timer);
  }
}

/** Adapts the filesystem port to the narrower seam the citation verifier takes. */
function verifyFileSystem(fs: InventoryFileSystem): VerifyFileSystem {
  return {
    readBytes: (path: string) => fs.readFileBytes(path),
    realpath: (path: string) => fs.realpath(path),
  };
}

/** Runs one enumerator under a budget; a throw or a hang becomes a `failed` outcome. */
export async function runEnumerator(
  enumerator: InventoryEnumerator,
  ctx: EnumerationContext,
  timeoutMs: number,
): Promise<EnumerationOutcome> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<EnumerationOutcome>((resolve) => {
    timer = setTimeout(
      () => resolve({ status: "failed", units: [], reason: `timed out after ${timeoutMs}ms` }),
      timeoutMs,
    );
    timer.unref?.();
  });
  try {
    return await Promise.race([
      enumerator.enumerate(ctx).catch((error: unknown) => ({
        status: "failed" as const,
        units: [],
        reason: error instanceof Error ? error.message : String(error),
      })),
      budget,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** A draft with the enumerator that produced it, so a drop can name a culprit. */
interface Candidate {
  readonly enumerator: string;
  readonly draft: DraftUnit;
  readonly id: string;
}

/** Turns a draft into the citation the verifier proves. */
function citationOf(draft: DraftUnit): CodeRef {
  return {
    file: draft.file,
    line: draft.line,
    ...(draft.endLine !== undefined && draft.endLine > draft.line
      ? { endLine: draft.endLine }
      : {}),
    ...(draft.note === undefined ? {} : { note: draft.note }),
  };
}

/**
 * Sorts units into the order the document stores them: by kind in the order
 * the contract declares them, then by file, line, label and id.
 */
export function sortUnits(units: readonly AuditUnit[]): AuditUnit[] {
  const rank = new Map(AUDIT_UNIT_KINDS.map((kind, index) => [kind, index]));
  return [...units].sort(
    (left, right) =>
      (rank.get(left.kind) ?? 0) - (rank.get(right.kind) ?? 0) ||
      left.location.file.localeCompare(right.location.file) ||
      left.location.line - right.location.line ||
      left.label.localeCompare(right.label) ||
      left.id.localeCompare(right.id),
  );
}

/** Counts units per kind, with every kind present, in contract order. */
export function countByKind(units: readonly AuditUnit[]): Record<AuditUnitKind, number> {
  const counts = zeroCounts();
  for (const unit of units) counts[unit.kind] += 1;
  return counts;
}

/** Everything the document needs that enumeration does not produce. */
export interface InventoryDocumentInput {
  readonly runId: string;
  readonly target: string;
  readonly units: readonly AuditUnit[];
  readonly enumerators: readonly EnumeratorReport[];
  readonly dropped: readonly DroppedUnit[];
}

/**
 * Builds the document and validates it in one step, so an invalid inventory
 * cannot exist as a value.
 */
export function buildInventoryDocument(input: InventoryDocumentInput): InventoryDocument {
  const units = sortUnits(input.units);
  return InventoryDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    units,
    counts: countByKind(units),
    enumerators: [...input.enumerators],
    dropped: [...input.dropped],
  });
}

/** Two-space JSON with a trailing newline: diffable between runs and commits. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Writes `inventory.json`, re-validated on the way out; returns its path. */
export async function writeInventoryDocument(
  fs: Pick<InventoryFileSystem, "writeFile">,
  runDir: string,
  document: InventoryDocument,
): Promise<string> {
  const path = join(runDir, INVENTORY_FILE);
  await fs.writeFile(path, serialise(InventoryDocumentSchema.parse(document)));
  return path;
}

/**
 * Enumerates every unit of audit in the target and writes `inventory.json`.
 *
 * The enumerators run concurrently; everything after that is deterministic and
 * ordered, because the artifact has to be comparable between two runs.
 */
export async function runInventory(
  ctx: InventoryContext,
  options: RunInventoryOptions = {},
): Promise<InventoryResult> {
  const startedAt = performance.now();
  const enumerators = options.enumerators ?? defaultEnumerators();
  const snapshot = options.snapshot ?? (await RepoSnapshot.create(ctx.fs, ctx.targetDir));
  const search =
    options.search ??
    createAstGrepSearch({
      exec: ctx.exec,
      tools: ctx.tools,
      targetDir: ctx.targetDir,
      allowPathTools: ctx.allowPathTools,
      timeoutMs: ctx.timeoutMs,
      signal: ctx.signal,
    });
  const enumerationContext: EnumerationContext = { ...ctx, snapshot, search };
  const budget = Math.round((ctx.timeoutMs ?? ENUMERATOR_TIMEOUT_MS) * ENUMERATOR_GRACE_FACTOR);

  const outcomes = await Promise.all(
    enumerators.map((enumerator) => runEnumerator(enumerator, enumerationContext, budget)),
  );

  // Ids are assigned in registration order, never in completion order.
  const candidates: Candidate[] = [];
  for (let index = 0; index < enumerators.length; index += 1) {
    const enumerator = enumerators[index];
    const outcome = outcomes[index];
    if (enumerator === undefined || outcome === undefined) continue;
    for (const draft of outcome.units) {
      candidates.push({
        enumerator: enumerator.name,
        draft,
        id: unitId(draft.kind, draft.file, draft.symbol),
      });
    }
  }

  const cache = createVerifyCache();
  const verifyContext = { fs: verifyFileSystem(ctx.fs), targetDir: ctx.targetDir };
  const units: AuditUnit[] = [];
  const dropped: DroppedUnit[] = [];
  /** Unit id → the enumerator that produced it; the containment pass needs it. */
  const producedBy = new Map<string, string>();
  const seen = new Set<string>();

  for (const candidate of candidates) {
    const citation = citationOf(candidate.draft);
    if (seen.has(candidate.id)) {
      dropped.push({
        kind: candidate.draft.kind,
        label: candidate.draft.label,
        location: citation,
        enumerator: candidate.enumerator,
        reason: "another enumerator already claimed this (kind, file, symbol)",
      });
      continue;
    }
    const verified = await verifyCodeRef(citation, verifyContext, {}, cache);
    if (!verified.ok) {
      dropped.push({
        kind: candidate.draft.kind,
        label: candidate.draft.label,
        location: citation,
        enumerator: candidate.enumerator,
        reason: `${verified.reason}: ${verified.detail}`,
      });
      continue;
    }
    seen.add(candidate.id);
    producedBy.set(candidate.id, candidate.enumerator);
    // The snippet is deliberately not kept: phase 3 slices the real source out
    // of the file for the prompt, and a snippet per unit would triple the size
    // of an artifact whose job is to be diffed.
    const { snippet: _snippet, ...location } = verified.ref;
    units.push({
      id: candidate.id,
      kind: candidate.draft.kind,
      label: candidate.draft.label,
      location,
      attributes: attributesOf(candidate.draft.attributes),
    });
  }

  // Containment runs on the verified units and before anything counts them: a
  // query inside a migration or a handler is evidence of that unit, not a unit
  // of its own, so it must not reach the coverage denominator, the batches or
  // the report as a separate thing to return a verdict for.
  const sorted = sortUnits(units);
  const containment = containUnits(sorted);
  const remaining = [...containment.units];
  await applyCrossReferences(enumerators, candidates, remaining, enumerationContext);

  const disclosure = containmentDisclosure(sorted, containment.contained, producedBy);
  const reports: EnumeratorReport[] = enumerators.map((enumerator, index) => {
    const outcome = outcomes[index];
    const notes = disclosure.get(enumerator.name);
    const reason = joinReasons([outcome?.reason, notes?.absorbed, notes?.carried]);
    return {
      name: enumerator.name,
      status: outcome?.status ?? "failed",
      ...(reason === undefined ? {} : { reason }),
      kinds: [...enumerator.kinds],
      units: remaining.filter((unit) => producedBy.get(unit.id) === enumerator.name).length,
    };
  });

  const document = buildInventoryDocument({
    runId: ctx.runId,
    target: ctx.targetDir,
    units: remaining,
    enumerators: reports,
    dropped,
  });

  // The schema is reconstructed from the same replay that produced the
  // migration units, and phase 3 reads it out of the run directory to build the
  // data-layer prompts' schema excerpt. Writing it here is what connects the
  // two: without this the excerpt is silently always absent.
  const schema = await reconstructSchema(enumerators, enumerationContext, budget);

  const artifacts: string[] = [];
  let path: string | null = null;
  if (options.write !== false) {
    path = await writeInventoryDocument(ctx.fs, ctx.runDir, document);
    artifacts.push(path);
    if (schema !== null) artifacts.push(await writeSchemaModel(ctx.fs, ctx.runDir, schema));
  }

  return {
    document,
    path,
    schema,
    artifacts: artifacts.sort(),
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  };
}

/** The two sentences one enumerator owes a reader about containment. */
interface ContainmentDisclosure {
  /** Its own units that were folded into someone else's, or undefined. */
  readonly absorbed: string | undefined;
  /** What its units took in, or undefined. */
  readonly carried: string | undefined;
}

/**
 * Turns the containment decisions into per-enumerator disclosure.
 *
 * Both directions, because a reader meets the two halves of the accounting in
 * different rows of the same table: `data-access` has to explain why it
 * contributed 10 units after producing 50, and `migrations` has to explain that
 * its 20 units are carrying the other 40. Neither sentence is inferable from the
 * other row's numbers.
 */
function containmentDisclosure(
  enumerated: readonly AuditUnit[],
  contained: readonly Containment[],
  producedBy: ReadonlyMap<string, string>,
): Map<string, ContainmentDisclosure> {
  const own = new Map<string, AuditUnit[]>();
  for (const unit of enumerated) push(own, producedBy.get(unit.id), unit);

  const absorbed = new Map<string, Containment[]>();
  const carried = new Map<string, Containment[]>();
  for (const entry of contained) {
    push(absorbed, producedBy.get(entry.unit.id), entry);
    push(carried, producedBy.get(entry.containerId), entry);
  }

  const disclosure = new Map<string, ContainmentDisclosure>();
  for (const name of new Set([...absorbed.keys(), ...carried.keys()])) {
    disclosure.set(name, {
      absorbed: containmentNote(own.get(name) ?? [], absorbed.get(name) ?? []),
      carried: carriedNote(carried.get(name) ?? []),
    });
  }
  return disclosure;
}

/** Appends to a grouped map, ignoring an entry nobody claims. */
function push<T>(groups: Map<string, T[]>, key: string | undefined, value: T): void {
  if (key === undefined) return;
  const existing = groups.get(key);
  if (existing === undefined) groups.set(key, [value]);
  else existing.push(value);
}

/**
 * Runs the optional second pass and applies what it returns.
 *
 * Only attributes are taken: a cross-reference that tried to move a unit, drop
 * one or invent one is ignored, because coverage is decided by enumeration and
 * nothing else gets to change the list after it has been counted.
 */
async function applyCrossReferences(
  enumerators: readonly InventoryEnumerator[],
  candidates: readonly Candidate[],
  units: AuditUnit[],
  ctx: EnumerationContext,
): Promise<void> {
  const byId = new Map(units.map((unit) => [unit.id, unit]));
  for (const enumerator of enumerators) {
    if (enumerator.crossReference === undefined) continue;
    const ownIds = new Set(
      candidates.filter((c) => c.enumerator === enumerator.name).map((c) => c.id),
    );
    const own = units.filter((unit) => ownIds.has(unit.id));
    if (own.length === 0) continue;
    let patches: Awaited<ReturnType<NonNullable<InventoryEnumerator["crossReference"]>>>;
    try {
      patches = await enumerator.crossReference(own, units, ctx);
    } catch {
      // A cross-reference is an enrichment; failing it leaves the unit as it was.
      continue;
    }
    for (const [id, patch] of patches) {
      const unit = byId.get(id);
      if (unit === undefined || !ownIds.has(id)) continue;
      const merged = attributesOf({ ...unit.attributes, ...patch });
      byId.set(id, { ...unit, attributes: merged });
    }
  }
  for (let index = 0; index < units.length; index += 1) {
    const unit = units[index];
    if (unit === undefined) continue;
    const updated = byId.get(unit.id);
    if (updated !== undefined) units[index] = updated;
  }
}
