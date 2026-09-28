/**
 * Phase 3 — turning the inventory into the prompts phase 4 sends.
 *
 * This is the module that decides what the model sees, and it is built around
 * one rule: **Sentinel feeds the code to the model; the model never reads
 * files.** Every unit's source slice is extracted from disk here, by
 * `src/inventory/slice.ts`, and pasted into the prompt. The agent gets no
 * filesystem tools, so the prompt is the entire world it can reason about — and
 * `src/audit/verdict.ts` discards any citation that falls outside it. The agent
 * is given the code in its prompt rather than tools to fetch it, so a finding
 * cannot rest on something the model could not read: there is no read left to
 * fail silently, and nothing in context that this module did not choose.
 *
 * Four properties the rest of phase 4 depends on:
 *
 * - **Batches are homogeneous, by kind and by domain.** Routes with routes,
 *   migrations with migrations. One prompt per `(kind, domain)` pair means one
 *   set of checks, one rubric and one output shape, which is what makes a verdict
 *   comparable across a batch — and it is what lets one unit answer to more than
 *   one domain: a route is an access-control unit, an API contract and a
 *   reliability surface, so `./prompts/index.ts` may register three prompts for
 *   it and this module plans a series of batches for each. The units are read
 *   from disk once and shared by those series; the prompt characters are paid per
 *   series, which is why a second domain is only registered when it asks
 *   something the first does not.
 * - **The bound is a measured character budget, not a unit count.** A batch is
 *   packed by assembling the real prompt and measuring it. There is a count cap
 *   as well, but it is a guard against attention dilution across dozens of tiny
 *   units, not the thing that decides the size.
 * - **Batches are stable.** The same inventory produces the same partition and
 *   the same content-addressed batch ids, so a resumed run can reuse the
 *   verdicts it already paid for.
 * - **A unit that cannot be sliced is reported, never dropped.** It comes back
 *   in `skipped`, in the shape `Coverage.skipped` takes, because a unit missing
 *   from a coverage claim is a lie and a unit listed as skipped is a disclosure.
 *
 * ## Order and budget
 *
 * Two more properties, added once Sentinel was pointed at a repository it could
 * not afford to audit whole:
 *
 * - **Units are packed in risk order, not enumeration order.** `./risk.ts`
 *   scores every unit from the facts phase 2 proved, and a kind's units are
 *   packed highest-risk first, so the first batch of routes holds the
 *   unauthenticated mutating handlers rather than whichever handler sorted first
 *   by path. Each batch carries the mean score of its units and each unit
 *   carries the sentences that produced its own, so the dossier can say what put
 *   them at the front.
 * - **The plan is bounded, and says what it left out.** `./budget.ts` takes
 *   batches in risk order until a ceiling is reached; everything behind that
 *   line comes back in `skipped` with the cause `budget`, and `BatchPlan.bound`
 *   carries the numbers and the sentence. A plan that quietly contained a third
 *   of the repository would be a worse bug than the six hours it saves.
 */

import { join } from "node:path";
import { z } from "zod";
import { safeBatchId } from "../agents/raw-log.ts";
import type { AuditUnit, CodeRef, Domain } from "../contracts/findings.ts";
import {
  ATTRIBUTE,
  AUDIT_UNIT_KINDS,
  type AuditUnitKind,
  countUnits,
  groupThousands,
} from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import {
  type CodeSlice,
  type SliceBudget,
  type SliceContext,
  type SliceFailure,
  type SliceFileSystem,
  createSourceCache,
  sliceCode,
} from "../inventory/slice.ts";
import {
  authHelperFiles,
  authProviders,
  backendFrameworks,
  dataLayers,
  databaseEngines,
  evidenceFiles,
  hasFrontend,
  validatesConfig,
} from "../profile/accessors.ts";
import { contentSymbol } from "../scan/runners/_runner-support.ts";
import {
  type AuditBound,
  type AuditBudget,
  type ResolvedAuditBudget,
  buildAuditBound,
  resolveBudget,
  selectWithinBudget,
} from "./budget.ts";
import type { SkipCause } from "./coverage.ts";
import {
  type PromptBuilder,
  type PromptContext,
  type PromptGap,
  type PromptParts,
  type PromptPlanEntry,
  type PromptUnit,
  type RelatedSlice,
  type SharedSlice,
  type StackFacts,
  UNKNOWN_STACK,
  assemblePrompt,
  gapsFor,
  primaryDomainOf,
  promptsFor,
  unauditedReason,
} from "./prompts/index.ts";
import { RISK_ORDERING, type RiskScore, meanRisk, rankUnits, topReasons } from "./risk.ts";

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/** The bounds one batch is packed under. Every one of them is enforced. */
export interface BatchBudget {
  /**
   * Characters of the assembled prompt, system prompt included.
   *
   * Characters rather than tokens because characters are what can be measured
   * exactly, and the ratio is stable enough for a budget whose job is to keep a
   * prompt comfortably inside the context window rather than to fill it.
   */
  readonly promptChars: number;
  /**
   * Hard cap on units per batch, as a guard rather than as the bound: thirty
   * one-line sinks fit in the character budget several times over, and a model
   * asked for sixty verdicts starts omitting them.
   */
  readonly maxUnits: number;
  /** Share of the budget the shared context may take before it is trimmed. */
  readonly sharedShare: number;
  /** Overrides for the per-slice budget; anything omitted keeps `SLICE_BUDGET`. */
  readonly slice?: Partial<SliceBudget> | undefined;
}

/** The default budget: a prompt of roughly fifteen thousand tokens. */
export const BATCH_BUDGET: BatchBudget = {
  promptChars: 60_000,
  maxUnits: 30,
  sharedShare: 0.35,
};

/** Fills a partial budget with the defaults, clamping every knob to something usable. */
export function budgetOf(overrides: Partial<BatchBudget> | undefined): BatchBudget {
  const merged = { ...BATCH_BUDGET, ...overrides };
  return {
    promptChars: Math.max(2_000, Math.floor(merged.promptChars)),
    maxUnits: Math.max(1, Math.floor(merged.maxUnits)),
    sharedShare: Math.min(0.8, Math.max(0, merged.sharedShare)),
    ...(merged.slice === undefined ? {} : { slice: merged.slice }),
  };
}

// ---------------------------------------------------------------------------
// The batch
// ---------------------------------------------------------------------------

/** Code that belongs to a unit without being it, with the slice it was read from. */
export interface RelatedBatchSlice extends RelatedSlice {
  readonly slice: CodeSlice;
}

/** One unit in a batch: the unit, the source read from disk, and its related code. */
export interface BatchUnit {
  readonly unit: AuditUnit;
  readonly slice: CodeSlice;
  readonly related: readonly RelatedBatchSlice[];
  /**
   * Why this unit was prioritised, from `./risk.ts`.
   *
   * Carried per unit rather than per batch because that is the granularity a
   * reader argues at: "this handler was audited before those 4,000 queries
   * because it is reachable without authentication and takes an id off the
   * wire" is checkable, and a batch-level average is not.
   */
  readonly risk: RiskScore;
}

/** One block of shared context, and the slice behind it when it is source code. */
export interface SharedContextBlock extends SharedSlice {
  /** Present when the block is a source slice; absent for a rendered excerpt. */
  readonly slice?: CodeSlice | undefined;
  /** Lower priority is trimmed last when the shared context does not fit. */
  readonly priority: number;
  /**
   * Individual lines this block names as the declaration of something, which a
   * verdict about that thing is therefore allowed to cite.
   *
   * The schema excerpt is the reason this exists. It describes a table
   * completely — every column, index and foreign key — and ends with `declared
   * at: <file>:<line>`, but it is rendered text rather than a source slice, so
   * that line was not in the batch's citable set. A model that found an
   * unindexed foreign key from the excerpt then had to anchor its finding on
   * some *other* line of that migration that did happen to be in its slice, and
   * the report pointed the reader at an unrelated `CREATE TABLE`. Naming the
   * line here makes the honest citation the one that passes the gate.
   */
  readonly citable?: readonly { readonly file: string; readonly line: number }[] | undefined;
}

/** A line range that was pasted into a prompt; `CodeSlice` satisfies it structurally. */
export interface SliceExtent {
  /** Repo-relative POSIX path, as the slicer emits it. */
  readonly file: string;
  readonly startLine: number;
  readonly endLine: number;
}

/**
 * One dispatch's worth of work: homogeneous, measured, and ready to send.
 *
 * The field names are the audit phase's seam, so `planBatches` can be handed
 * straight to it: `units` is the list it must get a verdict for, `slices` is
 * every range the prompt contains, and `domain` is the domain the verdicts are
 * attributed to. `entries` is the same units with the slice each one was read
 * from, which is what the prompt and the citation gate use.
 */
export interface AuditBatch {
  /** Content-addressed and file-safe; stable for a given set of unit ids. */
  readonly id: string;
  readonly kind: AuditUnitKind;
  /** The domain whose checks this batch runs. */
  readonly domain: Domain;
  /**
   * 1-based position among the batches of this kind, in risk order.
   *
   * It counts the batches the kind was *split into*, not the ones that were
   * dispatched: `batch 3 of 229` on a budgeted run means 226 batches of that
   * kind were planned and never sent, which is a disclosure rather than a gap.
   */
  readonly index: number;
  /** How many batches this kind was split into, before any budget was applied. */
  readonly total: number;
  /** The mean risk of this batch's units; what the budget orders batches by. */
  readonly risk: number;
  /** Every unit the agent must return a verdict for. */
  readonly units: readonly AuditUnit[];
  /** The same units, each with the source slice pasted into the prompt. */
  readonly entries: readonly BatchUnit[];
  /** Every source range the prompt contains, units and shared context alike. */
  readonly slices: readonly SliceExtent[];
  readonly shared: readonly SharedContextBlock[];
  readonly systemPrompt: string;
  /** The assembled user prompt: this exact string is what the model is sent. */
  readonly prompt: string;
  /** Measured, not estimated: `systemPrompt.length + prompt.length`. */
  readonly chars: number;
  /** True when a single unit could not be made to fit; disclosed, never silent. */
  readonly overBudget: boolean;
}

/** A unit phase 4 will not return a verdict for, in the shape `Coverage.skipped` takes. */
export interface SkippedUnit {
  readonly unitId: string;
  readonly kind: AuditUnitKind;
  /**
   * The domain whose questions this unit will not be asked, when only one domain
   * is affected.
   *
   * A unit is audited once per domain that has a prompt for its kind, so a route
   * whose access-control batch was dispatched and whose contract batch the budget
   * deferred has a verdict in `appsec` and none in `api`. Phase 4 reads this to
   * file the skip in the right domain's coverage row; without it the `api` row
   * would count that unit out of its own total and read a clean fraction of a
   * fraction. Absent means the unit reached no batch in any domain, and the
   * fallback `DOMAIN_BY_UNIT_KIND` decides where it is counted.
   */
  readonly domain?: Domain | undefined;
  readonly reason: string;
  /**
   * How the coverage table classifies the loss.
   *
   * Phase 4 reads it so that a unit a *ceiling* held back is counted as
   * `budget` rather than collapsed into `no-batch` — "nobody planned a batch for
   * it" and "the run could not afford it" are different sentences, and only the
   * second one is resumable.
   */
  readonly cause?: SkipCause | undefined;
}

/** What phase 3 produced. */
export interface BatchPlan {
  /** The batches to dispatch, highest risk first. */
  readonly batches: readonly AuditBatch[];
  /** Units that will have no verdict, each with the reason it has none. */
  readonly skipped: readonly SkippedUnit[];
  /** Disclosures about the plan itself: trimmed context, missing shared files. */
  readonly notes: readonly string[];
  /**
   * Domains this run has units for and no prompt to ask them with.
   *
   * A `(kind, domain)` pair the registry declares without a builder — D6 and D7
   * while their prompt modules are being written. The units are audited by their
   * primary domain's batch, so they are not `skipped`; what is missing is a whole
   * domain's questions, and the only honest place to say so is here and in
   * {@link BatchPlan.notes}. Empty when every declared pair has a prompt.
   *
   * Optional for the same reason `runAudit`'s `PlannerDisclosure` fields are: a
   * caller that builds a plan by hand is still a valid planner, and `undefined`
   * says it does not describe its gaps rather than that it has none.
   */
  readonly gaps?: readonly PromptGap[] | undefined;
  /** The stack facts every prompt stated as ground truth. */
  readonly stack: StackFacts;
  /**
   * What the budget left out, as the plan forecasts it.
   *
   * `unitsAudited` here is the number of units the plan *put in a batch*, which
   * is the most phase 4 could possibly return a verdict for. Phase 4 rebuilds
   * the same shape from what actually came back and writes that one to
   * `audit.json`; this one is what the CLI can print before a single token is
   * spent.
   */
  readonly bound: AuditBound;
}

// ---------------------------------------------------------------------------
// The schema excerpt
// ---------------------------------------------------------------------------

/** A column of the reconstructed schema, as the excerpt renders it. */
export interface SchemaExcerptColumn {
  readonly name: string;
  readonly type: string;
  readonly nullable: boolean;
  readonly isPrimaryKey: boolean;
  readonly isUnique: boolean;
  readonly references?: { readonly table: string; readonly column: string } | undefined;
}

/** An index of the reconstructed schema, as the excerpt renders it. */
export interface SchemaExcerptIndex {
  readonly name: string;
  readonly columns: readonly string[];
  readonly unique: boolean;
}

/** A foreign key of the reconstructed schema, as the excerpt renders it. */
export interface SchemaExcerptForeignKey {
  readonly columns: readonly string[];
  readonly referencesTable: string;
  readonly referencesColumns: readonly string[];
  readonly onDelete?: string | undefined;
}

/** One table of the reconstructed schema, as the excerpt renders it. */
export interface SchemaExcerptTable {
  readonly name: string;
  readonly columns: readonly SchemaExcerptColumn[];
  readonly indexes: readonly SchemaExcerptIndex[];
  readonly foreignKeys: readonly SchemaExcerptForeignKey[];
  readonly uniqueConstraints: readonly { readonly columns: readonly string[] }[];
  readonly rlsEnabled: boolean;
  readonly policies: readonly { readonly name: string; readonly command: string }[];
  readonly evidence: readonly CodeRef[];
}

/**
 * The schema the excerpt is rendered from.
 *
 * Declared structurally rather than imported: `schema-model.json` is built by a
 * module private to phase 2, and the audit only needs to read a handful of its
 * fields. `SchemaModelDocument` satisfies this without either module depending
 * on the other.
 */
export interface SchemaSource {
  readonly dialect: string;
  readonly tables: readonly SchemaExcerptTable[];
}

/** Tables the excerpt will name for one batch, before it is capped. */
const MAX_EXCERPT_TABLES = 12;

/** The tables a unit says it touches, from the attributes the inventory proved. */
function tablesOf(unit: AuditUnit): string[] {
  const single = unit.attributes.table;
  const many = unit.attributes.tables;
  const names = [
    ...(single === undefined ? [] : [single]),
    ...(many === undefined ? [] : many.split(",")),
  ];
  return names.map((name) => name.trim()).filter((name) => name !== "" && name !== "unresolved");
}

/** Renders one table as the few lines the audit questions actually need. */
function renderTable(table: SchemaExcerptTable): string {
  const columns = table.columns.map((column) => {
    const flags = [
      column.isPrimaryKey ? "pk" : "",
      column.isUnique ? "unique" : "",
      column.nullable ? "null" : "not null",
      column.references === undefined
        ? ""
        : `-> ${column.references.table}.${column.references.column}`,
    ].filter((flag) => flag !== "");
    return `    ${column.name} ${column.type}${flags.length === 0 ? "" : ` [${flags.join(", ")}]`}`;
  });
  const indexes = table.indexes.map(
    (index) => `    ${index.name}(${index.columns.join(", ")})${index.unique ? " unique" : ""}`,
  );
  const keys = table.foreignKeys.map(
    (key) =>
      `    ${key.columns.join(", ")} -> ${key.referencesTable}(${key.referencesColumns.join(", ")})${
        key.onDelete === undefined ? "" : ` on delete ${key.onDelete}`
      }`,
  );
  const uniques = table.uniqueConstraints.map((unique) => `    (${unique.columns.join(", ")})`);
  const policies = table.policies.map((policy) => `    ${policy.name} for ${policy.command}`);
  const rls = table.rlsEnabled
    ? `row level security: ENABLED with ${table.policies.length} polic${
        table.policies.length === 1 ? "y" : "ies"
      }`
    : "row level security: not enabled";

  const lines = [`  table ${table.name} — ${rls}`];
  if (columns.length > 0) lines.push("  columns:", ...columns);
  if (indexes.length > 0) lines.push("  indexes:", ...indexes);
  else lines.push("  indexes: none");
  if (keys.length > 0) lines.push("  foreign keys:", ...keys);
  if (uniques.length > 0) lines.push("  unique constraints:", ...uniques);
  if (policies.length > 0) lines.push("  policies:", ...policies);
  const evidence = table.evidence[0];
  if (evidence !== undefined) lines.push(`  declared at: ${evidence.file}:${evidence.line}`);
  return lines.join("\n");
}

/**
 * The part of the reconstructed schema the units in front of the model touch.
 *
 * Only the tables they name: a sixty-table excerpt in every batch would spend
 * the budget on tables nobody asked about, and "the schema was not provided for
 * this table" is a legitimate `not-applicable` that the prompt asks for
 * explicitly.
 */
export function renderSchemaExcerpt(
  schema: SchemaSource,
  units: readonly AuditUnit[],
): SharedContextBlock | undefined {
  const wanted = new Set<string>();
  for (const unit of units) {
    for (const name of tablesOf(unit)) wanted.add(name.toLowerCase());
  }
  if (wanted.size === 0) return undefined;
  const matched = schema.tables
    .filter((table) => wanted.has(table.name.toLowerCase()))
    .sort((left, right) => left.name.localeCompare(right.name))
    .slice(0, MAX_EXCERPT_TABLES);
  if (matched.length === 0) return undefined;

  const missing = [...wanted]
    .filter((name) => !matched.some((table) => table.name.toLowerCase() === name))
    .sort();
  const lines = [
    `Reconstructed from the migration history and the ORM schema (${schema.dialect}).`,
    "It describes the database as the history leaves it, not as any one migration wrote it.",
    ...matched.map(renderTable),
  ];
  if (missing.length > 0) {
    lines.push(`  not in the model: ${missing.join(", ")} — treat them as unknown, not as absent`);
  }
  // The `declared at` line of every table the excerpt describes: a verdict about
  // that table may cite it, which is what keeps a claim derived from the excerpt
  // from having to anchor itself on whatever unrelated line happened to survive
  // the unit's slice budget.
  const citable = matched
    .map((table) => table.evidence[0])
    .filter((ref): ref is { file: string; line: number } => ref !== undefined)
    .map((ref) => ({ file: ref.file, line: ref.line }));
  return {
    label: "schema excerpt",
    text: lines.join("\n"),
    priority: 1,
    ...(citable.length === 0 ? {} : { citable }),
  };
}

// ---------------------------------------------------------------------------
// Shared context
// ---------------------------------------------------------------------------

/** A file the shared context quotes, and what it is there for. */
export interface SharedFileRequest {
  readonly label: string;
  readonly file: string;
  /** Lower priority survives trimming; the schema excerpt is priority 1. */
  readonly priority: number;
}

/** Which shared blocks each kind is given, in priority order. */
const SHARED_BY_KIND: Readonly<Record<string, readonly ("auth" | "validation" | "schema")[]>> = {
  route: ["auth", "validation"],
  "data-access": ["schema"],
  migration: ["schema"],
  "serverless-function": ["auth", "validation"],
  "queue-consumer": ["schema", "validation"],
  cron: ["auth"],
  webhook: ["auth", "validation"],
  "role-gate": ["auth"],
  sink: ["validation"],
};

/** How many auth-helper files are quoted; two is already generous for a prompt. */
const MAX_AUTH_HELPERS = 2;

/**
 * The files the shared context quotes for one kind, derived from phase 0.
 *
 * The auth helper is the file the audit compares a handler against: a helper
 * that resolves a session without asserting a role cannot be the authorization
 * check for a privileged route, and the model can only know that by reading it.
 * The validation helper is the project's own — an env schema, a shared parser —
 * so "validated" means what this codebase means by it.
 */
export function sharedFilesFor(
  kind: AuditUnitKind,
  profile: StackProfile | undefined,
): SharedFileRequest[] {
  if (profile === undefined) return [];
  const wanted = new Set(SHARED_BY_KIND[kind] ?? []);
  const requests: SharedFileRequest[] = [];
  if (wanted.has("auth")) {
    for (const file of authHelperFiles(profile).slice(0, MAX_AUTH_HELPERS)) {
      requests.push({ label: `auth helper (${file})`, file, priority: 0 });
    }
  }
  if (wanted.has("validation")) {
    const file = evidenceFiles(profile, "config-validation")[0];
    if (file !== undefined) {
      requests.push({ label: `the project's own validation helper (${file})`, file, priority: 2 });
    }
  }
  if (wanted.has("schema")) {
    const file = evidenceFiles(profile, "db-schema-file")[0];
    if (file !== undefined) {
      requests.push({ label: `ORM schema (${file})`, file, priority: 3 });
    }
  }
  return requests;
}

/** Line count a whole-file shared slice asks for; the slice budget cuts it down. */
const WHOLE_FILE_LINES = 100_000;

/** Reads a shared file as one budgeted slice: its head and its tail, cuts marked. */
async function sliceSharedFile(
  request: SharedFileRequest,
  ctx: SliceContext,
): Promise<SharedContextBlock | { readonly failure: SliceFailure }> {
  const result = await sliceCode({ file: request.file, line: 1, endLine: WHOLE_FILE_LINES }, ctx);
  if (!result.ok) return { failure: result };
  return {
    label: request.label,
    text: result.slice.text,
    slice: result.slice,
    priority: request.priority,
  };
}

// ---------------------------------------------------------------------------
// Stack facts
// ---------------------------------------------------------------------------

/** The stack facts the prompts state as ground truth, read off phase 0's output. */
export function stackFactsOf(profile: StackProfile | undefined): StackFacts {
  if (profile === undefined) return UNKNOWN_STACK;
  const notes: string[] = [];
  if (profile.scan.truncated) {
    notes.push("phase 0 stopped reading before every candidate file: the facts may be incomplete");
  }
  return {
    frameworks: backendFrameworks(profile),
    dataLayers: dataLayers(profile),
    databases: databaseEngines(profile),
    authProviders: authProviders(profile),
    authHelpers: authHelperFiles(profile),
    hasFrontend: hasFrontend(profile),
    validatesConfig: validatesConfig(profile),
    notes,
  };
}

// ---------------------------------------------------------------------------
// Related units
// ---------------------------------------------------------------------------

/** How many related slices one unit may carry. */
const MAX_RELATED = 2;

/** Kinds whose verdict depends on code that belongs to another unit. */
const RELATED_LABEL: Readonly<Partial<Record<AuditUnitKind, string>>> = {
  "role-gate": "the handler behind the gated action",
  cron: "the handler this schedule invokes",
};

/**
 * The units whose source one unit needs in order to be judged.
 *
 * This is the whole point of the `link` step: "authorization decided in the
 * browser" is a sentence until the handler behind the hidden button is in the
 * same prompt, and "cron endpoint reachable without a secret" is a guess until
 * the route the schedule calls is. Joined on the shared attribute vocabulary —
 * `targetUnitId` first, because the inventory's own cross-reference already
 * resolved it, then `path`.
 */
export function relatedUnitsOf(
  unit: AuditUnit,
  byId: ReadonlyMap<string, AuditUnit>,
  byPath: ReadonlyMap<string, readonly AuditUnit[]>,
): AuditUnit[] {
  if (RELATED_LABEL[unit.kind] === undefined) return [];
  const targetId = unit.attributes[ATTRIBUTE.targetUnitId];
  const target = targetId === undefined ? undefined : byId.get(targetId);
  if (target !== undefined) return [target];
  const path = unit.attributes[ATTRIBUTE.path] ?? unit.attributes.endpoint;
  if (path === undefined || path === "unresolved") return [];
  return [...(byPath.get(normalisePath(path)) ?? [])].slice(0, MAX_RELATED);
}

/** Trims a path to what two enumerators can be expected to agree on. */
function normalisePath(path: string): string {
  const withoutQuery = path.split("?")[0] ?? path;
  const trimmed = withoutQuery.replace(/\/+$/, "");
  return trimmed === "" ? "/" : trimmed;
}

/** Route units indexed by their resolved path, for the role-gate and cron joins. */
function indexByPath(units: readonly AuditUnit[]): Map<string, AuditUnit[]> {
  const index = new Map<string, AuditUnit[]>();
  for (const unit of units) {
    if (unit.kind !== "route") continue;
    const path = unit.attributes[ATTRIBUTE.path];
    if (path === undefined || path === "unresolved") continue;
    const key = normalisePath(path);
    const bucket = index.get(key);
    if (bucket === undefined) index.set(key, [unit]);
    else bucket.push(unit);
  }
  return index;
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/** Everything {@link planBatches} needs. */
export interface PlanBatchesInput {
  /** The inventory's units. Sorted again here, so the caller's order cannot matter. */
  readonly units: readonly AuditUnit[];
  /** How slices are read: the filesystem seam and the target directory. */
  readonly slices: SliceContext;
  /** Phase 0 output; without it the prompts say the stack is unknown. */
  readonly profile?: StackProfile | undefined;
  /** The reconstructed schema, when phase 2 built one. */
  readonly schema?: SchemaSource | undefined;
  /** Restrict the plan to these kinds; defaults to every kind with a prompt. */
  readonly kinds?: readonly AuditUnitKind[] | undefined;
  /**
   * The domains phase 0.5 turned on; defaults to every domain the registry has a
   * prompt for.
   *
   * Phase 4 filters batches by the enabled domains again, so this is not what
   * makes an out-of-scope domain safe — it is what stops the plan from slicing,
   * assembling and *budgeting* a series of batches that will then be thrown away.
   * Turning D6 and D7 off drops something like two batches in five on a
   * repository with routes, and a batch ceiling spent on them is coverage the
   * enabled domains do not get.
   */
  readonly domains?: readonly Domain[] | undefined;
  /** Per-batch packing budget: how big one prompt may get. */
  readonly budget?: Partial<BatchBudget> | undefined;
  /**
   * Run-level ceilings: how much of the inventory this plan may spend on a
   * model at all. Omitted takes {@link DEFAULT_AUDIT_BUDGET}; pass
   * {@link UNBOUNDED_BUDGET} to plan the whole repository.
   */
  readonly spend?: AuditBudget | undefined;
  /**
   * Unit ids an earlier attempt in this run directory already has a verdict for.
   *
   * They are removed before anything is scored, so a resumed run spends its
   * budget on the *next* highest-risk units instead of re-auditing what it has
   * already paid for — and they are not reported as deferred, because they were
   * not deferred. This is the whole of what resumability needs from phase 3.
   */
  readonly exclude?: readonly string[] | undefined;
  /** Overrides the files the shared context quotes, per kind. */
  readonly sharedFiles?: ((kind: AuditUnitKind) => readonly SharedFileRequest[]) | undefined;
  /**
   * Overrides the prompts a kind is audited with; the default is the registry.
   *
   * The seam a caller uses to plan one domain at a time, and the one the tests
   * use to exercise a kind with two prompts against a real registry entry while
   * the D6 and D7 modules are still being written. Turning a domain *off* for a
   * run is not done here — phase 4 filters batches by the enabled domains — so
   * this override cannot make a plan disagree with the scope decision.
   */
  readonly prompts?: ((kind: AuditUnitKind) => readonly PromptPlanEntry[]) | undefined;
}

/**
 * A unit that reached no batch at all, reported once per domain that would have
 * asked about it.
 *
 * One entry per domain, because coverage is per domain: a route whose source no
 * longer resolves is missing from the access-control table, from the contract
 * table and from the reliability table alike, and a single entry would have left
 * two of the three counting the unit out of their own totals — reporting a clean
 * fraction of the repository as the whole of it. A kind no prompt covers gets one
 * entry with no domain, and `DOMAIN_BY_UNIT_KIND` places it.
 */
function unbatchedIn(
  unit: AuditUnit,
  prompts: readonly PromptPlanEntry[],
  reason: string,
): SkippedUnit[] {
  const base = { unitId: unit.id, kind: unit.kind, cause: "no-batch" as const, reason };
  if (prompts.length === 0) return [base];
  return prompts.map((prompt) => ({ ...base, domain: prompt.domain }));
}

/**
 * Content-addressed, file-safe, and stable for a given set of unit ids.
 *
 * The domain joins the id once a kind has more than one prompt, because the same
 * units are then in two batches and one shared id would make one transcript in
 * `raw/agents/` overwrite the other. A kind's **primary** domain is left out, so
 * every id that exists today keeps the bytes it has: a resumed run over unchanged
 * code still recognises the batches it already paid a model for, and only a new
 * series carries a new name.
 */
export function batchId(kind: AuditUnitKind, unitIds: readonly string[], domain?: Domain): string {
  const prefix =
    domain === undefined || domain === primaryDomainOf(kind) ? kind : `${kind}-${domain}`;
  return safeBatchId(contentSymbol(prefix, unitIds.join("")));
}

/** Assembles the parts and returns the prompt with its measured size. */
function measure(parts: PromptParts): { prompt: string; chars: number } {
  const prompt = assemblePrompt(parts);
  return { prompt, chars: parts.systemPrompt.length + prompt.length };
}

/** The prompt parts for a candidate batch, with the shared context it carries. */
function partsFor(
  builder: PromptBuilder,
  stack: StackFacts,
  shared: readonly SharedContextBlock[],
  entries: readonly PromptUnit[],
  id: string,
): PromptParts {
  const ctx: PromptContext = { stack, shared, batchId: id };
  return {
    systemPrompt: builder.systemPrompt(),
    header: builder.header(ctx, entries),
    sections: entries.map((entry) => builder.section(entry)),
    footer: builder.footer(entries),
  };
}

/** A unit sliced from disk, ready to be packed. */
interface SlicedUnit {
  readonly unit: AuditUnit;
  readonly slice: CodeSlice;
  readonly related: readonly RelatedBatchSlice[];
  readonly entry: PromptUnit;
  readonly risk: RiskScore;
}

/**
 * `handlerSource` as the route enumerator writes it: `file:start-end`.
 *
 * The extent, not just the first line, because the slicer would otherwise have
 * to re-derive the block — and an `export default async (req, res) => {` sits at
 * brace depth zero, where "the enclosing block" is the whole module.
 */
const HANDLER_SOURCE = /^(.+):(\d+)-(\d+)$/;

/**
 * The handler a unit delegates to, when it is not already in the unit's slice.
 *
 * A router line like `api.delete("/:type/:id", removeByTypeAndId)` *is* the
 * unit, and it contains no code to audit: the validation, the principal and the
 * query are all in the file the handler was imported from. Without this the
 * model is shown one line and correctly answers `not-applicable` to every check,
 * which is a coverage hole dressed as an audit.
 */
function handlerRefOf(unit: AuditUnit, own: CodeSlice): CodeRef | undefined {
  const match = HANDLER_SOURCE.exec(unit.attributes.handlerSource ?? "");
  const file = match?.[1];
  const start = Number(match?.[2]);
  const end = Number(match?.[3]);
  if (file === undefined || !Number.isFinite(start) || !Number.isFinite(end)) return undefined;
  // Already on the page: a handler declared in the router's own file is inside
  // the slice the unit's location resolved to.
  if (file === own.file && start >= own.startLine && end <= own.endLine) return undefined;
  return { file, line: start, endLine: end };
}

/** Reads one unit and everything attached to it out of the repository. */
async function sliceUnit(
  unit: AuditUnit,
  related: readonly AuditUnit[],
  ctx: SliceContext,
  risk: RiskScore,
): Promise<SlicedUnit | { readonly failure: SliceFailure }> {
  const own = await sliceCode(unit.location, ctx);
  if (!own.ok) return { failure: own };
  const attached: RelatedBatchSlice[] = [];
  const handlerRef = handlerRefOf(unit, own.slice);
  if (handlerRef !== undefined) {
    const handler = await sliceCode(handlerRef, ctx);
    if (handler.ok) {
      attached.push({
        label: `the handler this ${unit.kind} registers: ${unit.attributes.handlerSymbol ?? handlerRef.file}`,
        text: handler.slice.text,
        slice: handler.slice,
      });
    }
  }
  for (const other of related) {
    const result = await sliceCode(other.location, ctx);
    if (!result.ok) continue;
    attached.push({
      label: `${RELATED_LABEL[unit.kind] ?? "related code"}: ${other.label}`,
      unitId: other.id,
      text: result.slice.text,
      slice: result.slice,
    });
  }
  return {
    unit,
    slice: own.slice,
    related: attached,
    entry: { unit, sliceText: own.slice.text, related: attached },
    risk,
  };
}

/**
 * Groups the units into the prompts phase 4 will send.
 *
 * Deterministic from end to end: the units are scored and re-sorted by risk, the
 * shared context is derived from sorted facts, the packing is a single greedy
 * pass over that order, every id is a hash of its contents, and the budget takes
 * whole batches off the front of a total order. Two runs over an unchanged
 * inventory produce the same batches with the same ids and the same budget line,
 * which is what lets a resumed run reuse the verdicts it already paid a model
 * for and continue with the next-highest-risk units rather than reshuffling.
 */
export async function planBatches(input: PlanBatchesInput): Promise<BatchPlan> {
  const budget = budgetOf(input.budget);
  const spend = resolveBudget(input.spend);
  const stack = stackFactsOf(input.profile);
  const sliceCtx: SliceContext = {
    ...input.slices,
    cache: input.slices.cache ?? createSourceCache(),
    ...(budget.slice === undefined ? {} : { budget: budget.slice }),
  };

  // The joins index the *whole* inventory: a cron whose target route a previous
  // attempt already audited still needs that route's source in its prompt.
  const byId = new Map(input.units.map((unit) => [unit.id, unit]));
  const byPath = indexByPath(input.units);

  const excluded = new Set(input.exclude ?? []);
  const carriedOver = input.units.filter((unit) => excluded.has(unit.id)).length;
  const ranked = rankUnits(input.units.filter((unit) => !excluded.has(unit.id)));
  const wantedKinds = new Set(input.kinds ?? AUDIT_UNIT_KINDS);

  const batches: AuditBatch[] = [];
  const skipped: SkippedUnit[] = [];
  const notes: string[] = [];
  const gaps: PromptGap[] = [];

  for (const kind of AUDIT_UNIT_KINDS) {
    // Already in risk order: `rankUnits` sorted the whole set and filtering
    // preserves it, so a kind's first batch holds its most dangerous units.
    const ofKind = ranked.filter((entry) => entry.unit.kind === kind);
    if (ofKind.length === 0) continue;
    const prompts = (input.prompts ?? promptsFor)(kind).filter(
      (entry) => input.domains === undefined || input.domains.includes(entry.domain),
    );
    if (!wantedKinds.has(kind)) {
      for (const entry of ofKind) {
        skipped.push(...unbatchedIn(entry.unit, prompts, "this kind was excluded from the run"));
      }
      continue;
    }
    if (prompts.length === 0) {
      // Two different silences: no prompt was ever written for this kind, or the
      // prompts exist and this run's scope turned their domains off. The second
      // is not a gap in Sentinel, and a reader deciding whether to re-run needs
      // to be told which one they are looking at.
      const registered = (input.prompts ?? promptsFor)(kind);
      const reason =
        registered.length === 0
          ? unauditedReason(kind)
          : `every domain that audits this kind is outside this run's scope: ${registered
              .map((entry) => entry.domain)
              .join(", ")}`;
      for (const entry of ofKind) {
        skipped.push(...unbatchedIn(entry.unit, prompts, reason));
      }
      continue;
    }
    // A domain this run has units for and no prompt to ask them with. The units
    // are audited by their primary domain's batch, so they are not skipped —
    // what is absent is a whole domain's questions, and this is where the plan
    // says so out loud instead of letting the domain read `0 of 0`.
    for (const gap of gapsFor(kind)) {
      gaps.push(gap);
      notes.push(
        `${kind}/${gap.domain}: ${countUnits(kind, ofKind.length)} were not audited for the ${gap.domain} domain — ${gap.reason}`,
      );
    }

    // Read every unit first: a batch is packed out of slices, and a unit whose
    // citation no longer resolves must not silently shrink the coverage claim.
    const sliced: SlicedUnit[] = [];
    for (const entry of ofKind) {
      const result = await sliceUnit(
        entry.unit,
        relatedUnitsOf(entry.unit, byId, byPath),
        sliceCtx,
        entry.risk,
      );
      if ("failure" in result) {
        skipped.push(
          ...unbatchedIn(
            entry.unit,
            prompts,
            `source could not be read: ${result.failure.reason}: ${result.failure.detail}`,
          ),
        );
        continue;
      }
      sliced.push(result);
    }
    if (sliced.length === 0) continue;

    const sharedFiles = (input.sharedFiles ?? ((k) => sharedFilesFor(k, input.profile)))(kind);
    const sharedBlocks: SharedContextBlock[] = [];
    for (const request of sharedFiles) {
      const block = await sliceSharedFile(request, sliceCtx);
      if ("failure" in block) {
        notes.push(
          `${kind}: ${request.label} was not quoted (${block.failure.reason}: ${block.failure.detail})`,
        );
        continue;
      }
      sharedBlocks.push(block);
    }
    const headers = await workflowHeaderBlocks(kind, sliced, sliceCtx);

    // One series of batches per registered prompt. The slices above are read
    // once and shared by every series: a second domain pays for the prompt
    // characters again, never for the disk.
    for (const prompt of prompts) {
      const { builder, domain } = prompt;
      const packed = packKind(builder, stack, sliced, budget);
      const total = packed.length;
      packed.forEach((group, index) => {
        const ids = group.map((item) => item.unit.id);
        const id = batchId(kind, ids, domain);
        const shared = sharedContextFor(
          sharedBlocks,
          input.schema,
          group.map((item) => item.unit),
          headers,
        );
        const built = fitPrompt(builder, stack, shared, group, budget, id);
        const label = `${kind}/${domain} batch ${index + 1}/${total}`;
        if (built.trimmed > 0) {
          notes.push(
            `${label}: ${built.trimmed} shared context block(s) were dropped to stay inside the ${budget.promptChars}-character budget`,
          );
        }
        if (built.overBudget) {
          notes.push(
            `${label}: the prompt is ${built.chars} characters, above the ${budget.promptChars}-character budget, because one unit could not be made smaller`,
          );
        }
        const entries: BatchUnit[] = group.map((item) => ({
          unit: item.unit,
          slice: item.slice,
          related: item.related,
          risk: item.risk,
        }));
        batches.push({
          id,
          kind,
          domain,
          index: index + 1,
          total,
          risk: meanRisk(entries.map((entry) => entry.risk)),
          units: entries.map((entry) => entry.unit),
          entries,
          slices: extentsOf(entries, built.shared),
          shared: built.shared,
          systemPrompt: builder.systemPrompt(),
          prompt: built.prompt,
          chars: built.chars,
          overBudget: built.overBudget,
        });
      });
    }
  }

  return finishPlan({ batches, skipped, notes, stack, spend, carriedOver, gaps });
}

/**
 * Applies the run-level ceilings and states what they cost.
 *
 * Split out of {@link planBatches} because it is the one step that decides what
 * a reader is *not* told about, and it should be readable without the six
 * hundred lines of slicing above it. Everything the budget holds back becomes a
 * `skipped` entry with the cause `budget` — so it reaches the CLI summary and
 * the coverage table through the paths that already exist — and `bound` carries
 * the numbers and the sentence for the places that want one line.
 */
function finishPlan(input: {
  readonly batches: readonly AuditBatch[];
  readonly skipped: readonly SkippedUnit[];
  readonly notes: readonly string[];
  readonly stack: StackFacts;
  readonly spend: ResolvedAuditBudget;
  readonly carriedOver: number;
  readonly gaps: readonly PromptGap[];
}): BatchPlan {
  const selection = selectWithinBudget(input.batches, input.spend);
  const skipped = [...input.skipped];
  const notes = [...input.notes];

  // Distinct units, not dispatch slots. A route in three batches — access
  // control, contract, reliability — is one unit of this repository, so the
  // denominator a reader checks is the count `inventory.json` lists. Summing the
  // batches' `units` arrays instead counts that route three times and inflates
  // the total a run claims existed. The per-domain shortfall is not lost by this:
  // it is in the coverage table, in the notes below, and on each skipped entry's
  // domain.
  const dispatchedUnits = new Set<string>();
  for (const batch of selection.dispatched) {
    for (const unit of batch.units) dispatchedUnits.add(unit.id);
  }
  const deferredOnly = new Set<string>();
  for (const batch of selection.deferred) {
    for (const unit of batch.units) {
      if (!dispatchedUnits.has(unit.id)) deferredOnly.add(unit.id);
    }
  }
  const unbatched = new Set<string>();
  for (const skip of skipped) {
    if (!dispatchedUnits.has(skip.unitId) && !deferredOnly.has(skip.unitId)) {
      unbatched.add(skip.unitId);
    }
  }
  const plannedUnits = dispatchedUnits.size;
  const deferredUnits = deferredOnly.size;
  const unitsTotal = plannedUnits + deferredUnits + unbatched.size + input.carriedOver;

  const bound = buildAuditBound({
    stop: selection.stop,
    limits: input.spend,
    unitsTotal,
    unitsDispatched: plannedUnits,
    // The plan's forecast: every unit it batched is a unit a model *could*
    // return a verdict for. Phase 4 replaces this with what actually came back.
    unitsAudited: plannedUnits + input.carriedOver,
    unitsDeferred: deferredUnits,
    unitsCarriedOver: input.carriedOver,
    batchesPlanned: input.batches.length,
    batchesDispatched: selection.dispatched.length,
    batchesDeferred: selection.deferred.length,
    ordering: RISK_ORDERING,
    reasons: topReasons(
      selection.dispatched.flatMap((batch) => batch.entries.map((entry) => entry.risk)),
    ),
  });

  if (selection.deferred.length > 0) {
    // One reason string for every deferred unit, so the CLI's existing
    // "N units were not batched" grouping prints the budget line with its count
    // without the CLI having to learn anything new. A deferral in a kind's
    // secondary domain names that domain in the reason as well as in the field,
    // so the grouped count cannot be read as a count of units left unaudited
    // altogether: those units were audited, for their primary domain.
    for (const batch of selection.deferred) {
      const secondary = batch.domain !== primaryDomainOf(batch.kind);
      const reason = secondary
        ? `${bound.statement} — deferred for the ${batch.domain} domain`
        : bound.statement;
      for (const unit of batch.units) {
        skipped.push({
          unitId: unit.id,
          kind: unit.kind,
          domain: batch.domain,
          cause: "budget",
          reason,
        });
      }
    }
    notes.push(bound.statement);
    for (const line of describeDeferredDomains(selection.dispatched, selection.deferred)) {
      notes.push(line);
    }
  }

  return {
    batches: selection.dispatched,
    skipped,
    notes,
    gaps: input.gaps,
    stack: input.stack,
    bound,
  };
}

/**
 * One line per `(kind, domain)` the budget cut short, naming what it cost.
 *
 * The run-level sentence counts distinct units, so a route audited for access
 * control and deferred for its contract does not appear in it — correctly, since
 * a model did look at that route. What it does not say is that a *domain* was
 * only asked about part of the repository, and that is the number a reader of the
 * D6 or D7 section needs. It is the same shortfall the coverage table carries,
 * said once in prose so nobody has to diff two tables to find it.
 */
function describeDeferredDomains(
  dispatched: readonly AuditBatch[],
  deferred: readonly AuditBatch[],
): string[] {
  const key = (batch: AuditBatch): string => `${batch.kind}\u0000${batch.domain}`;
  const sent = new Map<string, Set<string>>();
  for (const batch of dispatched) {
    const bucket = sent.get(key(batch)) ?? new Set<string>();
    for (const unit of batch.units) bucket.add(unit.id);
    sent.set(key(batch), bucket);
  }
  const held = new Map<string, { batch: AuditBatch; units: Set<string> }>();
  for (const batch of deferred) {
    const entry = held.get(key(batch)) ?? { batch, units: new Set<string>() };
    for (const unit of batch.units) {
      if (sent.get(key(batch))?.has(unit.id) === true) continue;
      entry.units.add(unit.id);
    }
    held.set(key(batch), entry);
  }
  const lines: string[] = [];
  for (const [pairKey, entry] of held) {
    if (entry.units.size === 0) continue;
    const total = entry.units.size + (sent.get(pairKey)?.size ?? 0);
    lines.push(
      `${entry.batch.kind}/${entry.batch.domain}: ${groupThousands(entry.units.size)} of ${countUnits(entry.batch.kind, total)} were not dispatched for the ${entry.batch.domain} domain, so that domain's coverage counts them as not audited`,
    );
  }
  return lines.sort();
}

/** Every range a prompt pasted, deduplicated, in the order the prompt shows them. */
function extentsOf(
  entries: readonly BatchUnit[],
  shared: readonly SharedContextBlock[],
): SliceExtent[] {
  const extents: SliceExtent[] = [];
  const seen = new Set<string>();
  const add = (slice: CodeSlice): void => {
    const key = `${slice.file}:${slice.startLine}-${slice.endLine}`;
    if (seen.has(key)) return;
    seen.add(key);
    extents.push({ file: slice.file, startLine: slice.startLine, endLine: slice.endLine });
  };
  for (const block of shared) {
    if (block.slice !== undefined) add(block.slice);
    for (const ref of block.citable ?? []) {
      const key = `${ref.file}:${ref.line}-${ref.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      extents.push({ file: ref.file, startLine: ref.line, endLine: ref.line });
    }
  }
  for (const entry of entries) {
    add(entry.slice);
    for (const related of entry.related) add(related.slice);
  }
  return extents;
}

/**
 * The shared context for one batch: the per-kind files, the blocks that belong to
 * the files this batch's units came from, and the tables it touches.
 *
 * `perFile` is keyed by the unit file it belongs to, so a batch carries the
 * workflow headers of its own jobs and not of the four other workflows in the
 * repository.
 */
function sharedContextFor(
  files: readonly SharedContextBlock[],
  schema: SchemaSource | undefined,
  units: readonly AuditUnit[],
  perFile: ReadonlyMap<string, SharedContextBlock> = new Map(),
): SharedContextBlock[] {
  const excerpt = schema === undefined ? undefined : renderSchemaExcerpt(schema, units);
  const own = new Set(units.map((unit) => unit.location.file));
  const attached = [...perFile.entries()]
    .filter(([file]) => own.has(file))
    .map(([, block]) => block);
  const blocks = [...files, ...attached, ...(excerpt === undefined ? [] : [excerpt])];
  return blocks.sort(
    (left, right) => left.priority - right.priority || left.label.localeCompare(right.label),
  );
}

/** Lines of a workflow file the header block may quote before the slice budget cuts it. */
const MAX_WORKFLOW_HEADER_LINES = 80;

/**
 * The header of every workflow the batch's jobs come from: `on:` with its
 * filters, the workflow-level `env:` and `permissions:`, and `concurrency`.
 *
 * A job's slice is the job. Everything that decides what the job is *worth to an
 * attacker* is above it: which events reach it and under which filters, the
 * account id and IAM role the workflow's `env` holds, the permissions it inherits
 * when it declares none. The unit's `triggers` fact names the events with the
 * filters stripped, which is enough to sort by risk and not enough to judge —
 * `workflow_run` gated on `branches: [develop]` and an unfiltered one read the
 * same. So the lines before the first job are quoted once per workflow, as a real
 * slice, which also makes them citable: a finding about a trigger can point at
 * the `on:` line the way the deterministic rule does.
 */
async function workflowHeaderBlocks(
  kind: AuditUnitKind,
  sliced: readonly SlicedUnit[],
  ctx: SliceContext,
): Promise<Map<string, SharedContextBlock>> {
  const blocks = new Map<string, SharedContextBlock>();
  if (kind !== "workflow-job") return blocks;
  const firstJob = new Map<string, number>();
  for (const item of sliced) {
    const { file, line } = item.unit.location;
    const current = firstJob.get(file);
    if (current === undefined || line < current) firstJob.set(file, line);
  }
  for (const [file, line] of [...firstJob.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const endLine = Math.min(line - 1, MAX_WORKFLOW_HEADER_LINES);
    // A workflow whose first job starts in the first two lines has no header to
    // quote; nothing is lost, and an unresolvable slice is never invented.
    if (endLine < 2) continue;
    const result = await sliceCode({ file, line: 1, endLine }, ctx);
    if (!result.ok) continue;
    blocks.set(file, {
      label: `workflow header (${file}): its triggers, workflow-level env and permissions`,
      text: result.slice.text,
      slice: result.slice,
      priority: 0,
    });
  }
  return blocks;
}

/**
 * Packs the units of one kind into batches under the character budget.
 *
 * A greedy single pass in the sorted order, measuring the real assembled prompt
 * at every step, with the shared context's share of the budget held back: the
 * blocks are batch-specific, so they are attached once the units are known and
 * trimmed by {@link fitPrompt} if they still do not fit. A unit whose own
 * section cannot fit anywhere gets a batch to itself rather than being dropped.
 */
function packKind(
  builder: PromptBuilder,
  stack: StackFacts,
  sliced: readonly SlicedUnit[],
  budget: BatchBudget,
): SlicedUnit[][] {
  const unitBudget = Math.max(1_000, Math.floor(budget.promptChars * (1 - budget.sharedShare)));
  const batches: SlicedUnit[][] = [];
  let current: SlicedUnit[] = [];

  for (const item of sliced) {
    const candidate = [...current, item];
    const ids = candidate.map((one) => one.unit.id);
    const { chars } = measure(
      partsFor(
        builder,
        stack,
        [],
        candidate.map((one) => one.entry),
        batchId(builder.kind, ids),
      ),
    );
    const fits = chars <= unitBudget && candidate.length <= budget.maxUnits;
    if (fits) {
      current = candidate;
      continue;
    }
    if (current.length === 0) {
      // One unit alone is over the budget: it still has to be audited.
      batches.push(candidate);
      continue;
    }
    batches.push(current);
    current = [item];
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/** A prompt assembled under the budget, with whatever had to be dropped counted. */
interface FittedPrompt {
  readonly prompt: string;
  readonly chars: number;
  readonly shared: readonly SharedContextBlock[];
  readonly trimmed: number;
  readonly overBudget: boolean;
}

/**
 * Assembles the final prompt, dropping shared context — highest priority number
 * first — until it fits.
 *
 * The units are never dropped here: coverage is decided by enumeration, and a
 * prompt that is over budget with no shared context left says so instead of
 * quietly auditing fewer units.
 */
function fitPrompt(
  builder: PromptBuilder,
  stack: StackFacts,
  shared: readonly SharedContextBlock[],
  group: readonly SlicedUnit[],
  budget: BatchBudget,
  id: string,
): FittedPrompt {
  const entries = group.map((item) => item.entry);
  let kept = [...shared];
  let measured = measure(partsFor(builder, stack, kept, entries, id));
  let trimmed = 0;
  while (measured.chars > budget.promptChars && kept.length > 0) {
    kept = kept.slice(0, -1);
    trimmed += 1;
    measured = measure(partsFor(builder, stack, kept, entries, id));
  }
  return {
    prompt: measured.prompt,
    chars: measured.chars,
    shared: kept,
    trimmed,
    overBudget: measured.chars > budget.promptChars,
  };
}

// ---------------------------------------------------------------------------
// The audit phase's two collaborators
// ---------------------------------------------------------------------------

/**
 * What a planner is handed.
 *
 * A subset of the audit phase's own context, declared structurally so that
 * context satisfies it without this module importing the phase that will call
 * it.
 */
export interface BatchPlannerContext {
  readonly fs: SliceFileSystem & { readFile(path: string): Promise<string> };
  /** Absolute path of the repository under analysis. Read, never written. */
  readonly targetDir: string;
  /** Where phase 2 left its artifacts; the schema model is read from here. */
  readonly runDir?: string | undefined;
  readonly profile?: StackProfile | undefined;
}

/** The two halves of a prompt, as the audit phase consumes them. */
export interface AuditPrompt {
  readonly system: string;
  readonly user: string;
}

/**
 * Phase 2 writes the reconstructed schema under this name.
 *
 * The name is repeated rather than imported: the document is built by a module
 * private to the inventory, and the audit only reads a handful of its fields.
 * {@link SchemaModelFileSchema} validates what it finds, so a rename shows up as
 * "no schema excerpt" and a disclosure in the plan's notes, never as a crash.
 */
export const SCHEMA_MODEL_FILE = "schema-model.json";

/**
 * The part of `schema-model.json` the audit reads.
 *
 * Its own schema, because a file on disk is external input whatever wrote it,
 * and because validating only the fields the excerpt renders means phase 2 can
 * add to that document without phase 3 caring.
 */
const SchemaModelFileSchema = z.object({
  dialect: z.string().default("unknown"),
  tables: z
    .array(
      z.object({
        name: z.string(),
        columns: z
          .array(
            z.object({
              name: z.string(),
              type: z.string(),
              nullable: z.boolean().default(true),
              isPrimaryKey: z.boolean().default(false),
              isUnique: z.boolean().default(false),
              references: z.object({ table: z.string(), column: z.string() }).optional(),
            }),
          )
          .default([]),
        indexes: z
          .array(
            z.object({
              name: z.string(),
              columns: z.array(z.string()).default([]),
              unique: z.boolean().default(false),
            }),
          )
          .default([]),
        foreignKeys: z
          .array(
            z.object({
              columns: z.array(z.string()).default([]),
              referencesTable: z.string(),
              referencesColumns: z.array(z.string()).default([]),
              onDelete: z.string().optional(),
            }),
          )
          .default([]),
        uniqueConstraints: z
          .array(z.object({ columns: z.array(z.string()).default([]) }))
          .default([]),
        rlsEnabled: z.boolean().default(false),
        policies: z.array(z.object({ name: z.string(), command: z.string() })).default([]),
        evidence: z
          .array(z.object({ file: z.string(), line: z.number().int().positive() }))
          .default([]),
      }),
    )
    .default([]),
});

/** Reads `schema-model.json` from the run directory, or `undefined` when there is none. */
export async function readSchemaModel(
  fs: Pick<BatchPlannerContext["fs"], "readFile">,
  runDir: string,
): Promise<SchemaSource | undefined> {
  let raw: string;
  try {
    raw = await fs.readFile(join(runDir, SCHEMA_MODEL_FILE));
  } catch {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const result = SchemaModelFileSchema.safeParse(parsed);
  return result.success ? result.data : undefined;
}

/**
 * A planner the audit phase can call directly, plus the rest of what it produced.
 *
 * The phase's planner seam returns batches and nothing else, but a plan also
 * carries the units that were skipped and the notes about what had to be
 * trimmed — and dropping those on the floor is exactly the kind of silence this
 * tool exists not to produce. `plan()` hands back the last full plan; a caller
 * that wants it up front calls {@link planBatches} directly.
 */
export interface BatchPlanner {
  (units: readonly AuditUnit[], ctx: BatchPlannerContext): Promise<AuditBatch[]>;
  /** The full plan from the most recent call, or `undefined` before the first. */
  plan(): BatchPlan | undefined;
}

/**
 * Builds a planner over a fixed set of options.
 *
 * It reads the schema model out of the run directory itself, so wiring the phase
 * costs one line and the data-layer prompts get their schema excerpt without the
 * caller having to know it exists.
 */
export function createBatchPlanner(
  options: Omit<PlanBatchesInput, "units" | "slices" | "profile"> = {},
): BatchPlanner {
  let last: BatchPlan | undefined;
  const planner = async (
    units: readonly AuditUnit[],
    ctx: BatchPlannerContext,
  ): Promise<AuditBatch[]> => {
    const schema =
      options.schema ??
      (ctx.runDir === undefined ? undefined : await readSchemaModel(ctx.fs, ctx.runDir));
    last = await planBatches({
      ...options,
      units,
      slices: { fs: ctx.fs, targetDir: ctx.targetDir, cache: createSourceCache() },
      ...(ctx.profile === undefined ? {} : { profile: ctx.profile }),
      ...(schema === undefined ? {} : { schema }),
    });
    return [...last.batches];
  };
  return Object.assign(planner, { plan: () => last });
}

/** The default planner, for a phase that has no options to pass. */
export const buildBatches: BatchPlanner = createBatchPlanner();

/**
 * The prompt of a batch, for the audit phase's prompt seam.
 *
 * The prompt was assembled and measured when the batch was packed, so this is a
 * read rather than a build: the bytes that were budgeted are the bytes that are
 * sent.
 */
export function buildPrompt(batch: { readonly id: string }): AuditPrompt {
  if (!isAuditBatch(batch)) {
    throw new Error(
      `batch ${batch.id} did not come from planBatches, so it carries no assembled prompt`,
    );
  }
  return { system: batch.systemPrompt, user: batch.prompt };
}

/** True when the object is one of this module's batches, carrying its own prompt. */
function isAuditBatch(value: { readonly id: string }): value is AuditBatch {
  const candidate = value as Partial<AuditBatch>;
  return typeof candidate.systemPrompt === "string" && typeof candidate.prompt === "string";
}

// ---------------------------------------------------------------------------
// What the model was shown
// ---------------------------------------------------------------------------

/** The lines of one file a batch actually put in front of the model. */
export interface CitedFile {
  /** Every line number the prompt printed, so a citation can be checked exactly. */
  readonly lines: ReadonlySet<number>;
  /** The block ranges the slices came from, for the message when a citation misses. */
  readonly ranges: readonly { readonly startLine: number; readonly endLine: number }[];
}

/** Every line of every file a batch showed, keyed by repo-relative path. */
export type CitedRanges = ReadonlyMap<string, CitedFile>;

/**
 * The line numbers a rendered slice printed.
 *
 * Parsed out of the gutter the slicer writes (`  42 | code`) because that is the
 * only exact answer: a slice over its line budget keeps the head, the tail and
 * the window around the citation, and the lines in between were elided. A model
 * that cites an elided line did not read it, and the decoder treats that the
 * same way it treats an invented file.
 */
export function shownLines(slice: CodeSlice): number[] {
  const numbers: number[] = [];
  for (const line of slice.text.split("\n")) {
    const match = /^\s*(\d+) \|/.exec(line);
    const value = match?.[1];
    if (value !== undefined) numbers.push(Number(value));
  }
  if (numbers.length > 0) return numbers;
  // Defensive: a slice with no gutter at all still bounds its own block.
  const all: number[] = [];
  for (let line = slice.startLine; line <= slice.endLine; line += 1) all.push(line);
  return all;
}

/** Indexes everything a batch showed, so a citation can be proven against it. */
export function citedRanges(batch: AuditBatch): CitedRanges {
  const index = new Map<
    string,
    { lines: Set<number>; ranges: { startLine: number; endLine: number }[] }
  >();
  const add = (slice: CodeSlice): void => {
    const entry = index.get(slice.file) ?? { lines: new Set<number>(), ranges: [] };
    for (const line of shownLines(slice)) entry.lines.add(line);
    entry.ranges.push({ startLine: slice.startLine, endLine: slice.endLine });
    index.set(slice.file, entry);
  };
  for (const block of batch.shared) {
    if (block.slice !== undefined) add(block.slice);
    for (const ref of block.citable ?? []) {
      const entry = index.get(ref.file) ?? { lines: new Set<number>(), ranges: [] };
      entry.lines.add(ref.line);
      entry.ranges.push({ startLine: ref.line, endLine: ref.line });
      index.set(ref.file, entry);
    }
  }
  for (const item of batch.entries) {
    add(item.slice);
    for (const related of item.related) add(related.slice);
  }
  return index;
}

/** True when the batch printed this exact line of this exact file. */
export function wasShown(ranges: CitedRanges, file: string, line: number): boolean {
  return ranges.get(file)?.lines.has(line) ?? false;
}

/** The ranges of a file a batch showed, rendered for a rejection message. */
export function shownRangesOf(ranges: CitedRanges, file: string): string {
  const entry = ranges.get(file);
  if (entry === undefined) return "no slice of that file was provided";
  return entry.ranges.map((range) => `${range.startLine}-${range.endLine}`).join(", ");
}
