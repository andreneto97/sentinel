/**
 * Shared plumbing for the phase 2 enumerators — the inventory's counterpart to
 * `src/scan/runners/_runner-support.ts`.
 *
 * It holds what every enumerator would otherwise repeat: the context they are
 * handed, the draft unit they return, the content-addressed identity that
 * survives a file being edited above the unit, and the small amount of text
 * work that turns a matched node into attributes an audit prompt can read.
 *
 * Two conventions live here and are worth stating once, because the audit
 * prompt depends on both:
 *
 * - **An attribute is omitted when it is not derivable, and spelled out when
 *   its absence is the finding.** A Cloudflare worker has no `memory`, so the
 *   key is absent; a queue consumer with nothing to deduplicate on carries
 *   `idempotencyKey: "none"`, because "nobody set one" is exactly what the
 *   audit is looking for.
 * - **Identity never contains a line number.** A unit is identified by its
 *   kind, its file and a symbol derived from *what it is* — a function name, a
 *   route path, a hash of the matched source — so adding an import at the top
 *   of a file does not renumber the whole inventory.
 */

import type { AuditUnit } from "../contracts/findings.ts";
import {
  AUDIT_UNIT_KINDS,
  AUDIT_UNIT_NOUN,
  type AuditUnitKind,
  type EnumeratorStatus,
  countUnits,
  groupThousands,
} from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import type { ProfileFileSystem } from "../profile/file-system-port.ts";
import type { RepoSnapshot } from "../profile/repo-snapshot.ts";
import { FILE_KIND_ORDER, type FileKind, classifyFile } from "../scan/_file-kind.ts";
import { contentSymbol } from "../scan/runners/_runner-support.ts";
import type { StructuralSearch } from "./_ast-grep.ts";

export { contentSymbol };

/**
 * The filesystem surface phase 2 needs, declared structurally so the real port
 * satisfies it without knowing it exists.
 */
export interface InventoryFileSystem extends ProfileFileSystem {
  /** Bytes, for the citation verifier. */
  readFileBytes(path: string): Promise<Uint8Array>;
  /** Atomic in the real port; used once, for `inventory.json`. */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  /** Canonical absolute path, for the containment check the verifier makes. */
  realpath(path: string): Promise<string>;
}

/** The slice of `src/ports/process-executor.ts` phase 2 depends on. */
export interface InventoryProcessExecutor {
  run(
    command: string,
    args?: readonly string[],
    options?: {
      readonly cwd?: string;
      readonly timeoutMs?: number;
      readonly maxOutputBytes?: number;
      readonly signal?: AbortSignal;
    },
  ): Promise<{
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
    readonly timedOut: boolean;
    readonly truncated: boolean;
    readonly notFound: boolean;
  }>;
}

/** The slice of `src/tools/resolve.ts#ToolResolver` phase 2 depends on. */
export interface InventoryToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/**
 * Everything phase 2 is handed.
 *
 * The field names are phase 1's, so the CLI passes its `ScanContext` straight
 * in and the two phases cannot disagree about which directory is the target.
 */
export interface InventoryContext {
  readonly fs: InventoryFileSystem;
  readonly exec: InventoryProcessExecutor;
  readonly tools: InventoryToolResolver;
  /** Absolute path of the repository under analysis. Never written to. */
  readonly targetDir: string;
  /** Absolute path of this run's output directory; `inventory.json` lands in it. */
  readonly runDir: string;
  /** Identifies the run in the artifact it writes. */
  readonly runId: string;
  /** Phase 0 output: what exists, and what was looked for and is absent. */
  readonly profile?: StackProfile | undefined;
  /** Allow a tool found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  /** Budget for one enumerator, and for the ast-grep process it may spawn. */
  readonly timeoutMs?: number | undefined;
  /** Cancels the phase; forwarded to the structural search's child process. */
  readonly signal?: AbortSignal | undefined;
}

/**
 * What an enumerator actually runs against: the context, plus the two things
 * the aggregator builds once and shares.
 *
 * Sharing matters. The snapshot walks the repository once and caches every
 * read, so eight enumerators inspecting `vercel.json` read it once; the search
 * is one ast-grep process per enumerator rather than one per pattern.
 */
export interface EnumerationContext extends InventoryContext {
  /** The repository listing, with cached reads. Shared by every enumerator. */
  readonly snapshot: RepoSnapshot;
  /** Structural search over JS/TS. Reports `ok: false` when ast-grep is missing. */
  readonly search: StructuralSearch;
}

/**
 * A unit as an enumerator produces it: located, described, but not yet
 * identified — the aggregator assigns the id, so identity is computed in one
 * place and cannot drift between enumerators.
 */
export interface DraftUnit {
  readonly kind: AuditUnitKind;
  /** What a reader sees in the coverage table, e.g. `POST /api/webhooks/stripe`. */
  readonly label: string;
  /** Repo-relative POSIX path. */
  readonly file: string;
  /** 1-based first line of the unit. */
  readonly line: number;
  /** 1-based last line, when the unit spans a body worth slicing for the prompt. */
  readonly endLine?: number | undefined;
  /**
   * What identifies the unit inside its file. Content-derived — a name, a
   * path, or {@link contentSymbol} over the matched source — never a line.
   */
  readonly symbol: string;
  /** Anything the citation itself should carry into the report. */
  readonly note?: string | undefined;
  readonly attributes: Readonly<Record<string, string | undefined>>;
}

/** What one enumerator contributed, and whether it could do its job. */
export interface EnumerationOutcome {
  readonly status: EnumeratorStatus;
  /** Why the outcome is not `ok`, or context worth disclosing when it is. */
  readonly reason?: string | undefined;
  readonly units: readonly DraftUnit[];
  /**
   * Drafts the non-production policy removed from `units`, kept so the decision
   * is auditable rather than invisible.
   *
   * The count is already in `reason`, which is what `inventory.json` and the
   * report's coverage section print. This list is the same decision at full
   * resolution; `inventory.ts` does not read it yet, and listing these in
   * `inventory.json`'s `dropped` array is a few lines there once someone wants
   * the paths as well as the count.
   */
  readonly excluded?: readonly DraftUnit[] | undefined;
}

/** An attribute patch the cross-reference pass applies, keyed by unit id. */
export type AttributePatch = ReadonlyMap<string, Readonly<Record<string, string | undefined>>>;

/** One source of units. The aggregator runs every registered enumerator concurrently. */
export interface InventoryEnumerator {
  /** Identifies it in the enumerator report; unique within a run. */
  readonly name: string;
  /** The kinds it owns, listed even when it finds none of them. */
  readonly kinds: readonly AuditUnitKind[];
  /** Never throws: everything that can go wrong comes back as an outcome. */
  enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome>;
  /**
   * Optional second pass, run once every unit has an id.
   *
   * It can only *add attributes*: the aggregator applies the returned patches
   * and ignores everything else, so a cross-reference cannot invent a unit or
   * move one. This is how a cron that calls `/api/cron/rotate` records whether
   * the route it hits checks a shared secret.
   */
  crossReference?(
    own: readonly AuditUnit[],
    all: readonly AuditUnit[],
    ctx: EnumerationContext,
  ): Promise<AttributePatch>;
}

// ---------------------------------------------------------------------------
// The non-production policy
// ---------------------------------------------------------------------------

/**
 * The kinds that keep their units wherever the file lives, because for these a
 * non-production *path* does not make the thing itself non-production.
 *
 * - `workflow-job` — a CI job is the real pipeline whatever the workflow is
 *   called. A workflow whose name says "test" still holds real secrets, real
 *   `permissions` and a real checkout of untrusted code.
 * - `container` — a Dockerfile builds an image that runs. One under `test/`
 *   still gets built, still runs as root if it says so.
 * - `migration` — a migration executes against the real database. Directory
 *   names do not change that.
 *
 * Everything else is production-only: see {@link PRODUCTION_ONLY_UNIT_KINDS}.
 */
export const PATH_INDEPENDENT_UNIT_KINDS: readonly AuditUnitKind[] = [
  "workflow-job",
  "container",
  "migration",
];

/**
 * The kinds that are only audited in production code — everything that is not
 * {@link PATH_INDEPENDENT_UNIT_KINDS}.
 *
 * These units are all audited for the same class of question: does this code
 * path check the caller's role, constrain the query by tenant, or sanitise the
 * input it forwards. Every one of those questions presupposes a real caller with
 * real input. A test asserts on a *fake* handler, queries a *seeded* row, and
 * feeds a sink a literal it wrote three lines earlier, so a verdict on one is
 * noise rather than coverage.
 *
 * Stated as an exception list rather than an allow-list on purpose. A
 * well-tested repository holds far more handler-shaped and sink-shaped code in
 * its suites than in its application: every supertest assertion is a `res.get`
 * the sink enumerator recognises. So an allow-list that forgot a kind does not
 * merely add noise — because the exclusion runs before
 * {@link MAX_UNITS_PER_ENUMERATOR} in {@link finishOutcome}, the test code
 * spends the whole per-enumerator budget and pushes production candidates out of
 * the inventory entirely. The domain then reports that a great many sinks exist
 * and none were audited, which is a true sentence about the wrong files.
 *
 * So a kind is production-only unless there is an argument for it not to be, and
 * the three arguments are in {@link PATH_INDEPENDENT_UNIT_KINDS}.
 */
export const PRODUCTION_ONLY_UNIT_KINDS: readonly AuditUnitKind[] = AUDIT_UNIT_KINDS.filter(
  (kind) => !PATH_INDEPENDENT_UNIT_KINDS.includes(kind),
);

/** True when a draft of this kind, in this file, is not worth a verdict. */
function isExcluded(draft: DraftUnit, kind: FileKind): boolean {
  return kind !== "production" && PRODUCTION_ONLY_UNIT_KINDS.includes(draft.kind);
}

/** What the policy removed, and the sentence the coverage section prints. */
export interface UnitExclusion {
  readonly kept: readonly DraftUnit[];
  readonly excluded: readonly DraftUnit[];
  /** The count, in the inventory's own vocabulary; undefined when nothing went. */
  readonly note: string | undefined;
}

/**
 * Splits drafts into the ones worth auditing and the ones the policy excludes.
 *
 * Counted and worded, never silent: the note is what reaches
 * `inventory.json`'s `enumerators[].reason` and the report's coverage table, so
 * a run that excluded units says how many, and of which kind, instead of quietly
 * showing a smaller total than the repository has.
 */
export function excludeNonProductionUnits(units: readonly DraftUnit[]): UnitExclusion {
  const kept: DraftUnit[] = [];
  const excluded: DraftUnit[] = [];
  const perUnitKind = new Map<AuditUnitKind, number>();
  const perFileKind = new Map<FileKind, number>();

  for (const draft of units) {
    const fileKind = classifyFile(draft.file).kind;
    if (!isExcluded(draft, fileKind)) {
      kept.push(draft);
      continue;
    }
    excluded.push(draft);
    perUnitKind.set(draft.kind, (perUnitKind.get(draft.kind) ?? 0) + 1);
    perFileKind.set(fileKind, (perFileKind.get(fileKind) ?? 0) + 1);
  }

  if (excluded.length === 0) return { kept, excluded, note: undefined };

  const counted = PRODUCTION_ONLY_UNIT_KINDS.filter((kind) => perUnitKind.has(kind)).map((kind) =>
    countUnits(kind, perUnitKind.get(kind) ?? 0),
  );
  const where = FILE_KIND_ORDER.filter((kind) => perFileKind.has(kind));

  return {
    kept,
    excluded,
    note: `${counted.join(" and ")} in ${joinWords(where)} code ${excluded.length === 1 ? "was" : "were"} ${EXCLUSION_TAIL}`,
  };
}

/** The half of the exclusion note that does not vary; kept whole for one template literal. */
const EXCLUSION_TAIL =
  "excluded from the audit: nothing outside production code answers a real request, so a verdict on one would be noise rather than coverage";

/** `a`, `a and b`, `a, b and c` — for a list inside a sentence. */
function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words[0] ?? "";
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] ?? ""}`;
}

// ---------------------------------------------------------------------------
// Outcome constructors
// ---------------------------------------------------------------------------

/**
 * The enumerator ran with everything it needs.
 *
 * This and {@link degraded} are the two constructors that carry units, so the
 * non-production policy is applied here rather than in each enumerator: a route
 * unit in a test file is excluded whoever produced it, and the enumerator that
 * produced it does not get a say in whether the exclusion is disclosed.
 */
export function enumerated(units: readonly DraftUnit[], reason?: string): EnumerationOutcome {
  return withPolicy("ok", units, reason);
}

/** It ran, but with less than it needs; its units are usable, its coverage is not complete. */
export function degraded(units: readonly DraftUnit[], reason: string): EnumerationOutcome {
  return withPolicy("degraded", units, reason);
}

/**
 * Builds an outcome with the policy applied and its count folded into `reason`.
 *
 * The status is left alone: an exclusion is a stated scope decision, not a gap
 * in what was enumerated, so it must not turn an `ok` enumerator into a
 * `degraded` one — `degraded` is reserved for coverage Sentinel cannot vouch for.
 */
function withPolicy(
  status: "ok" | "degraded",
  units: readonly DraftUnit[],
  reason: string | undefined,
): EnumerationOutcome {
  const policy = excludeNonProductionUnits(units);
  const joined = joinReasons([reason, policy.note]);
  return {
    status,
    units: policy.kept,
    ...(joined === undefined ? {} : { reason: joined }),
    ...(policy.excluded.length === 0 ? {} : { excluded: policy.excluded }),
  };
}

/** It could not apply: the repository has nothing of this kind to enumerate. */
export function notApplicable(reason: string): EnumerationOutcome {
  return { status: "skipped", units: [], reason };
}

/** It ran and its output cannot be trusted. */
export function failed(reason: string): EnumerationOutcome {
  return { status: "failed", units: [], reason };
}

/** Cap on the units one enumerator contributes; hitting it is disclosed, never silent. */
export const MAX_UNITS_PER_ENUMERATOR = 500;

/**
 * The tail every enumerator ends with: apply the non-production policy, cap the
 * list, and decide between ok, degraded and skipped.
 *
 * The three statuses are not cosmetic. `skipped` means "there is nothing of
 * this kind here", which the report may state as a fact; `degraded` means
 * "something was not enumerated", which it may not. A structural search that
 * did not run, or a cap that was hit, is therefore always degraded — the units
 * it did produce are still usable, but the coverage claim is not complete.
 *
 * The policy runs *before* the cap, so a budget of 500 units is spent on 500
 * production units instead of on test code, and the exclusion is reported here
 * rather than by the constructors below — they receive an already-filtered list
 * and would have nothing left to count.
 */
export function finishOutcome(
  units: readonly DraftUnit[],
  options: {
    readonly notes?: readonly string[] | undefined;
    readonly searchOk?: boolean | undefined;
    readonly emptyReason: string;
    readonly limit?: number | undefined;
  },
): EnumerationOutcome {
  const policy = excludeNonProductionUnits(units);
  const limit = options.limit ?? MAX_UNITS_PER_ENUMERATOR;
  const capped = policy.kept.slice(0, limit);
  const truncated = policy.kept.length > capped.length;
  const notes = [...(options.notes ?? [])];
  if (truncated) {
    notes.push(
      `stopped at ${limit} units; ${policy.kept.length - capped.length} more were not kept`,
    );
  }
  notes.push(policy.note ?? "");
  const reason = joinReasons(notes);

  /** Re-attaches what the policy removed; the constructors cannot see it any more. */
  const disclose = (outcome: EnumerationOutcome): EnumerationOutcome =>
    policy.excluded.length === 0 ? outcome : { ...outcome, excluded: policy.excluded };

  if (options.searchOk === false || truncated) {
    return disclose(degraded(capped, reason ?? "the structural search did not run"));
  }
  // "Nothing of this kind is here" would be false when the policy is the reason
  // the list is empty, so that case reports an enumerator that ran and kept none.
  if (capped.length === 0 && policy.excluded.length === 0) {
    return notApplicable(reason ?? options.emptyReason);
  }
  return disclose(reason === undefined ? enumerated(capped) : enumerated(capped, reason));
}

/**
 * Joins notes into one sentence, dropping the empty ones.
 *
 * Kept byte-for-byte in step with `src/scan/runners/_runner-support.ts`; see the
 * note there for why the helper exists twice rather than in one place.
 */
export function joinReasons(parts: ReadonlyArray<string | null | undefined>): string | undefined {
  const kept = parts.filter(
    (part): part is string => part !== null && part !== undefined && part.trim() !== "",
  );
  return kept.length === 0 ? undefined : kept.join("; ");
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** Separator that cannot occur in a kind, a path or a symbol. */
const ID_SEPARATOR = String.fromCharCode(31);

/**
 * Stable across runs and machines: a short hash of what identifies a unit.
 *
 * Deliberately the same construction as `findingId`, minus the rule: a unit is
 * `(kind, file, symbol)` and a finding is `(domain, rule, file, symbol)`, so
 * the two id spaces are independent but equally stable.
 */
export function unitId(kind: AuditUnitKind, file: string, symbol: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update([kind, file, symbol].join(ID_SEPARATOR));
  return hasher.digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

/** Longest attribute value the inventory keeps; the audit gets the real slice anyway. */
export const MAX_ATTRIBUTE_LENGTH = 200;

/** Collapses whitespace so a multi-line node reads as one attribute value. */
export function collapse(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** Collapses and caps a value, marking it when something was cut. */
export function brief(text: string, limit = MAX_ATTRIBUTE_LENGTH): string {
  const collapsed = collapse(text);
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 3)}...`;
}

/** The content of a quoted or template literal, or `undefined` when it is not one. */
export function literalOf(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  const trimmed = text.trim();
  const match = /^(['"`])([\s\S]*)\1$/.exec(trimmed);
  if (match === null) return undefined;
  const body = match[2] ?? "";
  // A template literal with a substitution is not a literal value.
  if (match[1] === "`" && body.includes("${")) return undefined;
  return body;
}

/** A literal's content when the text is one, and the text itself when it is not. */
export function literalOrExpression(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  return literalOf(text) ?? brief(text);
}

/** Characters that open a nesting level while scanning an object literal. */
const OPENERS: Readonly<Record<string, string>> = { "{": "}", "[": "]", "(": ")" };

/**
 * Reads `key: value` out of an object-literal's source text.
 *
 * Source text rather than a parse tree: the enumerators already have the node
 * ast-grep matched, and what they need from it is a handful of option values —
 * `concurrency`, `attempts`, `memorySize`. The scan tracks nesting and quoting,
 * so an object value comes back whole, but it takes the *first* occurrence of
 * the key at any depth, which is why callers look for specific option names
 * rather than generic ones.
 */
export function optionOf(source: string, key: string): string | undefined {
  const finder = new RegExp(`(?:^|[\\s,{(])['"]?${key}['"]?\\s*:`, "g");
  let found = finder.exec(source);
  while (found !== null) {
    const start = found.index + found[0].length;
    if (!insideLiteral(source, found.index)) {
      const value = readValue(source, start);
      if (value !== "") return value;
    }
    found = finder.exec(source);
  }
  return undefined;
}

/** True when the offset sits inside a string or template literal. */
function insideLiteral(source: string, offset: number): boolean {
  let quote: string | null = null;
  for (let index = 0; index < offset; index += 1) {
    const char = source[index];
    if (char === undefined) break;
    if (quote !== null) {
      if (char === "\\") {
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") quote = char;
  }
  return quote !== null;
}

/** Reads one value starting at `start`, stopping at the comma that ends it. */
function readValue(source: string, start: number): string {
  const stack: string[] = [];
  let quote: string | null = null;
  let index = start;
  while (index < source.length && /\s/.test(source[index] ?? "")) index += 1;
  const from = index;
  for (; index < source.length; index += 1) {
    const char = source[index] ?? "";
    if (quote !== null) {
      if (char === "\\") {
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    const closer = OPENERS[char];
    if (closer !== undefined) {
      stack.push(closer);
      continue;
    }
    if (stack.length > 0) {
      if (char === stack[stack.length - 1]) stack.pop();
      continue;
    }
    if (char === "," || char === "}" || char === ")" || char === "]" || char === "\n") break;
  }
  return source.slice(from, index).trim();
}

/** True when the object text declares the key at all, whatever its value. */
export function hasOption(source: string, key: string): boolean {
  return optionOf(source, key) !== undefined;
}

/** Declarations that name the symbol a line belongs to. */
const DECLARATIONS: readonly RegExp[] = [
  /^\s*export\s+default\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)?/,
  /^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=/,
  /^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*[:{]/,
];

/** Leading whitespace width of a line, tabs counted as one column. */
function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

/** The name a line declares, or `undefined` when it declares nothing. */
function declarationName(text: string): string | undefined {
  for (const pattern of DECLARATIONS) {
    const match = pattern.exec(text);
    if (match !== null) return match[1] ?? "default";
  }
  return undefined;
}

/**
 * True when a declaration line leaves something open beneath it — a body, an
 * argument list, an arrow. A declaration that finishes on its own line cannot
 * be what encloses a line further down, which is what keeps a `const canEdit =
 * user.role === "admin";` three lines above a JSX element from being reported
 * as the component that contains it.
 */
function opensBlock(text: string): boolean {
  return /[{([,]\s*$|=>\s*$/.test(text.replace(/\/\/.*$/, "").trimEnd());
}

/**
 * The nearest enclosing function, component or class name above `line`.
 *
 * Walked upwards over the source rather than asked of the parser: ast-grep can
 * express "inside a function declaration", but not "and tell me its name"
 * without a second query per match, and every enumerator needs this for every
 * hit. Preference goes to a declaration indented less than the cited line —
 * the thing that *contains* it — falling back to the nearest declaration of any
 * indentation.
 */
export function enclosingSymbol(lines: readonly string[], line: number): string | undefined {
  const target = lines[line - 1];
  if (target === undefined) return undefined;
  const targetIndent = indentOf(target);
  let fallback: string | undefined;
  for (let index = line - 1; index >= 0; index -= 1) {
    const text = lines[index];
    if (text === undefined || text.trim() === "") continue;
    const name = declarationName(text);
    if (name === undefined) continue;
    // The cited line declares it itself: that is its own symbol.
    if (index === line - 1) return name;
    if (!opensBlock(text)) continue;
    if (indentOf(text) < targetIndent) return name;
    fallback ??= name;
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

/**
 * Normalises an attribute record: drops the keys nothing could be derived for,
 * collapses every value, and sorts the keys.
 *
 * Sorting is not cosmetic. `inventory.json` has to be byte-identical across two
 * runs of unchanged code, and JSON preserves insertion order, so an attribute
 * map built in whatever order the branches happened to run would produce a
 * different file every time.
 */
export function attributesOf(
  source: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const normalised: Record<string, string> = {};
  for (const key of Object.keys(source).sort()) {
    const value = source[key];
    if (value === undefined) continue;
    const text = brief(value);
    if (text === "") continue;
    normalised[key] = text;
  }
  return normalised;
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

/**
 * The kinds whose span *carries* other units.
 *
 * These are the things an audit can reason about on their own: a request
 * handler, a migration script, a function a platform invokes. Each one has a
 * body, a caller and a reason to exist, so a verdict about it is a verdict
 * about something a reader can act on.
 */
export const CONTAINING_UNIT_KINDS: readonly AuditUnitKind[] = [
  "route",
  "migration",
  "serverless-function",
  "queue-consumer",
  "webhook",
];

/**
 * The kinds that are evidence of the unit around them rather than units of
 * their own — when there *is* a unit around them.
 *
 * A query and a sink are fragments. Asking a model whether
 * `queryRunner.query(sql)` constrains by tenant, with no handler around it and
 * no caller in view, is what produces an ungrounded verdict: the model invents
 * the context it was not given. Inside a handler the same query is answerable,
 * because the handler says who is calling and with what. So where a container
 * exists the fragment travels with it, and where none exists — a query in a
 * service module nothing in the inventory encloses — it stays a unit, because
 * something has to carry it.
 */
export const CONTAINED_UNIT_KINDS: readonly AuditUnitKind[] = ["data-access", "sink"];

/**
 * The attribute keys containment writes on a containing unit.
 *
 * Spelled once here because two readers depend on them: the audit prompt,
 * which prints every attribute a unit carries, and anyone reading
 * `inventory.json` to check that a migration's 47 statements were not quietly
 * dropped when they stopped being 47 units.
 */
export const CONTAINMENT_ATTRIBUTE = {
  /** How many units this one absorbed, in total. */
  units: "containedUnits",
  /** The absorbed units per kind, e.g. `data-access:9,sink:1`. */
  kinds: "containedKinds",
  /** Tables the absorbed call sites name, deduplicated and sorted. */
  tables: "containedTables",
  /** Operations the absorbed call sites perform, deduplicated and sorted. */
  operations: "containedOperations",
  /** Sink types the absorbed sinks are, deduplicated and sorted. */
  sinkTypes: "containedSinkTypes",
} as const;

/**
 * The data-access enumerator's word for a call site it could not tie to a
 * table. Rolling it up would put the string `unresolved` in a list of table
 * names, which reads like a table called `unresolved`.
 */
const UNRESOLVED_TABLE = "unresolved";

/** One absorbed unit and the unit that absorbed it. */
export interface Containment {
  /** Id of the containing unit; it is still in the document. */
  readonly containerId: string;
  /** Kind of the containing unit, so a disclosure can name it. */
  readonly containerKind: AuditUnitKind;
  /** The absorbed unit, exactly as it was enumerated. */
  readonly unit: AuditUnit;
}

/** What {@link containUnits} decided. */
export interface ContainmentResult {
  /** The units that remain, each container carrying what it absorbed. */
  readonly units: readonly AuditUnit[];
  /** Every absorbed unit, in the order the input listed them. */
  readonly contained: readonly Containment[];
}

/** The lines a unit occupies; a unit with no `endLine` occupies one. */
function spanOf(unit: AuditUnit): readonly [number, number] {
  const { line, endLine } = unit.location;
  return [line, endLine !== undefined && endLine > line ? endLine : line];
}

/** True when the container's span covers the unit's, in the same file. */
function covers(container: AuditUnit, unit: AuditUnit): boolean {
  if (container.location.file !== unit.location.file) return false;
  const [outerStart, outerEnd] = spanOf(container);
  const [innerStart, innerEnd] = spanOf(unit);
  return outerStart <= innerStart && outerEnd >= innerEnd;
}

/**
 * The tightest container around a unit.
 *
 * Tightest rather than first: a query inside a webhook receiver inside a route
 * belongs to the webhook, because that is the code the audit would have to read
 * to answer anything about the query. Ties are broken by id so two runs over
 * unchanged code make the same choice.
 */
function innermost(containers: readonly AuditUnit[], unit: AuditUnit): AuditUnit | undefined {
  let best: AuditUnit | undefined;
  let bestWidth = Number.POSITIVE_INFINITY;
  for (const container of containers) {
    if (container.id === unit.id || !covers(container, unit)) continue;
    const [start, end] = spanOf(container);
    const width = end - start;
    if (width > bestWidth) continue;
    if (best !== undefined && width === bestWidth && container.id.localeCompare(best.id) >= 0) {
      continue;
    }
    best = container;
    bestWidth = width;
  }
  return best;
}

/** Deduplicated, sorted, joined — or `undefined` when nothing was collected. */
function joinValues(values: ReadonlySet<string>): string | undefined {
  return values.size === 0 ? undefined : [...values].sort().join(",");
}

/** Rewrites a container with what it absorbed recorded as its own evidence. */
function withContained(container: AuditUnit, carried: readonly Containment[]): AuditUnit {
  const perKind = new Map<AuditUnitKind, number>();
  const tables = new Set<string>();
  const operations = new Set<string>();
  const sinkTypes = new Set<string>();

  for (const { unit } of carried) {
    perKind.set(unit.kind, (perKind.get(unit.kind) ?? 0) + 1);
    const table = unit.attributes.table;
    if (table !== undefined && table !== "" && table !== UNRESOLVED_TABLE) tables.add(table);
    const operation = unit.attributes.operation;
    if (operation !== undefined && operation !== "") operations.add(operation);
    const sinkType = unit.attributes.sinkType;
    if (sinkType !== undefined && sinkType !== "") sinkTypes.add(sinkType);
  }

  return {
    ...container,
    attributes: attributesOf({
      ...container.attributes,
      [CONTAINMENT_ATTRIBUTE.units]: String(carried.length),
      [CONTAINMENT_ATTRIBUTE.kinds]: AUDIT_UNIT_KINDS.filter((kind) => perKind.has(kind))
        .map((kind) => `${kind}:${perKind.get(kind) ?? 0}`)
        .join(","),
      [CONTAINMENT_ATTRIBUTE.tables]: joinValues(tables),
      [CONTAINMENT_ATTRIBUTE.operations]: joinValues(operations),
      [CONTAINMENT_ATTRIBUTE.sinkTypes]: joinValues(sinkTypes),
    }),
  };
}

/**
 * Folds every unit that lies inside another unit's span into that unit.
 *
 * The one rule, and it is kind-aware in both directions: only a
 * {@link CONTAINING_UNIT_KINDS} unit absorbs, only a
 * {@link CONTAINED_UNIT_KINDS} unit is absorbed, and the two sets do not
 * overlap, so a container can never be swallowed by another container and the
 * pass cannot cascade.
 *
 * Why it exists: a repository whose migrations number in the hundreds has most
 * of its queries and sinks *inside* a migration script that is already a unit.
 * Without this pass the audit pays a model to read the same DDL twice — once as
 * the migration, once per statement — and the coverage denominator advertises
 * several times as many things as the repository has worth a verdict.
 *
 * Nothing is lost and nothing is silent. The container records what it took in
 * {@link CONTAINMENT_ATTRIBUTE}, which the audit prompt prints with every other
 * fact, and the caller turns {@link ContainmentResult.contained} into the
 * sentence the coverage table shows — see {@link containmentNote}.
 */
export function containUnits(units: readonly AuditUnit[]): ContainmentResult {
  const containersByFile = new Map<string, AuditUnit[]>();
  for (const unit of units) {
    if (!CONTAINING_UNIT_KINDS.includes(unit.kind)) continue;
    const list = containersByFile.get(unit.location.file);
    if (list === undefined) containersByFile.set(unit.location.file, [unit]);
    else list.push(unit);
  }
  if (containersByFile.size === 0) return { units: [...units], contained: [] };

  const contained: Containment[] = [];
  const carriedBy = new Map<string, Containment[]>();
  const kept: AuditUnit[] = [];
  for (const unit of units) {
    const host = CONTAINED_UNIT_KINDS.includes(unit.kind)
      ? innermost(containersByFile.get(unit.location.file) ?? [], unit)
      : undefined;
    if (host === undefined) {
      kept.push(unit);
      continue;
    }
    const entry: Containment = { containerId: host.id, containerKind: host.kind, unit };
    contained.push(entry);
    const list = carriedBy.get(host.id);
    if (list === undefined) carriedBy.set(host.id, [entry]);
    else list.push(entry);
  }
  if (contained.length === 0) return { units: kept, contained };

  return {
    units: kept.map((unit) => {
      const carried = carriedBy.get(unit.id);
      return carried === undefined ? unit : withContained(unit, carried);
    }),
    contained,
  };
}

/** The half of the containment disclosure that does not vary. */
const CONTAINMENT_TAIL =
  "a contained unit is evidence of the unit around it, not a unit of its own, so every coverage denominator counts the container, whose extent the audit reads in full";

/** `a`, `a or b`, `a, b or c` — the container kinds, in a sentence. */
function joinAlternatives(words: readonly string[]): string {
  if (words.length <= 1) return words[0] ?? "";
  return `${words.slice(0, -1).join(", ")} or ${words[words.length - 1] ?? ""}`;
}

/**
 * What an enumerator whose units were absorbed has to disclose.
 *
 * `50 data-access call sites, 40 of them inside a migration that carries them` —
 * the produced total first, because the number that vanished from the counts is
 * the one a reader will otherwise go looking for.
 *
 * `produced` is everything the enumerator contributed before containment ran;
 * `absorbed` is the subset of {@link ContainmentResult.contained} whose units
 * are its own.
 */
export function containmentNote(
  produced: readonly AuditUnit[],
  absorbed: readonly Containment[],
): string | undefined {
  if (absorbed.length === 0) return undefined;
  const total = new Map<AuditUnitKind, number>();
  for (const unit of produced) total.set(unit.kind, (total.get(unit.kind) ?? 0) + 1);
  const taken = new Map<AuditUnitKind, number>();
  const hosts = new Set<AuditUnitKind>();
  for (const entry of absorbed) {
    taken.set(entry.unit.kind, (taken.get(entry.unit.kind) ?? 0) + 1);
    hosts.add(entry.containerKind);
  }
  const where = joinAlternatives(
    AUDIT_UNIT_KINDS.filter((kind) => hosts.has(kind)).map(
      (kind) => `a ${AUDIT_UNIT_NOUN[kind][0]}`,
    ),
  );
  const parts = AUDIT_UNIT_KINDS.filter((kind) => taken.has(kind)).map((kind) => {
    const folded = taken.get(kind) ?? 0;
    return `${countUnits(kind, total.get(kind) ?? folded)}, ${groupThousands(
      folded,
    )} of them inside ${where} that carries ${folded === 1 ? "it" : "them"}`;
  });
  return `${parts.join("; ")}; ${CONTAINMENT_TAIL}`;
}

/**
 * What an enumerator whose units did the absorbing has to disclose.
 *
 * The other half of the same accounting: `20 migrations carry 40 data-access
 * call sites and 5 unsafe-input sinks as evidence rather than as units of their
 * own`. Without it the migration line reads as though those 20 units were all
 * the repository had at that path.
 */
export function carriedNote(carried: readonly Containment[]): string | undefined {
  if (carried.length === 0) return undefined;
  const containers = new Map<AuditUnitKind, Set<string>>();
  const taken = new Map<AuditUnitKind, number>();
  for (const entry of carried) {
    const ids = containers.get(entry.containerKind) ?? new Set<string>();
    ids.add(entry.containerId);
    containers.set(entry.containerKind, ids);
    taken.set(entry.unit.kind, (taken.get(entry.unit.kind) ?? 0) + 1);
  }
  const who = AUDIT_UNIT_KINDS.filter((kind) => containers.has(kind)).map((kind) =>
    countUnits(kind, containers.get(kind)?.size ?? 0),
  );
  const what = AUDIT_UNIT_KINDS.filter((kind) => taken.has(kind)).map((kind) =>
    countUnits(kind, taken.get(kind) ?? 0),
  );
  // One container "carries"; one carried unit is "a unit of its own".
  const verb =
    [...containers.values()].reduce((total, ids) => total + ids.size, 0) === 1
      ? "carries"
      : "carry";
  const tail = carried.length === 1 ? "a unit of its own" : "units of their own";
  return `${joinWords(who)} ${verb} ${joinWords(what)} as evidence rather than as ${tail}`;
}
