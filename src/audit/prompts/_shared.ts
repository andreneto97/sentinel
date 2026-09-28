/**
 * What every audit prompt is made of.
 *
 * The one rule this whole module exists to enforce: **Sentinel feeds the code to
 * the model; the model never reads files.** A prompt is a closed document — the
 * stack facts phase 0 proved, the shared context the batch needs once, and the
 * source slice of every unit, read from disk by `src/inventory/slice.ts`. The
 * agent is given no filesystem, so anything it cites that is not in this
 * document is, by construction, invented; `src/audit/verdict.ts` drops it and
 * `src/verify/` would drop it again.
 *
 * Three things are shared rather than repeated per kind, because letting them
 * drift between kinds would make the report incomparable:
 *
 * - **The severity rubric**, with a per-rule ceiling. A model asked for a
 *   severity without a rubric invents one, and a `SELECT *` reported as critical
 *   poisons every score built on top of it.
 * - **The verdict obligation.** Every unit in the batch must come back with a
 *   verdict naming every check. A silent omission is a coverage hole, so the
 *   footer lists the ids and the decoder counts what is missing.
 * - **The certainty rule.** Fewer certain findings, never a skipped unit, and
 *   `not-applicable` (with a reason) for a question the provided code cannot
 *   answer — including when an elision marker hides the part that would.
 *
 * The prompt is assembled from parts — a system prompt, a header, one section
 * per unit, a footer — so `src/audit/batch.ts` can pack a batch by measuring the
 * real assembled text instead of estimating its size.
 */

import type { AuditUnit, Severity } from "../../contracts/findings.ts";
import type { AuditUnitKind } from "../../contracts/inventory.ts";

/** Separator between the blocks of a rendered prompt. */
export const BLOCK_SEPARATOR = "\n\n";

/**
 * The domain a dotted rule id belongs to, which is its own prefix.
 *
 * Every rule a prompt offers is named `<domain>.<what-is-wrong>`, so the domain
 * of a finding is settled by the rule the prompt told the model to use and never
 * by the model itself.
 */
export function domainOfRule(rule: string): string {
  return rule.split(".")[0] ?? "";
}

/**
 * The key a check is answered under: `<domain>.<name>`.
 *
 * Dotted and globally consistent, for two reasons. It is the `checkId` an
 * `Assurance` carries, so two kinds that assert the same thing — a route and a
 * webhook both validating their input — can be counted as one population. And it
 * lets a reply be read without knowing which kind it came from, which is what
 * the audit phase's verdict adapter does.
 */
export function checkIdOf(check: AuditCheck): string {
  return `${domainOfRule(check.rule)}.${check.name}`;
}

/**
 * One question the audit asks of a unit, and the rule a failure is filed under.
 *
 * `name` is the key the model answers under and the name an `Assurance` carries,
 * so it is stable vocabulary: renaming one changes what a passing check is
 * called in the report. `rule` is the dotted id the finding gets, which fixes
 * its domain — the decoder refuses a rule this kind never offered.
 */
export interface AuditCheck {
  /** Kebab-case name, unique within a kind; the dotted id is derived from it. */
  readonly name: string;
  /**
   * The one sentence the report prints when this check passes, in the report's
   * voice and in the positive: "objects are loaded with an ownership predicate".
   *
   * This is the assurance. "23/23 route handlers: objects are loaded with an
   * ownership predicate" is a sentence a client can act on; "23/23 idor" is not,
   * and letting a model write the sentence would make it a different sentence
   * every run.
   */
  readonly statement: string;
  /**
   * Plural noun for the population, when it is narrower than the unit kind:
   * `mutation handlers` rather than `route handlers`.
   */
  readonly subject?: string | undefined;
  /** Dotted rule id a failure is filed under, e.g. `appsec.idor`. */
  readonly rule: string;
  /** The question, phrased about the code in front of the model. */
  readonly question: string;
  /** What makes this check `fail` rather than `pass`. */
  readonly fails: string;
  /** The highest severity this rule may carry; anything above it is clamped. */
  readonly ceiling: Severity;
  /** Why the check may not apply, when there is a common reason. */
  readonly notApplicable?: string | undefined;
}

/** Everything one unit kind's prompt says that the shared scaffolding does not. */
export interface PromptSpec {
  readonly kind: AuditUnitKind;
  /** Plural noun for the units, used in the prose: "route handlers". */
  readonly noun: string;
  /** The model's job for this kind, in one or two sentences. */
  readonly mission: string;
  /** The checks, in the order the prompt lists them and the report reads them. */
  readonly checks: readonly AuditCheck[];
  /** Kind-specific reading instructions: what an attribute means, what to trust. */
  readonly guidance: readonly string[];
  /** Attribute keys worth naming in the prompt, with what each one means. */
  readonly attributes?: Readonly<Record<string, string>> | undefined;
}

/**
 * The stack facts stated as ground truth, so the model is not guessing whether
 * `createClient()` is Supabase.
 *
 * Every field is a list because a monorepo really can run Express and Next.js
 * at once, and an empty list is rendered as "not detected" rather than omitted —
 * "phase 0 found no ORM" is a fact the audit should know.
 */
export interface StackFacts {
  readonly frameworks: readonly string[];
  readonly dataLayers: readonly string[];
  readonly databases: readonly string[];
  readonly authProviders: readonly string[];
  /** Files that contain the project's own authentication check. */
  readonly authHelpers: readonly string[];
  readonly hasFrontend: boolean;
  /** True when the repository validates its environment with a schema at startup. */
  readonly validatesConfig: boolean;
  /** Anything else worth stating, e.g. "stack detection did not run". */
  readonly notes: readonly string[];
}

/** A stack with nothing proven; every prompt built from it says so out loud. */
export const UNKNOWN_STACK: StackFacts = {
  frameworks: [],
  dataLayers: [],
  databases: [],
  authProviders: [],
  authHelpers: [],
  hasFrontend: false,
  validatesConfig: false,
  notes: ["stack detection did not run: do not assume a framework, an ORM or an auth mechanism"],
};

/** A block of context the whole batch shares, already rendered. */
export interface SharedSlice {
  /** What it is, e.g. "auth helper" or "schema excerpt". */
  readonly label: string;
  /** The rendered text: a numbered source slice, or a plain-text excerpt. */
  readonly text: string;
}

/** Code that belongs to one unit without being it: the route a cron calls, for instance. */
export interface RelatedSlice {
  readonly label: string;
  /** The unit this code is, when it is itself an audited unit. */
  readonly unitId?: string | undefined;
  readonly text: string;
}

/** One unit as the prompt renders it: the facts, and the source read from disk. */
export interface PromptUnit {
  readonly unit: AuditUnit;
  /** The rendered slice — `CodeSlice.text`, with its real line numbers. */
  readonly sliceText: string;
  readonly related: readonly RelatedSlice[];
}

/** What a prompt needs that is not one of the units. */
export interface PromptContext {
  readonly stack: StackFacts;
  readonly shared: readonly SharedSlice[];
  /**
   * The batch's id, stated in the header so the reply can echo it.
   *
   * A reply that carries the id it was given is a reply that can be matched to
   * the work it was asked to do; without it, a crossed transcript or a replayed
   * answer would be filed as if it were about these units.
   */
  readonly batchId?: string | undefined;
}

/**
 * A prompt, still in pieces.
 *
 * Kept apart so a batch can be packed by assembling and measuring candidates —
 * the budget is spent on real characters, never on an estimate — and so the
 * system prompt, which is identical for every batch of a kind, can be cached by
 * the transport.
 */
export interface PromptParts {
  readonly systemPrompt: string;
  readonly header: string;
  readonly sections: readonly string[];
  readonly footer: string;
}

/** Joins the user-facing parts into the prompt exactly as it will be sent. */
export function assemblePrompt(parts: PromptParts): string {
  return [parts.header, ...parts.sections, parts.footer].join(BLOCK_SEPARATOR);
}

/** Total characters of a prompt, system prompt included, as the transport sees them. */
export function promptChars(parts: PromptParts): number {
  return parts.systemPrompt.length + assemblePrompt(parts).length;
}

/** One kind's prompt, in parts. */
export interface PromptBuilder {
  readonly kind: AuditUnitKind;
  readonly spec: PromptSpec;
  /** Constant for the kind, so the prompt cache can hold it across batches. */
  systemPrompt(): string;
  /** Stack facts, shared context, and the checks this batch must answer. */
  header(ctx: PromptContext, units: readonly PromptUnit[]): string;
  /** One unit: its id, location, attributes and source slice. */
  section(unit: PromptUnit): string;
  /** The list of ids a verdict is required for. */
  footer(units: readonly PromptUnit[]): string;
}

// ---------------------------------------------------------------------------
// The constant blocks
// ---------------------------------------------------------------------------

/** The rule the agent works under: it has no filesystem, and it never needs one. */
const CLOSED_WORLD = `You are auditing source code that is quoted IN FULL in the message you are given.
You have no filesystem, no shell and no tools. Do not ask for a file, do not
guess at one, and do not reason about code you were not shown.

Every slice is headed by \`// <file>:<start>-<end>\` and every source line is
prefixed with its REAL line number in that file. Cite those numbers verbatim.
A citation outside the slices below is discarded before it reaches the report.
A line reading \`// … N lines elided …\` means Sentinel removed N lines to fit a
budget: that code exists, you were simply not shown it.`;

/** The obligation that makes coverage provable. */
const VERDICT_OBLIGATION = `Return one verdict for EVERY unit id listed, whether or not you found anything.
For each unit, answer EVERY check under the exact key it is listed with:
  "pass"           — the control the check looks for is present in the code shown.
  "fail"           — it is absent or wrong; the verdict must carry a finding for it.
  "not-applicable" — the check cannot apply to this unit, OR the code needed to
                     answer it was not provided. Say which, in the check's note.
A unit you do not answer for is a hole in a coverage claim, not a safe omission.`;

/** The severity rubric, stated once so no kind invents its own. */
const SEVERITY_RUBRIC = `Use this severity rubric. Do not invent your own scale.
  critical — reachable by an unauthenticated caller, or lets any authenticated
             user read or change another tenant's or user's data; a credential
             that is valid as written; injection reaching a database, a shell or
             an interpreter.
  high     — needs an authenticated session but no special role, and discloses
             or destroys data, or removes the only control standing in front of
             a privileged action.
  medium   — needs a precondition the attacker does not control (a specific
             flag, a race, an administrator acting on crafted input), or a
             defect with a clear production impact that is not an access-control
             break: an N+1 on a hot path, an unbounded query, a locking
             migration, a job that can run twice.
  low      — hardening or defence in depth, with no exploit path you can state.
  info     — an observation with no exploit and no measurable impact.

Every check below states the highest severity its rule may carry. A finding
above that ceiling is lowered to it, so use the ceiling only when the rubric
above independently justifies it.

Set \`confidence\` to how sure you are that the finding is real: \`high\` when the
code shown proves it, \`medium\` when it depends on a caller you cannot see,
\`low\` when it is a suspicion. Omit it and it is read as \`medium\`.`;

/** The instruction that keeps the dossier defensible. */
const CERTAINTY = `Fewer, certain findings beat a long speculative list — but never at the cost of
skipping a unit.
- Report a finding only when the code in front of you shows it. State the
  preconditions for exploitation in \`exploitability\`: who must be authenticated,
  what flag must be on, what the caller must control.
- If answering a check would need a file you were not given, the check is
  \`not-applicable\` and its note names the file you would have needed.
- Do not conclude that a control is missing because it sits in a part of the
  function that was elided.
- Two findings that share a rule and a cause on the same unit are one finding
  with two evidence pointers.`;

/** The exact document the reply must be, with a worked example. */
const OUTPUT_CONTRACT = `Reply with ONE JSON document and nothing else — no prose before it, no commentary
after it. Shape:

{
  "batchId": "<the batch id from the BATCH line above>",
  "verdicts": [
    {
      "unitId": "<a unit id from the list, copied exactly>",
      "checks": {
        "<check-id>": "pass",
        "<check-id>": {
          "result": "pass",
          "evidence": { "file": "src/api/orders.ts", "line": 41 },
          "note": "the query is scoped by session.orgId"
        },
        "<check-id>": { "result": "not-applicable", "note": "a GET writes nothing" }
      },
      "findings": [
        {
          "rule": "<one of the rule ids listed with the checks>",
          "title": "short, specific, no severity words",
          "description": "what the code does, and why that is wrong",
          "severity": "high",
          "confidence": "high",
          "location": { "file": "src/api/orders.ts", "line": 52 },
          "evidence": [{ "file": "src/api/orders.ts", "line": 47, "note": "id read from the path" }],
          "exploitability": "any authenticated user; no flag or role required",
          "impact": "what an attacker or an operator gets out of it",
          "recommendation": "the change that fixes it, in terms of this code",
          "acceptanceCriteria": ["a verifiable statement that is false today"],
          "cwe": ["CWE-639"],
          "owasp": ["A01:2021"]
        }
      ],
      "notes": "optional: doubt, or the context you would have needed"
    }
  ]
}

A passing check with an \`evidence\` pointer becomes a published assurance —
"all 23 mutation handlers assert ownership", with the line that proves it — so
point at the line that does the work rather than at the function's first line.`;

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** Pluralises the kind's noun; every one of them takes a plain `s`. */
function plural(noun: string, count: number): string {
  return count === 1 ? noun : `${noun}s`;
}

/** Renders a list as `a, b, c`, or the fallback when it is empty. */
function listOf(values: readonly string[], fallback: string): string {
  return values.length === 0 ? fallback : values.join(", ");
}

/** The stack facts block: what phase 0 proved, stated as ground truth. */
export function renderStack(stack: StackFacts): string {
  const lines = [
    "STACK (detected by Sentinel, treat as ground truth):",
    `- framework: ${listOf(stack.frameworks, "not detected")}`,
    `- data layer: ${listOf(stack.dataLayers, "not detected")}`,
    `- database: ${listOf(stack.databases, "not detected")}`,
    `- auth: ${listOf(stack.authProviders, "not detected")}`,
    `- auth helpers: ${listOf(stack.authHelpers, "none found")}`,
    `- frontend in this repository: ${stack.hasFrontend ? "yes" : "no"}`,
    `- environment validated at startup: ${stack.validatesConfig ? "yes" : "no"}`,
  ];
  for (const note of stack.notes) lines.push(`- note: ${note}`);
  return lines.join("\n");
}

/** The checks block: every question, the key it is answered under, and its ceiling. */
export function renderChecks(spec: PromptSpec): string {
  const lines = [
    `CHECKS — answer all ${spec.checks.length} for every unit, under exactly these keys:`,
  ];
  for (const check of spec.checks) {
    lines.push(`- "${checkIdOf(check)}"  [rule: ${check.rule}, max severity: ${check.ceiling}]`);
    lines.push(`    ask: ${check.question}`);
    lines.push(`    fail when: ${check.fails}`);
    if (check.notApplicable !== undefined) {
      lines.push(`    not applicable when: ${check.notApplicable}`);
    }
    lines.push(`    a pass publishes: "${check.statement}"`);
  }
  return lines.join("\n");
}

/** The shared-context block, or a line saying there is none. */
export function renderShared(shared: readonly SharedSlice[]): string {
  if (shared.length === 0) {
    return "SHARED CONTEXT: none was available for this batch.";
  }
  const blocks = shared.map((slice) => `--- ${slice.label} ---\n${slice.text}`);
  return [
    "SHARED CONTEXT — the same for every unit below; cite it like any other slice:",
    ...blocks,
  ].join("\n");
}

/** The attribute table of one unit: what the inventory proved about it. */
export function renderAttributes(unit: AuditUnit): string {
  const keys = Object.keys(unit.attributes).sort();
  if (keys.length === 0) return "  facts: none recorded";
  const rows = keys.map((key) => `    ${key}: ${unit.attributes[key] ?? ""}`);
  return ["  facts (from Sentinel's own enumeration, not from a model):", ...rows].join("\n");
}

/** The `file:line` of a unit, in the form every citation uses. */
function locationOf(unit: AuditUnit): string {
  const { file, line, endLine } = unit.location;
  return endLine === undefined || endLine <= line
    ? `${file}:${line}`
    : `${file}:${line}-${endLine}`;
}

/** One unit's section: its identity, its facts, its related code and its source. */
export function renderUnit(entry: PromptUnit): string {
  const { unit } = entry;
  const parts = [
    `UNIT ${unit.id}`,
    `  kind: ${unit.kind}`,
    `  label: ${unit.label}`,
    `  at: ${locationOf(unit)}`,
    renderAttributes(unit),
  ];
  if (unit.location.note !== undefined) parts.push(`  note: ${unit.location.note}`);
  for (const related of entry.related) {
    const suffix = related.unitId === undefined ? "" : ` (unit ${related.unitId})`;
    parts.push(`  related — ${related.label}${suffix}:`);
    parts.push(related.text);
  }
  parts.push("  source:");
  parts.push(entry.sliceText);
  return parts.join("\n");
}

/** Builds the prompt pieces for one kind from its spec. */
export function createPromptBuilder(spec: PromptSpec): PromptBuilder {
  const rules = spec.checks.map((check) => check.rule);
  const system = [
    `You are Sentinel's ${spec.noun} auditor. ${spec.mission}`,
    CLOSED_WORLD,
    VERDICT_OBLIGATION,
    SEVERITY_RUBRIC,
    CERTAINTY,
    `Use only these rule ids: ${[...new Set(rules)].join(", ")}.`,
    OUTPUT_CONTRACT,
  ].join(BLOCK_SEPARATOR);

  return {
    kind: spec.kind,
    spec,
    systemPrompt: () => system,

    header(ctx, units) {
      const id = ctx.batchId ?? "unset";
      const blocks = [
        `BATCH ${id} — ${units.length} ${plural(spec.noun, units.length)} to audit, all of kind \`${spec.kind}\`.`,
        renderStack(ctx.stack),
        renderShared(ctx.shared),
        renderChecks(spec),
      ];
      if (spec.attributes !== undefined) {
        const rows = Object.keys(spec.attributes)
          .sort()
          .map((key) => `- ${key}: ${spec.attributes?.[key] ?? ""}`);
        blocks.push(["HOW TO READ THE FACTS ON EACH UNIT:", ...rows].join("\n"));
      }
      if (spec.guidance.length > 0) {
        blocks.push(["READING THIS KIND:", ...spec.guidance.map((line) => `- ${line}`)].join("\n"));
      }
      return blocks.join(BLOCK_SEPARATOR);
    },

    section: renderUnit,

    footer(units) {
      const ids = units.map((entry) => `- ${entry.unit.id}  (${entry.unit.label})`);
      return [
        `A VERDICT IS REQUIRED FOR ALL ${units.length} OF THESE UNIT IDS:`,
        ...ids,
        "",
        `Answer every one of the ${spec.checks.length} checks for every id above, then stop.`,
        "Reply with the JSON document only.",
      ].join("\n");
    },
  };
}
