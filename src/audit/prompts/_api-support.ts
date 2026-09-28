/**
 * The endpoint matrix — D6's one *output*, as opposed to its findings.
 *
 * `PLAN.md` promises `endpoint-matrix.md`: every route with its method, path,
 * auth requirement, input validation, pagination and rate limit, and it says
 * that the gaps in that table *are* the findings. So the table and the checks
 * cannot be two lists. {@link MATRIX_COLUMNS} names, for each column, the check
 * whose answer fills it, and `api.test.ts` fails if `api.ts` stops asking one of
 * them — which is the only thing that keeps a column from silently becoming a
 * column of blanks.
 *
 * The rule the whole project turns on applies to a cell as much as to a score:
 * **a cell with no verdict reads `not audited`, never `no`.** A route the audit
 * never reached must not appear in a published table as a route that failed a
 * check, and a route whose check came back `not-applicable` must not appear as
 * one that passed. That is why {@link MatrixState} has four values and not two,
 * and why the enumerator's own facts — `validation: none`, `pagination: limit` —
 * are rendered with an `enumerated:` prefix rather than as an answer. Phase 2's
 * pattern matching is a reason to look; it is not a verdict, and it is wrong about
 * validation on every route of any codebase that validates through a helper of its
 * own rather than through a bare `.parse(` call.
 *
 * Nothing here reads a file or calls a model: it is a pure projection of the
 * inventory's units and the decoder's verdicts, so the report can render the
 * table and the CLI can count it without either one re-deriving the columns.
 */

import { z } from "zod";
import type { AuditUnit } from "../../contracts/findings.ts";
import { groupThousands } from "../../contracts/inventory.ts";
import { truncate } from "../../verify/text.ts";

/** File name of the endpoint matrix inside a run directory, as `PLAN.md` names it. */
export const ENDPOINT_MATRIX_FILE = "endpoint-matrix.md";

/** Longest cell detail the table carries; the rest is cut with an ellipsis. */
const MAX_DETAIL = 90;

/**
 * What one cell of the matrix can say.
 *
 * `not-audited` is the value this type exists for. A bounded run that reached most
 * of a repository's routes and not the rest leaves those rows' cells unknown, and
 * printing them as `no` would be Sentinel reporting a gap it never established —
 * the one bug this project cannot ship.
 */
export const MATRIX_STATES = ["yes", "no", "not-applicable", "not-audited"] as const;

/** One of {@link MATRIX_STATES}. */
export type MatrixState = (typeof MATRIX_STATES)[number];

/** Validates a matrix state read back from an artifact. */
export const MatrixStateSchema = z.enum(MATRIX_STATES);

/** The words the table prints for each state; `not-audited` is spelled out. */
const STATE_LABEL: Readonly<Record<MatrixState, string>> = {
  yes: "yes",
  no: "no",
  "not-applicable": "n/a",
  "not-audited": "not audited",
};

/** One cell: the answer, and the sentence that justifies it. */
export const MatrixCellSchema = z.object({
  state: MatrixStateSchema,
  /**
   * The model's note for the check, or the enumerator's fact prefixed with
   * `enumerated:` when there is no verdict — so a reader can always tell a
   * decision from a pattern match.
   */
  detail: z.string().default(""),
});
/** One cell of the endpoint matrix; see {@link MatrixCellSchema}. */
export type MatrixCell = z.infer<typeof MatrixCellSchema>;

/** One row: an endpoint, and the four columns `PLAN.md` asks for. */
export const EndpointMatrixRowSchema = z.object({
  unitId: z.string(),
  /** HTTP method as the inventory recorded it, or `ANY`. */
  method: z.string(),
  /** Resolved request path, or `unresolved` when phase 2 could not compose it. */
  path: z.string(),
  file: z.string(),
  line: z.number().int().positive(),
  auth: MatrixCellSchema,
  validation: MatrixCellSchema,
  pagination: MatrixCellSchema,
  rateLimit: MatrixCellSchema,
});
/** One row of the endpoint matrix; see {@link EndpointMatrixRowSchema}. */
export type EndpointMatrixRow = z.infer<typeof EndpointMatrixRowSchema>;

/** The row fields that hold a cell, which is what a summary iterates. */
export const MATRIX_CELL_KEYS = ["auth", "validation", "pagination", "rateLimit"] as const;

/** One of {@link MATRIX_CELL_KEYS}. */
export type MatrixCellKey = (typeof MATRIX_CELL_KEYS)[number];

/**
 * Each column, the check that answers it, and the enumerated fact that stands in
 * when no verdict does.
 *
 * This is the join between the prompt and the table. `checkId` must be one of
 * the ids `api.ts` demands an answer under, and `attribute` must be a key the
 * route enumerator really attaches — both asserted in `api.test.ts` against the
 * spec and against a unit shaped the way the inventory writes one.
 */
export const MATRIX_COLUMNS: readonly {
  readonly key: MatrixCellKey;
  /** Column heading, as the Markdown table prints it. */
  readonly heading: string;
  /** The dotted check id whose result fills this column. */
  readonly checkId: string;
  /** The unit attribute quoted when there is no verdict, if any. */
  readonly attribute?: string | undefined;
}[] = [
  { key: "auth", heading: "Auth", checkId: "api.auth-requirement", attribute: "authCheck" },
  {
    key: "validation",
    heading: "Validated",
    checkId: "api.input-validation",
    attribute: "validation",
  },
  {
    key: "pagination",
    heading: "Paginated",
    checkId: "api.pagination",
    attribute: "pagination",
  },
  { key: "rateLimit", heading: "Rate limited", checkId: "appsec.rate-limit" },
];

/** The check ids the matrix is built from, in column order. */
export const MATRIX_CHECK_IDS: readonly string[] = MATRIX_COLUMNS.map((column) => column.checkId);

/**
 * One check's answer, as little of it as the matrix needs.
 *
 * Structural on purpose: `DecodedCheck` from `src/audit/verdict.ts` satisfies it,
 * and depending on that module from inside `prompts/` would close a cycle —
 * `verdict.ts` already imports the prompt registry to find out which checks a
 * kind demanded.
 */
export interface MatrixCheckAnswer {
  readonly checkId: string;
  /** The decoder's `CheckResult`, which this union mirrors structurally. */
  readonly result: "pass" | "fail" | "not-applicable";
  readonly note?: string | undefined;
}

/** One unit's answers, as little of a `DecodedVerdict` as the matrix needs. */
export interface MatrixVerdict {
  readonly unitId: string;
  readonly checks: readonly MatrixCheckAnswer[];
}

/** The state a check result maps to; an unanswered check is not a `no`. */
function stateOf(result: MatrixCheckAnswer["result"]): MatrixState {
  if (result === "pass") return "yes";
  if (result === "fail") return "no";
  return "not-applicable";
}

/** Flattens a note onto one line and keeps a Markdown table from breaking. */
function oneLine(text: string): string {
  return text.replace(/\s+/g, " ").replace(/\|/g, "\\|").trim();
}

/** The cell's justification: the model's note, or the enumerator's fact, labelled. */
function detailOf(note: string | undefined, enumerated: string | undefined): string {
  const fromModel = note === undefined ? "" : oneLine(note);
  if (fromModel !== "") return truncate(fromModel, MAX_DETAIL);
  const fact = enumerated === undefined ? "" : oneLine(enumerated);
  if (fact === "") return "";
  return `enumerated: ${truncate(fact, MAX_DETAIL)}`;
}

/** The one cell a column gets for a unit, from its answer or from silence. */
function cellFor(
  unit: AuditUnit,
  answers: ReadonlyMap<string, MatrixCheckAnswer>,
  column: (typeof MATRIX_COLUMNS)[number],
): MatrixCell {
  const enumerated = column.attribute === undefined ? undefined : unit.attributes[column.attribute];
  const answer = answers.get(column.checkId);
  if (answer === undefined) {
    return MatrixCellSchema.parse({
      state: "not-audited",
      detail: detailOf(undefined, enumerated),
    });
  }
  return MatrixCellSchema.parse({
    state: stateOf(answer.result),
    detail: detailOf(answer.note, enumerated),
  });
}

/** The key rows are ordered by: path, then method, then location. */
function sortKey(row: EndpointMatrixRow): string {
  return `${row.path}\u0000${row.method}\u0000${row.file}\u0000${String(row.line).padStart(8, "0")}`;
}

/**
 * Code-unit comparison, deliberately not `localeCompare`.
 *
 * Every artifact this project writes has to be byte-identical between two runs
 * over unchanged code, and `localeCompare` makes the order a property of the
 * machine: it ignores the leading `/` of a path, so `/api-docs` sorts before `/`
 * under one ICU build and after it under another.
 */
function compareText(left: string, right: string): number {
  if (left < right) return -1;
  return left > right ? 1 : 0;
}

/**
 * The endpoint matrix for a run: one row per route unit, audited or not.
 *
 * Every route in the inventory gets a row, including the ones no batch reached,
 * because a table that lists only the audited routes is a table that hides the
 * coverage gap it was supposed to expose. The rows are sorted by path, then
 * method, then location, so two runs over unchanged code produce identical
 * bytes.
 */
export function buildEndpointMatrix(
  units: readonly AuditUnit[],
  verdicts: readonly MatrixVerdict[],
): EndpointMatrixRow[] {
  const byUnit = new Map<string, ReadonlyMap<string, MatrixCheckAnswer>>();
  for (const verdict of verdicts) {
    const answers = new Map<string, MatrixCheckAnswer>();
    for (const check of verdict.checks) {
      // First answer wins, matching the decoder's own duplicate handling.
      if (!answers.has(check.checkId)) answers.set(check.checkId, check);
    }
    const existing = byUnit.get(verdict.unitId);
    if (existing === undefined) {
      byUnit.set(verdict.unitId, answers);
      continue;
    }
    const merged = new Map(existing);
    for (const [id, check] of answers) if (!merged.has(id)) merged.set(id, check);
    byUnit.set(verdict.unitId, merged);
  }

  const empty: ReadonlyMap<string, MatrixCheckAnswer> = new Map();
  const rows = units
    .filter((unit) => unit.kind === "route")
    .map((unit) => {
      const answers = byUnit.get(unit.id) ?? empty;
      const cells = {} as Record<MatrixCellKey, MatrixCell>;
      for (const column of MATRIX_COLUMNS) cells[column.key] = cellFor(unit, answers, column);
      return EndpointMatrixRowSchema.parse({
        unitId: unit.id,
        method: unit.attributes.method ?? "ANY",
        path: unit.attributes.path ?? "unresolved",
        file: unit.location.file,
        line: unit.location.line,
        ...cells,
      });
    });
  return rows.sort((left, right) => compareText(sortKey(left), sortKey(right)));
}

/** How one column came out across every row; every state present, at zero. */
export interface MatrixColumnSummary {
  readonly key: MatrixCellKey;
  readonly heading: string;
  readonly counts: Readonly<Record<MatrixState, number>>;
}

/** A zeroed counter for every state, so a summary line never omits one. */
function emptyStateCounts(): Record<MatrixState, number> {
  const counts = {} as Record<MatrixState, number>;
  for (const state of MATRIX_STATES) counts[state] = 0;
  return counts;
}

/** Counts each column's answers, in column order, for the one-line summary. */
export function summariseEndpointMatrix(rows: readonly EndpointMatrixRow[]): MatrixColumnSummary[] {
  return MATRIX_COLUMNS.map((column) => {
    const counts = emptyStateCounts();
    for (const row of rows) counts[row[column.key].state] += 1;
    return { key: column.key, heading: column.heading, counts };
  });
}

/** `Validated: 288 yes, 12 no, 16 not audited` — zero states left out. */
export function formatColumnSummary(summary: MatrixColumnSummary): string {
  const parts = MATRIX_STATES.filter((state) => summary.counts[state] > 0).map(
    (state) => `${groupThousands(summary.counts[state])} ${STATE_LABEL[state]}`,
  );
  return `${summary.heading}: ${parts.length === 0 ? "no rows" : parts.join(", ")}`;
}

/** One cell as the table prints it: the answer, then what justifies it. */
function renderCell(cell: MatrixCell): string {
  const label = STATE_LABEL[cell.state];
  return cell.detail === "" ? label : `${label} — ${cell.detail}`;
}

/**
 * The matrix as `endpoint-matrix.md`.
 *
 * The preamble is not decoration: it states how many routes the table covers and
 * what `not audited` means, so the table cannot be quoted out of a run and read
 * as a clean bill of health for the rows nobody checked.
 */
export function renderEndpointMatrix(rows: readonly EndpointMatrixRow[]): string {
  const headings = [
    "Method",
    "Path",
    ...MATRIX_COLUMNS.map((column) => column.heading),
    "Declared at",
  ];
  const lines = [
    "# Endpoint matrix",
    "",
    `${groupThousands(rows.length)} route ${rows.length === 1 ? "handler" : "handlers"} enumerated by Sentinel.`,
    "",
    "A cell reads `not audited` when no verdict answered its check in this run. It is",
    "never rendered as `no`, because nobody asked: a gap in coverage and a gap in the",
    "code are different sentences. `n/a` is an answer — the check does not apply to",
    "this endpoint — and `enumerated:` marks a fact from Sentinel's own pattern",
    "matching rather than a decision about the code.",
    "",
  ];
  for (const summary of summariseEndpointMatrix(rows))
    lines.push(`- ${formatColumnSummary(summary)}`);
  lines.push("");
  lines.push(`| ${headings.join(" | ")} |`);
  lines.push(`|${headings.map(() => "---").join("|")}|`);
  for (const row of rows) {
    const cells = [
      row.method,
      `\`${oneLine(row.path)}\``,
      ...MATRIX_COLUMNS.map((column) => renderCell(row[column.key])),
      `${oneLine(row.file)}:${row.line}`,
    ];
    lines.push(`| ${cells.join(" | ")} |`);
  }
  return `${lines.join("\n")}\n`;
}
