import { describe, expect, test } from "bun:test";
import { createFileSystem } from "../ports/file-system.ts";
import {
  type MatchSpan,
  type ProvenanceResult,
  type ProvenanceVerdict,
  analyseInterpolation,
  capAt,
  createProvenanceReader,
  decideProvenance,
  gatedRule,
  isAnalysableFile,
  renderParts,
  worseClass,
} from "./_provenance.ts";

const disk = createFileSystem();

/** One file per shape the analyser has to resolve. See the fixture README. */
const FIXTURES = `${import.meta.dir}/__fixtures__/provenance`;

/** Sentinel's own intentionally vulnerable corpus, used for the reachable cases. */
const CORPUS = `${import.meta.dir}/runners/__fixtures__/rule-pack-target`;

const cache = new Map<string, string>();

async function fixture(name: string, dir = FIXTURES): Promise<string> {
  const key = `${dir}/${name}`;
  const cached = cache.get(key);
  if (cached !== undefined) return cached;
  const text = await disk.readFile(key);
  cache.set(key, text);
  return text;
}

/**
 * The span a rule would report for the call on the line holding `needle`.
 *
 * opengrep reports the whole call, but its columns are optional in SARIF, so
 * `columns: false` reproduces the minimum a producer can emit -- a start line
 * and nothing else.
 */
function spanOf(
  text: string,
  needle: string,
  options: { occurrence?: number; columns?: boolean } = {},
): MatchSpan {
  const lines = text.split("\n");
  let remaining = options.occurrence ?? 1;
  const index = lines.findIndex((line) => line.includes(needle) && --remaining === 0);
  if (index === -1) throw new Error(`the fixture has no line containing ${needle}`);
  const line = lines[index] ?? "";
  if (options.columns === false) {
    return { startLine: index + 1, startColumn: null, endLine: null, endColumn: null };
  }
  return {
    startLine: index + 1,
    startColumn: line.indexOf(needle) + 1,
    endLine: null,
    endColumn: null,
  };
}

/** Analyses one fixture and fails the test if the module refused to answer. */
function verdictOf(result: ProvenanceResult): ProvenanceVerdict {
  if (!result.analysed) throw new Error(`expected an answer, got: ${result.reason}`);
  return result;
}

interface AnalyseOptions {
  readonly occurrence?: number;
  readonly columns?: boolean;
  readonly scope?: "statement" | "arguments";
  readonly dir?: string;
}

async function analyse(
  name: string,
  needle: string,
  options: AnalyseOptions = {},
): Promise<ProvenanceResult> {
  const dir = options.dir ?? FIXTURES;
  const text = await fixture(name, dir);
  return analyseInterpolation(
    { file: name, text },
    spanOf(text, needle, {
      ...(options.occurrence === undefined ? {} : { occurrence: options.occurrence }),
      ...(options.columns === undefined ? {} : { columns: options.columns }),
    }),
    options.scope ?? "statement",
  );
}

/** What the SQL rule declares, which is the base every decision starts from. */
const SQL_BASE = { severity: "critical", confidence: "medium" } as const;

describe("provably closed provenance", () => {
  test("a `for...of` over a local array literal is a closed set of literals", async () => {
    const verdict = verdictOf(
      await analyse("add-bike-model-code.migration.ts", "queryRunner.query"),
    );

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts).toHaveLength(1);
    expect(verdict.parts[0]?.text).toBe("code");
    expect(verdict.parts[0]?.kind).toBe("loop-literal");
    expect(verdict.parts[0]?.why).toContain('array literal `addedModelCodes = ["cargo-trike"]`');
  });

  test("both sinks of that loop share one signature, so they are one finding", async () => {
    const first = verdictOf(await analyse("add-bike-model-code.migration.ts", "queryRunner.query"));
    const second = verdictOf(
      await analyse("add-bike-model-code.migration.ts", "queryRunner.query", { occurrence: 2 }),
    );

    expect(second.signature).toBe(first.signature);
    expect(first.context.symbol).toBe("up");
  });

  test("a module constant bound to a string literal is folded and named", async () => {
    const verdict = verdictOf(
      await analyse("record-ride-change.migration.ts", "queryRunner.query"),
    );

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts.map((part) => part.text)).toEqual(["table"]);
    expect(verdict.parts[0]?.kind).toBe("constant");
    expect(verdict.parts[0]?.why).toContain('module constant `table = "ride_journal"`');
    expect(verdict.parts[0]?.why).toContain("declared on line 17");
    expect(verdict.parts[0]?.why).toContain("never reassigned");
  });

  test("a parameter typed `(typeof X)[number]` over an `as const` array cannot escape it", async () => {
    const verdict = verdictOf(await analyse("normalize-labels.handler.ts", "SELECT id FROM"));

    expect(verdict.klass).toBe("closed");
    const byText = new Map(verdict.parts.map((part) => [part.text, part]));
    expect(byText.get("table")?.kind).toBe("closed-union");
    expect(byText.get("table")?.why).toContain("5 literals of the `as const` array `LABEL_TABLES`");
    expect(byText.get("table")?.via).toContain("the type alias `LabelTable`");
    // The template constant beside it resolves too, with no interpolation of its own.
    expect(byText.get("MESSY_LABELS")?.kind).toBe("constant");
  });

  test("one identifier interpolated twice in one statement is one part", async () => {
    const verdict = verdictOf(await analyse("normalize-labels.handler.ts", "UPDATE"));

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts.map((part) => part.text)).toEqual(["table"]);
    expect(verdict.context.symbol).toBe("runBatch");
  });

  test("`.map(...).join(...)` over an `as const` tuple is a fixed compile-time set", async () => {
    const verdict = verdictOf(
      await analyse("station-profile.service.ts", "INSERT INTO station_profiles"),
    );

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts.map((part) => part.text).sort()).toEqual(["changedClause", "setClause"]);
    for (const part of verdict.parts) {
      expect(part.kind).toBe("frozen-tuple");
      expect(part.why).toContain("`as const` tuple `PROFILE_COLUMNS =");
    }
  });

  test("a lookup table indexed by request input is the table's values, not the request", async () => {
    const verdict = verdictOf(
      await analyse("injection.js", 'path.join("/srv", name)', {
        dir: CORPUS,
        scope: "arguments",
      }),
    );

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts.map((part) => part.text)).toEqual(["name"]);
  });

  test("the verdict does not depend on the producer emitting columns", async () => {
    const withColumns = verdictOf(
      await analyse("record-ride-change.migration.ts", "queryRunner.query"),
    );
    const withoutColumns = verdictOf(
      await analyse("record-ride-change.migration.ts", "queryRunner.query", { columns: false }),
    );

    expect(withoutColumns.klass).toBe(withColumns.klass);
    expect(withoutColumns.signature).toBe(withColumns.signature);
  });
});

describe("deploy-time configuration", () => {
  test("a local helper's returned template is inlined and its env field named", async () => {
    const verdict = verdictOf(
      await analyse("notify-dock-change.migration.ts", "CREATE OR REPLACE"),
    );

    expect(verdict.klass).toBe("config");
    expect(verdict.parts.map((part) => part.text)).toEqual(["getNotifyCall()"]);
    expect(verdict.parts[0]?.via).toContain("the local helper `getNotifyCall()`");
    expect(verdict.parts[0]?.why).toContain("config.DOCK_EVENT_CHANNEL");
    expect(verdict.parts[0]?.why).toContain("@fleet/config");
  });

  test("fields of an imported configuration module are not caller input", async () => {
    const verdict = verdictOf(await analyse("stale-queue-reaper.worker.ts", "WITH stale AS"));

    expect(verdict.klass).toBe("config");
    expect(verdict.parts).toHaveLength(2);
    for (const part of verdict.parts) {
      expect(part.kind).toBe("config");
      expect(part.why).toContain("deploy-time configuration");
    }
  });
});

describe("provably attacker-reachable", () => {
  test("a handler's request field reaching a helper's parameter in the same file", async () => {
    const verdict = verdictOf(await analyse("ride-search.ts", "ORDER BY ${sort}"));

    expect(verdict.klass).toBe("reachable");
    expect(verdict.parts[0]?.kind).toBe("request-input");
    expect(verdict.parts[0]?.via?.[0]).toContain("fed by the one call site in this file");
    expect(verdict.parts[0]?.why).toContain("req.query.sort");
  });

  test("the same file's closed sibling is not dragged along", async () => {
    const verdict = verdictOf(await analyse("ride-search.ts", "ORDER BY ${column}"));

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts[0]?.why).toContain("2 literals of the `as const` array `ALLOWED_SORTS`");
  });

  test("a request field interpolated directly is reachable without a call hop", async () => {
    const text = [
      "app.get('/s', async (req, res) => {",
      "  res.json(await db.query(`SELECT * FROM t ORDER BY ${req.query.sort}`))",
      "})",
    ].join("\n");
    const verdict = verdictOf(
      analyseInterpolation({ file: "route.ts", text }, spanOf(text, "db.query")),
    );

    expect(verdict.klass).toBe("reachable");
    expect(verdict.context.kind).toBe("request-handler");
  });

  test("a path built from a request field keeps its severity", async () => {
    const verdict = verdictOf(
      await analyse("injection.js", 'path.join("/srv/uploads"', {
        dir: CORPUS,
        scope: "arguments",
      }),
    );

    expect(verdict.klass).toBe("reachable");
    const decision = decideProvenance(
      { severity: "high", confidence: "high" },
      verdict,
      "filesystem path",
    );
    expect(decision.severity).toBe("high");
    expect(decision.confidence).toBe("high");
    expect(decision.suppressed).toBe(false);
  });
});

describe("unresolved provenance", () => {
  test("an exported function's parameter stays unresolved, whatever this file passes", async () => {
    const verdict = verdictOf(
      await analyse("injection.js", "SELECT * FROM users WHERE email", { dir: CORPUS }),
    );

    expect(verdict.klass).toBe("unresolved");
    expect(verdict.parts[0]?.kind).toBe("parameter");
    expect(verdict.parts[0]?.why).toContain("whose callers this file does not show");
  });

  test("a literal call site does not close an exported function's parameter", () => {
    const text = [
      "export async function findUser(db, email) {",
      "  return db.query(`SELECT * FROM u WHERE e = '${email}'`)",
      "}",
      "findUser(db, 'a@b.c')",
    ].join("\n");
    const verdict = verdictOf(
      analyseInterpolation({ file: "users.ts", text }, spanOf(text, "db.query")),
    );

    expect(verdict.klass).toBe("unresolved");
  });

  test("a non-exported function's only call site does close its parameter", () => {
    const text = [
      "const TABLES = ['users', 'orders']",
      "function count(db, table) {",
      "  return db.query(`SELECT count(*) FROM ${table}`)",
      "}",
      "export const all = (db) => TABLES.map((t) => count(db, t))",
    ].join("\n");
    const verdict = verdictOf(
      analyseInterpolation({ file: "count.ts", text }, spanOf(text, "db.query")),
    );

    expect(verdict.klass).toBe("closed");
    expect(verdict.parts[0]?.via?.[0]).toContain("fed by the one call site in this file");
  });
});

describe("what the module refuses to answer", () => {
  test("a file it cannot parse", () => {
    const result = analyseInterpolation(
      { file: "query.py", text: 'cursor.execute(f"select {table}")' },
      { startLine: 1, startColumn: 1, endLine: null, endColumn: null },
    );

    expect(result.analysed).toBe(false);
    if (!result.analysed) expect(result.reason).toContain("not JavaScript or TypeScript");
  });

  test("a match that does not sit on a call", () => {
    const result = analyseInterpolation(
      { file: "a.ts", text: "const sql = `select ${table}`\n" },
      { startLine: 1, startColumn: 1, endLine: null, endColumn: null },
    );

    expect(result.analysed).toBe(false);
    if (!result.analysed) expect(result.reason).toContain("does not sit on a call");
  });

  test("a method chain gives every call the same start, so the span's end decides", () => {
    // Three calls that all begin at `appClient`, so a producer that reports the
    // chain gives each of them the same start line and column.
    const lines = [
      "const otherRes = await appClient",
      "  .get('/v1/stations/docks')",
      "  .query(`riderIds[0]=${other.id}`)",
      "  .set({ 'x-fleet-operator-id': `${operator.id}` })",
    ];
    const text = lines.join("\n");
    const verdict = verdictOf(
      analyseInterpolation(
        { file: "docks.test.ts", text },
        {
          startLine: 1,
          startColumn: (lines[0] ?? "").indexOf("appClient") + 1,
          endLine: 3,
          endColumn: (lines[2] ?? "").length + 1,
        },
      ),
    );

    // `.query(...)`, not the `.get(...)` inside it or the `.set(...)` around it.
    expect(verdict.parts.map((part) => part.text)).toEqual(["other.id"]);
  });

  test("bound values are not evidence of danger: only the statement is read", () => {
    const text = "db.query(`SELECT * FROM users WHERE email = $1`, [req.query.email])\n";
    const result = analyseInterpolation({ file: "a.ts", text }, spanOf(text, "db.query"));

    expect(result.analysed).toBe(false);
    if (!result.analysed) expect(result.reason).toContain("literals only");
  });

  test("a file too large to be hand-written code", () => {
    const result = analyseInterpolation(
      { file: "bundle.js", text: `//${"x".repeat(2_000_001)}` },
      { startLine: 1, startColumn: 1, endLine: null, endColumn: null },
    );

    expect(result.analysed).toBe(false);
    if (!result.analysed) expect(result.reason).toContain("too large");
  });

  test("an unresolvable expression is unresolved, never assumed safe", () => {
    const text = "db.query(`SELECT * FROM ${globalThis.__table}`)\n";
    const verdict = verdictOf(
      analyseInterpolation({ file: "a.ts", text }, spanOf(text, "db.query")),
    );

    expect(verdict.klass).toBe("unresolved");
  });
});

describe("the severity policy", () => {
  test("P1 -- a closed verdict is information with the provenance named, not a vulnerability", async () => {
    const verdict = verdictOf(
      await analyse("record-ride-change.migration.ts", "queryRunner.query"),
    );
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(decision.severity).toBe("info");
    expect(decision.confidence).toBe("high");
    expect(decision.suppressed).toBe(true);
    expect(decision.titlePrefix).toBe("Not injectable: ");
    expect(decision.rationale).toContain("(P1)");
    expect(decision.rationale).toContain("ride_journal");
    expect(decision.impact).toContain("None as written");
    expect(decision.acceptanceCriteria?.[0]).toContain("No change is required");
    expect(decision.acceptanceCriteria?.[1]).toContain("returns as a vulnerability");
  });

  test("P2 -- configuration is capped at low and says who can change it", async () => {
    const verdict = verdictOf(await analyse("stale-queue-reaper.worker.ts", "WITH stale AS"));
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(decision.severity).toBe("low");
    expect(decision.confidence).toBe("low");
    expect(decision.rationale).toContain("(P2)");
    expect(decision.exploitability).toContain("Not reachable from a request");
    expect(decision.acceptanceCriteria?.[0]).toContain("quote_literal");
  });

  test("P3 -- an unresolved verdict is a lead at medium, not a critical", async () => {
    const verdict = verdictOf(
      await analyse("injection.js", "SELECT * FROM users WHERE email", { dir: CORPUS }),
    );
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(decision.severity).toBe("medium");
    expect(decision.confidence).toBe("low");
    expect(decision.rationale).toContain("(P3)");
    expect(decision.exploitability).toContain("Reachability was not established");
    // The rule's own acceptance criteria stand: the fix is still to bind the value.
    expect(decision.acceptanceCriteria).toBeNull();
  });

  test("P4 -- a reachable verdict keeps the rule's severity and gains confidence", async () => {
    const verdict = verdictOf(await analyse("ride-search.ts", "ORDER BY ${sort}"));
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(decision.severity).toBe("critical");
    expect(decision.confidence).toBe("high");
    expect(decision.rationale).toContain("(P4)");
    expect(decision.titlePrefix).toBe("");
  });

  test("P5 -- an unresolved value in a migration's `up()` is capped at low", () => {
    const text = [
      "export class Backfill implements MigrationInterface {",
      "  public async up(queryRunner: QueryRunner, tenant: string): Promise<void> {",
      "    await queryRunner.query(`DELETE FROM audit WHERE tenant = '${tenant}'`)",
      "  }",
      "}",
    ].join("\n");
    const verdict = verdictOf(
      analyseInterpolation({ file: "m.ts", text }, spanOf(text, "queryRunner.query")),
    );
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(verdict.klass).toBe("unresolved");
    expect(verdict.context.kind).toBe("migration-up");
    expect(decision.severity).toBe("low");
    expect(decision.rationale).toContain("(P3)");
    expect(decision.rationale).toContain("(P5)");
    expect(decision.rationale).toContain("MigrationInterface");
  });

  test("P5 -- `down()` is a manual rollback, so it sits below the same code in `up()`", async () => {
    const text = await fixture("record-ride-change.migration.ts");
    const reader = createProvenanceReader();
    const up = verdictOf(
      reader.analyse({ file: "m.ts", text }, spanOf(text, "queryRunner.query"), "statement"),
    );
    const down = verdictOf(
      reader.analyse(
        { file: "m.ts", text },
        spanOf(text, "queryRunner.query", { occurrence: 2 }),
        "statement",
      ),
    );

    expect(up.context.kind).toBe("migration-up");
    expect(down.context.kind).toBe("migration-down");
    expect(down.context.detail).toContain("explicit manual revert");
  });

  test("a migration that only interpolates configuration is low, not critical", async () => {
    const verdict = verdictOf(
      await analyse("notify-dock-change.migration.ts", "CREATE OR REPLACE"),
    );
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(verdict.context.kind).toBe("migration-up");
    expect(decision.severity).toBe("low");
    expect(decision.rationale).toContain("(P2)");
  });

  test("P5 never lowers a verdict that traces to request input", () => {
    const text = [
      "export class Repair implements MigrationInterface {",
      "  public async up(queryRunner: QueryRunner, req) {",
      "    await queryRunner.query(`DELETE FROM t WHERE id = ${req.query.id}`)",
      "  }",
      "}",
    ].join("\n");
    const verdict = verdictOf(
      analyseInterpolation({ file: "m.ts", text }, spanOf(text, "queryRunner.query")),
    );
    const decision = decideProvenance(SQL_BASE, verdict, "SQL statement");

    expect(verdict.klass).toBe("reachable");
    expect(verdict.context.kind).toBe("migration-up");
    expect(decision.severity).toBe("critical");
  });

  test("the policy only ever lowers what the rule declared", async () => {
    const verdict = verdictOf(await analyse("ride-search.ts", "ORDER BY ${sort}"));
    const decision = decideProvenance({ severity: "low", confidence: "medium" }, verdict);

    expect(decision.severity).toBe("low");
  });
});

describe("the pieces the runner depends on", () => {
  test("every gated rule is one whose match proves interpolation, not control", () => {
    expect(gatedRule("appsec.injection.sql-built-from-variables")?.scope).toBe("statement");
    expect(gatedRule("appsec.injection.raw-query-unsafe")?.scope).toBe("statement");
    expect(gatedRule("appsec.injection.command-interpolation")?.subject).toBe("shell command");
    // The path rule matches the request field itself, so every argument counts.
    expect(gatedRule("appsec.injection.path-from-request-input")?.scope).toBe("arguments");
    // A rule that matches an operator rather than a value is not graded here.
    expect(gatedRule("appsec.injection.nosql-where-operator")).toBeNull();
    expect(gatedRule("appsec.xss.inner-html-assignment")).toBeNull();
  });

  test("only JavaScript and TypeScript files are analysable", () => {
    expect(isAnalysableFile("a/b/c.ts")).toBe(true);
    expect(isAnalysableFile("a/b/c.tsx")).toBe(true);
    expect(isAnalysableFile("a/b/c.mjs")).toBe(true);
    expect(isAnalysableFile("a/b/c.py")).toBe(false);
    expect(isAnalysableFile("Makefile")).toBe(false);
  });

  test("the worst verdict of a statement decides it", () => {
    expect(worseClass("closed", "config")).toBe("config");
    expect(worseClass("reachable", "unresolved")).toBe("reachable");
    expect(worseClass("closed", "closed")).toBe("closed");
  });

  test("a cap lowers and never raises", () => {
    expect(capAt("critical", "low")).toBe("low");
    expect(capAt("info", "low")).toBe("info");
    expect(capAt("medium", "medium")).toBe("medium");
  });

  test("the rendered sentence names the expression, the line and the declaration", async () => {
    const verdict = verdictOf(
      await analyse("record-ride-change.migration.ts", "queryRunner.query"),
    );
    const rendered = renderParts(verdict.parts);

    expect(rendered).toContain("`table`");
    expect(rendered).toContain(`line ${verdict.parts[0]?.line}`);
    expect(rendered).toContain("resolves to");
  });

  test("the reader answers the same as a one-off parse", async () => {
    const text = await fixture("add-bike-model-code.migration.ts");
    const reader = createProvenanceReader();
    const first = reader.analyse(
      { file: "m.ts", text },
      spanOf(text, "queryRunner.query"),
      "statement",
    );
    const second = reader.analyse(
      { file: "m.ts", text },
      spanOf(text, "queryRunner.query", { occurrence: 2 }),
      "statement",
    );
    const fresh = analyseInterpolation(
      { file: "m.ts", text },
      spanOf(text, "queryRunner.query", { occurrence: 2 }),
    );

    expect(verdictOf(first).klass).toBe("closed");
    expect(verdictOf(second)).toEqual(verdictOf(fresh));
  });
});
