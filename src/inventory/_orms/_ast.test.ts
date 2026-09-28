import { describe, expect, test } from "bun:test";
import {
  AST_LANGUAGES,
  type AstProcessExecutor,
  type AstRule,
  astGrepArgs,
  contains,
  parseMatchLine,
  parseMatchStream,
  renderInlineRules,
  runAstGrep,
} from "./_ast.ts";

const RULE: AstRule = {
  id: "a:drizzle.builder",
  rule: { pattern: "$DB.select($$$ARGS)" },
  constraints: { DB: { regex: "^db$" } },
};

/** One real `--json=stream` record, captured from ast-grep 0.45.3. */
const RECORD = JSON.stringify({
  text: "db.select()",
  range: {
    byteOffset: { start: 197, end: 208 },
    start: { line: 5, column: 21 },
    end: { line: 5, column: 32 },
  },
  file: "src/services/bookings.ts",
  lines: "  const rows = await db.select().from(bookings);",
  charCount: { leading: 21, trailing: 68 },
  language: "TypeScript",
  metaVariables: {
    single: { DB: { text: "db", range: { byteOffset: { start: 197, end: 199 } } } },
    multi: { ARGS: [{ text: "{ id: users.id }" }] },
    transformed: {},
  },
  ruleId: "a:drizzle.builder",
  severity: "info",
  note: null,
  message: "",
  labels: [],
});

/** An executor that returns a scripted result without spawning anything. */
function executor(result: Partial<Awaited<ReturnType<AstProcessExecutor["run"]>>>) {
  const calls: Array<{ command: string; args: readonly string[] }> = [];
  const exec: AstProcessExecutor = {
    async run(command, args = []) {
      calls.push({ command, args });
      return {
        exitCode: result.exitCode ?? 0,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        timedOut: result.timedOut ?? false,
        truncated: result.truncated ?? false,
        notFound: result.notFound ?? false,
      };
    },
  };
  return { exec, calls };
}

/** A context whose tool resolution a test decides. */
function context(binary: string | null, result: Parameters<typeof executor>[0] = {}) {
  const { exec, calls } = executor(result);
  return {
    ctx: { exec, tools: { resolve: async () => binary }, targetDir: "/target" },
    calls,
  };
}

describe("renderInlineRules", () => {
  test("emits one document per grammar, because they are separate parsers", () => {
    const document = renderInlineRules([RULE]);
    expect(document.split("\n---\n")).toHaveLength(AST_LANGUAGES.length);
    for (const language of AST_LANGUAGES) expect(document).toContain(`"language":"${language}"`);
  });

  test("a pattern with quotes and dollars needs no escaping, because JSON is YAML", () => {
    const document = renderInlineRules([
      { id: "x", rule: { pattern: '$C.from("t")' }, languages: ["TypeScript"] },
    ]);
    expect(JSON.parse(document)).toEqual({
      id: "x",
      language: "TypeScript",
      severity: "info",
      rule: { pattern: '$C.from("t")' },
    });
  });

  test("constraints travel next to the rule, not inside it", () => {
    const parsed = JSON.parse(
      renderInlineRules([{ ...RULE, languages: ["TypeScript"] }]),
    ) as Record<string, unknown>;
    expect(parsed.constraints).toEqual({ DB: { regex: "^db$" } });
  });
});

describe("astGrepArgs", () => {
  test("excludes what is never first-party and scans the whole target", () => {
    const args = astGrepArgs("<rules>");
    expect(args.slice(0, 4)).toEqual(["scan", "--inline-rules", "<rules>", "--json=stream"]);
    expect(args).toContain("!**/node_modules/**");
    expect(args[args.length - 1]).toBe(".");
  });

  test("a path list replaces the whole-repository scan", () => {
    expect(astGrepArgs("<rules>", { paths: ["migrations/1.ts"] })).toContain("migrations/1.ts");
  });
});

describe("parseMatchLine", () => {
  test("turns a real record into 1-based lines and flat metavariables", () => {
    const match = parseMatchLine(RECORD);
    expect(match).not.toBeNull();
    // ast-grep counts lines from zero; every Sentinel artifact counts from one.
    expect(match?.startLine).toBe(6);
    expect(match?.endLine).toBe(6);
    expect(match?.startByte).toBe(197);
    expect(match?.meta.DB).toBe("db");
    expect(match?.metaList.ARGS).toEqual(["{ id: users.id }"]);
  });

  test("a record that does not fit the shape is refused, not trusted", () => {
    expect(parseMatchLine('{"ruleId":"x"}')).toBeNull();
    expect(parseMatchLine("not json")).toBeNull();
    expect(parseMatchLine("   ")).toBeNull();
  });

  test("the stream counts what it had to refuse", () => {
    const parsed = parseMatchStream(`${RECORD}\nbroken\n\n${RECORD}`);
    expect(parsed.matches).toHaveLength(2);
    expect(parsed.unparsedRecords).toBe(1);
  });
});

describe("contains", () => {
  test("a range contains itself and everything inside it", () => {
    const outer = { startByte: 10, endByte: 20 };
    expect(contains(outer, { startByte: 10, endByte: 20 })).toBe(true);
    expect(contains(outer, { startByte: 12, endByte: 18 })).toBe(true);
    expect(contains(outer, { startByte: 9, endByte: 18 })).toBe(false);
  });
});

describe("runAstGrep", () => {
  test("a missing analyzer is a skip with a reason, never an empty success", async () => {
    const { ctx } = context(null);
    const run = await runAstGrep(ctx, [RULE]);
    expect(run.status).toBe("skipped");
    expect(run.reason).toContain("not installed");
  });

  test("a rule that does not compile is a failure, not zero matches", async () => {
    const { ctx } = context("/bin/ast-grep", { exitCode: 1, stderr: "unknown kind" });
    const run = await runAstGrep(ctx, [RULE]);
    expect(run.status).toBe("failed");
    expect(run.reason).toContain("unknown kind");
  });

  test("a timeout is a failure, because the enumeration would be partial", async () => {
    const { ctx } = context("/bin/ast-grep", { timedOut: true });
    expect((await runAstGrep(ctx, [RULE])).status).toBe("failed");
  });

  test("truncated output degrades and says what was lost", async () => {
    const { ctx } = context("/bin/ast-grep", { stdout: RECORD, truncated: true });
    const run = await runAstGrep(ctx, [RULE]);
    expect(run.status).toBe("degraded");
    expect(run.matches).toHaveLength(1);
    expect(run.reason).toContain("truncated");
  });

  test("a clean run reports its matches and runs in the target directory", async () => {
    const { ctx, calls } = context("/bin/ast-grep", { stdout: RECORD });
    const run = await runAstGrep(ctx, [RULE]);
    expect(run.status).toBe("ok");
    expect(run.matches[0]?.file).toBe("src/services/bookings.ts");
    expect(calls[0]?.command).toBe("/bin/ast-grep");
  });

  test("no rules is a skip, so an empty rule set cannot look like a clean scan", async () => {
    const { ctx } = context("/bin/ast-grep");
    expect((await runAstGrep(ctx, [])).status).toBe("skipped");
  });
});
