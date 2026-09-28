import { describe, expect, test } from "bun:test";
import {
  AST_GREP_TOOL,
  astGrepArgs,
  buildRuleDocument,
  createAstGrepSearch,
  emptySearch,
  excludeGlobs,
  parseAstGrepOutput,
} from "./_ast-grep.ts";

/** One ast-grep match, as the tool prints it: 0-based lines, commas in `$$$`. */
function rawMatch(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    text: 'new Worker("email", handler)',
    file: "src/queue/email.ts",
    range: { start: { line: 4, column: 27 }, end: { line: 6, column: 3 } },
    ruleId: "bull-worker",
    metaVariables: {
      single: { QUEUE: { text: "q" } },
      multi: { ARGS: [{ text: '"email"' }, { text: "," }, { text: "handler" }] },
    },
    // `JSON.stringify` drops an `undefined`, which is how a test omits a key.
    ...overrides,
  };
}

/** The payload for one match. */
function payload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify([rawMatch(overrides)]);
}

/** An executor that answers one command and remembers how it was called. */
function stubExecutor(result: Partial<{ exitCode: number; stdout: string; stderr: string }>) {
  const calls: Array<{ command: string; args: readonly string[]; cwd?: string }> = [];
  return {
    calls,
    async run(
      command: string,
      args: readonly string[] = [],
      options: { cwd?: string } = {},
    ): Promise<{
      exitCode: number;
      stdout: string;
      stderr: string;
      timedOut: boolean;
      truncated: boolean;
      notFound: boolean;
    }> {
      calls.push({ command, args, ...(options.cwd === undefined ? {} : { cwd: options.cwd }) });
      return {
        exitCode: result.exitCode ?? 0,
        stdout: result.stdout ?? "[]",
        stderr: result.stderr ?? "",
        timedOut: false,
        truncated: false,
        notFound: false,
      };
    },
  };
}

describe("buildRuleDocument", () => {
  test("emits one document per language, as JSON that YAML accepts", () => {
    const document = buildRuleDocument([
      { id: "worker", languages: ["TypeScript"], rule: { pattern: "new Worker($$$ARGS)" } },
    ]);
    expect(document).toBe(
      '{"id":"worker","language":"TypeScript","rule":{"pattern":"new Worker($$$ARGS)"}}',
    );
  });

  test("a rule with no language declared runs against all three", () => {
    const document = buildRuleDocument([{ id: "x", rule: { pattern: "eval($$$A)" } }]);
    const documents = document.split("\n---\n");
    expect(documents).toHaveLength(3);
    expect(documents.map((entry) => JSON.parse(entry).language)).toEqual([
      "TypeScript",
      "Tsx",
      "JavaScript",
    ]);
  });

  test("a pattern containing quotes and colons survives serialisation", () => {
    const document = buildRuleDocument([
      { id: "x", languages: ["Tsx"], rule: { pattern: { context: '<a b={"c: d"} />' } } },
    ]);
    expect(JSON.parse(document).rule.pattern.context).toBe('<a b={"c: d"} />');
  });
});

describe("astGrepArgs", () => {
  test("scans the current directory so match paths stay repo-relative", () => {
    const args = astGrepArgs("rules");
    expect(args[0]).toBe("scan");
    expect(args).toContain("--json=compact");
    expect(args[args.length - 1]).toBe(".");
  });

  test("excludes the directories that are never the customer's code", () => {
    expect(excludeGlobs()).toContain("!**/node_modules/**");
    expect(excludeGlobs()).toContain("!**/*.min.js");
    expect(astGrepArgs("rules").filter((arg) => arg === "--globs").length).toBe(
      excludeGlobs().length,
    );
  });
});

describe("parseAstGrepOutput", () => {
  test("normalises a match to 1-based lines and comma-free captures", () => {
    const result = parseAstGrepOutput(payload());
    expect(result.ok).toBe(true);
    const [first] = result.matches;
    expect(first?.line).toBe(5);
    expect(first?.endLine).toBe(7);
    expect(first?.file).toBe("src/queue/email.ts");
    expect(first?.vars.QUEUE).toBe("q");
    expect(first?.lists.ARGS).toEqual(['"email"', "handler"]);
  });

  test("an empty payload is a successful search with nothing in it", () => {
    expect(parseAstGrepOutput("[]")).toEqual({ ok: true, matches: [] });
    expect(parseAstGrepOutput("   ")).toEqual({ ok: true, matches: [] });
  });

  test("a match with no rule id is dropped rather than guessed at", () => {
    expect(parseAstGrepOutput(payload({ ruleId: undefined })).matches).toHaveLength(0);
  });

  test("a rule that binds nothing still yields a match", () => {
    const result = parseAstGrepOutput(payload({ metaVariables: undefined }));
    expect(result.matches[0]?.vars).toEqual({});
    expect(result.matches[0]?.lists).toEqual({});
  });

  test("output that is not JSON is refused, not half-read", () => {
    const result = parseAstGrepOutput("ERROR: no such file");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not JSON");
  });

  test("output of the wrong shape is refused", () => {
    const result = parseAstGrepOutput('[{"file":"a.ts"}]');
    expect(result.ok).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("matches come back in a stable order whatever order the tool printed them", () => {
    const printed = JSON.stringify([
      rawMatch({ file: "src/z.ts" }),
      rawMatch({ file: "src/a.ts" }),
    ]);
    const result = parseAstGrepOutput(printed);
    expect(result.matches.map((entry) => entry.file)).toEqual(["src/a.ts", "src/z.ts"]);
  });
});

describe("createAstGrepSearch", () => {
  const rules = [{ id: "x", languages: ["TypeScript"] as const, rule: { pattern: "eval($$$A)" } }];

  test("degrades with a sentence when the tool is not installed", async () => {
    const search = createAstGrepSearch({
      exec: stubExecutor({}),
      tools: { resolve: async () => null },
      targetDir: "/repo",
    });
    const result = await search.search(rules);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain(AST_GREP_TOOL);
    expect(result.reason).toContain("sentinel setup");
  });

  test("runs the binary in the target directory", async () => {
    const exec = stubExecutor({ stdout: payload() });
    const search = createAstGrepSearch({
      exec,
      tools: { resolve: async () => "/cache/ast-grep" },
      targetDir: "/repo",
    });
    const result = await search.search(rules);
    expect(result.matches).toHaveLength(1);
    expect(exec.calls[0]?.command).toBe("/cache/ast-grep");
    expect(exec.calls[0]?.cwd).toBe("/repo");
  });

  test("a non-zero exit is a degraded search, not a throw", async () => {
    const search = createAstGrepSearch({
      exec: stubExecutor({ exitCode: 8, stderr: "Cannot parse rule INLINE_RULES" }),
      tools: { resolve: async () => "/cache/ast-grep" },
      targetDir: "/repo",
    });
    const result = await search.search(rules);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("exited 8");
    expect(result.reason).toContain("Cannot parse rule");
  });

  test("no rules means no process", async () => {
    const exec = stubExecutor({});
    const search = createAstGrepSearch({
      exec,
      tools: { resolve: async () => "/cache/ast-grep" },
      targetDir: "/repo",
    });
    expect(await search.search([])).toEqual({ ok: true, matches: [] });
    expect(exec.calls).toHaveLength(0);
  });

  test("the empty search reports why it found nothing", async () => {
    const result = await emptySearch("no JS/TS in this repository").search(rules);
    expect(result).toEqual({ ok: false, matches: [], reason: "no JS/TS in this repository" });
  });
});
