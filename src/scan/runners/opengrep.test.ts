import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileSystem } from "../../ports/file-system.ts";
import { createProcessExecutor } from "../../ports/process-executor.ts";
import { readToolsLock } from "../../tools/installer.ts";
import { createToolResolver } from "../../tools/resolve.ts";
import { type SarifFinding, parseSarif } from "../parsers/sarif.ts";
import {
  DEFAULT_EXCLUDES,
  OPENGREP_STEP,
  type OpengrepContext,
  confidenceOf,
  defaultRulesDir,
  domainOf,
  localeEnv,
  opengrepArgs,
  runOpengrep,
  severityOf,
} from "./opengrep.ts";

const disk = createFileSystem();

/** The corpus the fixture SARIF was captured from; its files are cited by the report. */
const CORPUS = `${import.meta.dir}/__fixtures__/rule-pack-target`;

/** Real opengrep output over that corpus, trimmed to six rules. */
const REPORT = await Bun.file(
  `${import.meta.dir}/../parsers/__fixtures__/opengrep-report.sarif`,
).text();

const CONFIG_ERROR = await Bun.file(
  `${import.meta.dir}/../parsers/__fixtures__/opengrep-config-error.sarif`,
).text();

const RUN_DIR = "/runs/r1";
const REPORT_PATH = `${RUN_DIR}/raw/opengrep/report.sarif`;

/**
 * The real filesystem with a handful of paths overlaid in memory. Findings are
 * verified against the corpus on disk, which is the point: the snippets in the
 * assertions below were read from real files, not from the tool's output.
 */
class OverlayFs {
  readonly overlay = new Map<string, string>();
  readonly dirs = new Set<string>();

  async readFile(path: string): Promise<string> {
    const body = this.overlay.get(path);
    return body === undefined ? disk.readFile(path) : body;
  }

  async readFileBytes(path: string): Promise<Uint8Array> {
    const body = this.overlay.get(path);
    return body === undefined ? disk.readFileBytes(path) : new TextEncoder().encode(body);
  }

  async writeFile(path: string, data: string | Uint8Array): Promise<void> {
    this.overlay.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
  }

  async mkdirp(path: string): Promise<void> {
    this.dirs.add(path);
  }

  async exists(path: string): Promise<boolean> {
    return this.overlay.has(path) || this.dirs.has(path) || disk.exists(path);
  }

  async realpath(path: string): Promise<string> {
    return this.overlay.has(path) ? path : disk.realpath(path);
  }
}

interface HarnessOptions {
  readonly report?: string | null;
  readonly exitCode?: number;
  readonly stderr?: string;
  readonly timedOut?: boolean;
  readonly notFound?: boolean;
  readonly truncated?: boolean;
  readonly binary?: string | null;
  readonly rulesDir?: string;
}

interface Call {
  readonly args: readonly string[];
  readonly cwd: string | undefined;
  readonly env: Readonly<Record<string, string | undefined>> | undefined;
}

/** Builds a context whose opengrep is a stub that writes a chosen report. */
function harness(options: HarnessOptions = {}): { ctx: OpengrepContext; calls: Call[] } {
  const fs = new OverlayFs();
  const calls: Call[] = [];
  const ctx: OpengrepContext = {
    fs,
    exec: {
      async run(_command, args = [], runOptions = {}) {
        calls.push({ args, cwd: runOptions.cwd, env: runOptions.env });
        const report = options.report === undefined ? REPORT : options.report;
        if (report !== null) await fs.writeFile(REPORT_PATH, report);
        return {
          exitCode: options.exitCode ?? 0,
          stdout: "",
          stderr: options.stderr ?? "",
          timedOut: options.timedOut ?? false,
          truncated: options.truncated ?? false,
          notFound: options.notFound ?? false,
        };
      },
    },
    tools: {
      async resolve() {
        return options.binary === undefined ? "/tools/opengrep" : options.binary;
      },
    },
    targetDir: CORPUS,
    runDir: RUN_DIR,
    ...(options.rulesDir === undefined ? {} : { rulesDir: options.rulesDir }),
    env: { LANG: "en_US.UTF-8" },
  };
  return { ctx, calls };
}

/** A SARIF finding shell, for the routing unit tests. */
function sarifFinding(partial: Partial<SarifFinding>): SarifFinding {
  return {
    ruleId: "appsec.xss.inner-html-assignment",
    level: "error",
    message: "",
    locations: [],
    primary: null,
    fingerprints: {},
    rule: null,
    tags: [],
    ...partial,
  };
}

describe("opengrepArgs", () => {
  test("pins the rule ids, so a directory config does not rename them", () => {
    expect(opengrepArgs("/rules", REPORT_PATH, [])).toContain("--no-rewrite-rule-ids");
  });

  test("scans `.` so the SARIF paths stay repository-relative", () => {
    expect(opengrepArgs("/rules", REPORT_PATH, []).at(-1)).toBe(".");
  });

  test("writes SARIF to the run directory", () => {
    expect(opengrepArgs("/rules", REPORT_PATH, [])).toContain(`--sarif-output=${REPORT_PATH}`);
  });

  test("passes each exclusion as its own flag", () => {
    const args = opengrepArgs("/rules", REPORT_PATH, ["node_modules", "dist"]);
    expect(args).toContain("--exclude=node_modules");
    expect(args).toContain("--exclude=dist");
  });

  test("keeps vendored and generated code out by default", () => {
    expect(DEFAULT_EXCLUDES).toContain("node_modules");
    expect(DEFAULT_EXCLUDES).toContain(".next");
    expect(DEFAULT_EXCLUDES).toContain("*.min.js");
  });
});

describe("localeEnv", () => {
  test("forces UTF-8 when the ambient locale is the C default of most CI images", () => {
    expect(localeEnv({})).toEqual({ LC_ALL: "C.UTF-8" });
    expect(localeEnv({ LANG: "C" })).toEqual({ LC_ALL: "C.UTF-8" });
    expect(localeEnv({ LC_ALL: "POSIX" })).toEqual({ LC_ALL: "C.UTF-8" });
  });

  test("leaves a UTF-8 environment alone", () => {
    expect(localeEnv({ LANG: "en_US.UTF-8" })).toEqual({});
    expect(localeEnv({ LC_CTYPE: "UTF-8" })).toEqual({});
    expect(localeEnv({ LC_ALL: "C.utf8" })).toEqual({});
  });
});

describe("routing a match to a domain, severity and confidence", () => {
  test("prefers the rule's own tags", () => {
    const finding = sarifFinding({
      tags: ["sentinel-domain:delivery", "sentinel-severity:critical", "sentinel-confidence:low"],
    });
    expect(domainOf(finding)).toBe("delivery");
    expect(severityOf(finding)).toBe("critical");
    expect(confidenceOf(finding)).toBe("low");
  });

  test("falls back to the first segment of the dotted rule id", () => {
    expect(domainOf(sarifFinding({ ruleId: "data.missing-index-on-fk" }))).toBe("data");
  });

  test("is null for a rule that names no domain at all", () => {
    expect(domainOf(sarifFinding({ ruleId: "some-third-party-rule" }))).toBeNull();
  });

  test("ignores a tag whose value is not a domain", () => {
    expect(domainOf(sarifFinding({ ruleId: "x.y", tags: ["sentinel-domain:banana"] }))).toBeNull();
  });

  test("falls back to the SARIF level when no severity is declared", () => {
    expect(severityOf(sarifFinding({ level: "error" }))).toBe("high");
    expect(severityOf(sarifFinding({ level: "warning" }))).toBe("medium");
    expect(severityOf(sarifFinding({ level: "note" }))).toBe("low");
  });

  test("an undeclared match is medium confidence, not high", () => {
    expect(confidenceOf(sarifFinding({}))).toBe("medium");
    expect(confidenceOf(sarifFinding({ tags: ["sentinel-confidence:nonsense"] }))).toBe("medium");
  });
});

describe("runOpengrep on real captured output", () => {
  test("normalises every match, routed by its rule's metadata", async () => {
    const step = await runOpengrep(harness().ctx);

    expect(step.step).toBe("opengrep");
    expect(step.status).toBe("ok");
    expect(step.findings.length).toBeGreaterThan(0);
    const byRule = new Map(step.findings.map((finding) => [finding.rule, finding]));
    expect(byRule.get("appsec.xss.inner-html-assignment")?.domain).toBe("appsec");
    expect(byRule.get("appsec.xss.inner-html-assignment")?.severity).toBe("high");
    expect(byRule.get("delivery.node.tls-verification-disabled")?.domain).toBe("delivery");
    expect(byRule.get("delivery.express.missing-helmet")?.severity).toBe("medium");
    expect(byRule.get("delivery.express.missing-helmet")?.confidence).toBe("low");
  });

  test("the snippet is read from disk, not taken from the tool", async () => {
    const step = await runOpengrep(harness().ctx);
    const hit = step.findings.find(
      (finding) => finding.rule === "appsec.xss.inner-html-assignment",
    );

    expect(hit?.location.file).toBe("xss.js");
    // The gutter and the `>` marker are the verifier's rendering, which proves
    // the text came from `src/verify` rather than from the SARIF payload.
    expect(hit?.location.snippet).toContain(">  7 |");
    expect(hit?.location.snippet).toContain("el.innerHTML = comment.body;");
    // Context lines the tool never printed.
    expect(hit?.location.snippet).toContain("export function renderComment");
  });

  test("carries the human-written title, impact and fix from the rule", async () => {
    const step = await runOpengrep(harness().ctx);
    const hit = step.findings.find(
      (finding) => finding.rule === "appsec.auth.insecure-cookie-flags",
    );

    expect(hit?.title).toBe("Cookie set without the full flag set in auth.js");
    expect(hit?.impact).toContain("Without httpOnly one XSS steals the session");
    expect(hit?.recommendation).toContain("httpOnly: true");
    expect(hit?.description).toContain("A cookie is set without the full flag set");
  });

  test("keeps the CWE and OWASP metadata the converter turned into tags", async () => {
    const step = await runOpengrep(harness().ctx);
    const hit = step.findings.find(
      (finding) => finding.rule === "appsec.xss.inner-html-assignment",
    );

    expect(hit?.cwe.some((entry) => entry.startsWith("CWE-79:"))).toBe(true);
    expect(hit?.owasp).toEqual(["A03:2021 - Injection"]);
    // The `OWASP-` prefix the converter adds is not part of the category.
    expect(hit?.owasp.every((entry) => !entry.startsWith("OWASP-"))).toBe(true);
  });

  test("attributes the finding to the rule, not to the binary", async () => {
    const step = await runOpengrep(harness().ctx);
    for (const finding of step.findings) {
      expect(finding.source.kind).toBe("rule");
      // The step that produced it, as every other producer records; the rule id
      // is already in `rule`.
      expect(finding.source.name).toBe(OPENGREP_STEP);
    }
  });

  test("spells out what closes the finding", async () => {
    const step = await runOpengrep(harness().ctx);
    for (const finding of step.findings) {
      expect(finding.acceptanceCriteria[0]).toContain("no longer matches at");
      expect(finding.acceptanceCriteria[1]).toContain("not by suppressing the rule");
    }
  });

  test("ids are stable and unique per match", async () => {
    const first = await runOpengrep(harness().ctx);
    const second = await runOpengrep(harness().ctx);
    const ids = first.findings.map((finding) => finding.id);
    expect(second.findings.map((finding) => finding.id)).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("a generic-mode match in a .vue file is normalised like any other", async () => {
    const step = await runOpengrep(harness().ctx);
    const hit = step.findings.find((finding) => finding.rule === "appsec.xss.vue-v-html");
    expect(hit?.location.file).toBe("widget.vue");
    expect(hit?.location.snippet).toContain('v-html="post.body"');
  });

  test("runs inside the target with a UTF-8 locale left alone", async () => {
    const { ctx, calls } = harness();
    await runOpengrep(ctx);
    expect(calls[0]?.cwd).toBe(CORPUS);
    expect(calls[0]?.env).toEqual({});
  });
});

describe("runOpengrep degrades instead of crashing", () => {
  test("skips when opengrep is not installed, and says what that costs", async () => {
    const step = await runOpengrep(harness({ binary: null }).ctx);
    expect(step.status).toBe("skipped");
    expect(step.reason).toContain("injection, XSS, crypto and misconfiguration rules did not");
  });

  test("fails when the rule pack is missing", async () => {
    const step = await runOpengrep(harness({ rulesDir: "/nowhere/rules" }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("rule pack is missing");
  });

  test("an unreadable rule file is a failure, never a clean bill of health", async () => {
    const step = await runOpengrep(harness({ report: CONFIG_ERROR, exitCode: 7 }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("could not run its rules");
    expect(step.reason).toContain("Invalid YAML file");
    expect(step.findings).toEqual([]);
  });

  test("fails when no report was written", async () => {
    const step = await runOpengrep(harness({ report: null, exitCode: 2, stderr: "usage" }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("wrote no report");
  });

  test("fails on a truncated report", async () => {
    const step = await runOpengrep(harness({ report: '{"runs":[{"resu' }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("not valid JSON");
  });

  test("fails on a timeout", async () => {
    const step = await runOpengrep(harness({ timedOut: true }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("time budget");
  });

  test("a clean repository is ok with no findings", async () => {
    const step = await runOpengrep(
      harness({ report: '{"version":"2.1.0","runs":[{"results":[]}]}' }).ctx,
    );
    expect(step.status).toBe("ok");
    expect(step.findings).toEqual([]);
    expect(step.artifacts).toEqual([REPORT_PATH]);
  });

  test("a match from a rule with no domain is dropped and disclosed", async () => {
    const foreign = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          results: [
            {
              ruleId: "someones-other-pack",
              message: { text: "hi" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "xss.js" },
                    region: { startLine: 7 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const step = await runOpengrep(harness({ report: foreign }).ctx);
    expect(step.findings).toEqual([]);
    expect(step.reason).toContain("no Sentinel domain");
  });

  test("a match citing a file that is gone is dropped and counted", async () => {
    const stale = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          results: [
            {
              ruleId: "appsec.xss.inner-html-assignment",
              message: { text: "hi" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "deleted-since-the-scan.js" },
                    region: { startLine: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const step = await runOpengrep(harness({ report: stale }).ctx);
    expect(step.findings).toEqual([]);
    expect(step.reason).toContain("could not be read back from disk");
  });

  test("two patterns of one rule on one line are one finding", async () => {
    const duplicated = JSON.parse(REPORT) as {
      runs: { results: unknown[] }[];
    };
    const first = duplicated.runs[0]?.results[0];
    duplicated.runs[0]?.results.push(structuredClone(first));
    const step = await runOpengrep(harness({ report: JSON.stringify(duplicated) }).ctx);
    const rules = step.findings.map((finding) => `${finding.rule}:${finding.location.line}`);
    expect(new Set(rules).size).toBe(rules.length);
  });
});

describe("the shipped rule pack", () => {
  const packDir = defaultRulesDir();

  test("is where the runner expects it", async () => {
    expect(await disk.exists(packDir)).toBe(true);
  });

  test("is ASCII only, because opengrep reads rule files in the ambient locale", async () => {
    const files = await disk.glob("*.yaml", { cwd: packDir, absolute: true });
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const body = await disk.readFile(file);
      // biome-ignore lint/suspicious/noControlCharactersInRegex: the point is the non-ASCII range.
      const offending = body.match(/[^\x00-\x7F]/);
      expect(offending === null ? null : `${file}: ${offending[0]}`).toBeNull();
    }
  });

  test("every rule declares the routing tags the SARIF path depends on", async () => {
    const files = await disk.glob("*.yaml", { cwd: packDir, absolute: true });
    for (const file of files) {
      const body = await disk.readFile(file);
      const ids = [...body.matchAll(/^ {2}- id: (\S+)$/gm)].map((match) => match[1]);
      expect(ids.length).toBeGreaterThan(0);
      for (const id of ids) {
        // The dotted prefix has to be a domain even if the tags were lost.
        expect(id).toMatch(/^(appsec|delivery|data|api|reliability|serverless|deadcode)\./);
      }
      for (const tag of ["sentinel-domain:", "sentinel-severity:", "sentinel-title:"]) {
        expect(body.split(tag).length - 1).toBe(ids.length);
      }
    }
  });
});

// The rule pack is YAML that only opengrep can validate; a typo in a pattern
// makes a rule silently stop matching, which no unit test would catch.
const toolLock = await readToolsLock();
const opengrepBinary = await createToolResolver({ lock: toolLock, fs: disk }).resolve("opengrep");

describe.skipIf(opengrepBinary === null)("the rule pack against the installed opengrep", () => {
  test("every rule loads and fires on the corpus, and none fires on its safe counterpart", async () => {
    if (opengrepBinary === null) return;
    const runDir = join(tmpdir(), `sentinel-opengrep-${crypto.randomUUID()}`);
    try {
      const step = await runOpengrep({
        fs: disk,
        exec: createProcessExecutor(),
        tools: {
          async resolve() {
            return opengrepBinary;
          },
        },
        targetDir: CORPUS,
        runDir,
        env: process.env,
      });

      expect(step.status).toBe("ok");
      const report = await disk.readFile(join(runDir, "raw", "opengrep", "report.sarif"));
      const parsed = parseSarif(report);
      if (!parsed.ok) throw new Error(parsed.error);
      expect(parsed.errors).toEqual([]);

      // Each corpus line is annotated with the rule it must trigger; the
      // `SAFE:` blocks must stay clean.
      const expected = new Set<string>();
      for (const name of await disk.glob("**/*", { cwd: CORPUS })) {
        const body = await disk.readFile(join(CORPUS, name));
        for (const match of body.matchAll(/(appsec|delivery)\.[a-z0-9.-]*[a-z0-9]/g)) {
          expected.add(match[0]);
        }
      }
      const fired = new Set(step.findings.map((finding) => finding.rule));
      expect([...expected].filter((rule) => !fired.has(rule))).toEqual([]);
      expect([...fired].filter((rule) => !expected.has(rule))).toEqual([]);

      // And the whole chain: the same rule, in one file, graded by where each
      // interpolated value comes from.
      const sql = step.findings.filter(
        (finding) => finding.rule === "appsec.injection.sql-built-from-variables",
      );
      const reachable = sql.find((finding) => finding.description.includes("(P4)"));
      const unresolved = sql.find((finding) => finding.description.includes("(P3)"));
      expect(reachable?.severity).toBe("critical");
      expect(reachable?.location.snippet).toContain("req.query.sort");
      expect(unresolved?.severity).toBe("medium");
      expect(unresolved?.confidence).toBe("low");
    } finally {
      await disk.remove(runDir);
    }
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/** The real shapes the provenance analyser is graded against; see their README. */
const PROVENANCE_FIXTURES = `${import.meta.dir}/../__fixtures__/provenance`;

/** A SARIF payload for one match of one rule, with the span opengrep would report. */
function matchReport(
  file: string,
  ruleId: string,
  text: string,
  needle: string,
  occurrence = 1,
): string {
  const lines = text.split("\n");
  let remaining = occurrence;
  const index = lines.findIndex((line) => line.includes(needle) && --remaining === 0);
  if (index === -1) throw new Error(`the fixture has no line containing ${needle}`);
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        results: [
          {
            ruleId,
            message: { text: "A SQL statement is assembled by string interpolation." },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: file },
                  region: {
                    startLine: index + 1,
                    startColumn: (lines[index] ?? "").indexOf(needle) + 1,
                  },
                },
              },
            ],
            properties: { fingerprints: {} },
          },
        ],
        tool: {
          driver: {
            name: "opengrep",
            rules: [
              {
                id: ruleId,
                defaultConfiguration: { level: "error" },
                properties: {
                  tags: [
                    "sentinel-domain:appsec",
                    "sentinel-severity:critical",
                    "sentinel-confidence:medium",
                    "sentinel-title:SQL assembled by string interpolation",
                    "sentinel-impact:A crafted value changes the statement.",
                    "sentinel-fix:Pass the values as bound parameters.",
                  ],
                },
              },
            ],
          },
        },
      },
    ],
  });
}

/** Seeds a fixture into the corpus in memory and runs the step over one match of it. */
async function runOverFixture(
  fixture: string,
  needle: string,
  options: { occurrence?: number; rule?: string } = {},
): Promise<Awaited<ReturnType<typeof runOpengrep>>> {
  const text = await disk.readFile(`${PROVENANCE_FIXTURES}/${fixture}`);
  const rule = options.rule ?? "appsec.injection.sql-built-from-variables";
  const report = matchReport(fixture, rule, text, needle, options.occurrence ?? 1);
  const { ctx } = harness({ report });
  await ctx.fs.writeFile(join(CORPUS, fixture), text);
  return runOpengrep(ctx);
}

describe("provenance decides what an interpolation match means", () => {
  test("a closed interpolation is information with the provenance named, not a critical", async () => {
    const step = await runOverFixture("record-ride-change.migration.ts", "queryRunner.query");
    const finding = step.findings[0];

    expect(step.findings).toHaveLength(1);
    expect(finding?.severity).toBe("info");
    expect(finding?.confidence).toBe("high");
    expect(finding?.title.startsWith("Not injectable: ")).toBe(true);
    expect(finding?.description).toContain("(P1)");
    expect(finding?.description).toContain('module constant `table = "ride_journal"`');
    expect(finding?.impact).toContain("None as written");
    expect(finding?.exploitability).toContain("No caller-controlled value reaches");
    // The snippet still comes from disk, so the reader can check the claim.
    expect(finding?.location.snippet).toContain("queryRunner.query");
  });

  test("the step discloses every downgrade it made", async () => {
    const step = await runOverFixture("record-ride-change.migration.ts", "queryRunner.query");

    expect(step.status).toBe("ok");
    expect(step.reason).toContain("resolved to values this code fixes");
    expect(step.reason).toContain("(P1)");
    expect(step.reason).toContain("rather than dropped");
  });

  test("a value that reaches the statement from the request keeps its severity", async () => {
    const step = await runOverFixture("ride-search.ts", "ORDER BY ${sort}");
    const finding = step.findings[0];

    expect(finding?.severity).toBe("critical");
    expect(finding?.confidence).toBe("high");
    expect(finding?.title.startsWith("Not injectable")).toBe(false);
    expect(finding?.description).toContain("(P4)");
    expect(finding?.exploitability).toContain("A caller controls the interpolated value");
    expect(step.reason).toContain("kept at full severity");
  });

  test("deploy-time configuration in a migration is low, and says who can change it", async () => {
    const step = await runOverFixture("notify-dock-change.migration.ts", "CREATE OR REPLACE");
    const finding = step.findings[0];

    expect(finding?.severity).toBe("low");
    expect(finding?.confidence).toBe("low");
    expect(finding?.description).toContain("(P2)");
    expect(finding?.description).toContain("DOCK_EVENT_CHANNEL");
    expect(finding?.acceptanceCriteria.join(" ")).toContain("quote_literal");
  });

  test("configuration outside a migration is capped by its class alone", async () => {
    const step = await runOverFixture("stale-queue-reaper.worker.ts", "WITH stale AS");
    const finding = step.findings[0];

    // A worker is not a migration, so P2's own ceiling is what is left.
    expect(finding?.severity).toBe("low");
    expect(finding?.confidence).toBe("low");
    expect(finding?.description).toContain("(P2)");
  });

  test("an unresolved value is a medium lead, not a critical claim", async () => {
    const text = await disk.readFile(`${CORPUS}/injection.js`);
    const report = matchReport(
      "injection.js",
      "appsec.injection.sql-built-from-variables",
      text,
      "SELECT * FROM users WHERE email",
    );
    const step = await runOpengrep(harness({ report }).ctx);
    const finding = step.findings[0];

    expect(finding?.severity).toBe("medium");
    expect(finding?.confidence).toBe("low");
    expect(finding?.description).toContain("(P3)");
    expect(finding?.exploitability).toContain("Reachability was not established");
    expect(step.reason).toContain("reachability is not established");
  });

  test("two sinks fed by one value in one function are one finding", async () => {
    const fixture = "add-bike-model-code.migration.ts";
    const text = await disk.readFile(`${PROVENANCE_FIXTURES}/${fixture}`);
    const rule = "appsec.injection.sql-built-from-variables";
    const first = JSON.parse(matchReport(fixture, rule, text, "queryRunner.query", 1)) as {
      runs: { results: unknown[] }[];
    };
    const second = JSON.parse(matchReport(fixture, rule, text, "queryRunner.query", 2)) as {
      runs: { results: unknown[] }[];
    };
    const both = first.runs[0]?.results[0];
    const other = second.runs[0]?.results[0];
    if (both === undefined || other === undefined) throw new Error("the fixture lost a match");
    first.runs[0]?.results.push(other);

    const { ctx } = harness({ report: JSON.stringify(first) });
    await ctx.fs.writeFile(join(CORPUS, fixture), text);
    const step = await runOpengrep(ctx);

    expect(step.findings).toHaveLength(1);
    expect(step.findings[0]?.evidence).toHaveLength(1);
    expect(step.findings[0]?.evidence[0]?.note).toContain("another statement here");
    expect(step.findings[0]?.description).toContain("one value with one fix is one finding");
    expect(step.reason).toContain("folded into a sibling");
  });

  test("a rule whose match is not an interpolation is left exactly as it fired", async () => {
    const step = await runOpengrep(harness().ctx);
    const xss = step.findings.find(
      (finding) => finding.rule === "appsec.xss.inner-html-assignment",
    );

    expect(xss?.severity).toBe("high");
    expect(xss?.description).not.toContain("(P1)");
    expect(xss?.description).not.toContain("(P3)");
  });
});
