import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  type RunHandler,
  fixtureRepo,
  harnessExecutor,
  harnessFileSystem,
  harnessResolver,
} from "./__fixtures__/harness.ts";
import type { RunnerContext } from "./_runner-support.ts";
import {
  DEPENDENCY_CRUISER_STEP,
  GENERATED_CONFIG_NAME,
  generatedConfig,
  runDependencyCruiser,
} from "./dependency-cruiser.ts";

/** Real `depcruise 18.4.0 --output-type json` output over the `node-demo` repo. */
const REPORT = await Bun.file(
  join(import.meta.dir, "../parsers/__fixtures__/dependency-cruiser-report.json"),
).text();

const TARGET = fixtureRepo("node-demo");
const BINARY = "/cache/sentinel/node/dependency-cruiser/18.4.0/node_modules/.bin/depcruise";
const RUN_DIR = "/runs/2026-09-22";

/** A context over the real fixture repo, with depcruise's output scripted. */
function contextWith(handler: RunHandler, overrides: Partial<RunnerContext> = {}) {
  const fs = harnessFileSystem();
  const exec = harnessExecutor(handler);
  const ctx: RunnerContext = {
    fs,
    exec,
    tools: harnessResolver({ "dependency-cruiser": BINARY }),
    targetDir: TARGET,
    runDir: RUN_DIR,
    ...overrides,
  };
  return { ctx, fs, exec };
}

describe("runDependencyCruiser", () => {
  test("turns a real cruise into one cycle finding and one orphan finding", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runDependencyCruiser(ctx);

    expect(result.step).toBe(DEPENDENCY_CRUISER_STEP);
    expect(result.findings.map((finding) => finding.rule)).toEqual([
      "deadcode.circular-dependency",
      "deadcode.orphan-module",
    ]);
  });

  test("the cycle finding cites every module in the ring", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runDependencyCruiser(ctx);

    const cycle = result.findings[0];
    expect(cycle?.title).toBe("Circular import: src/a.ts -> src/b.ts -> src/a.ts");
    expect(cycle?.location.file).toBe("src/a.ts");
    expect(cycle?.location.snippet).toContain('import { helper } from "./b.ts"');
    expect(cycle?.evidence).toHaveLength(1);
    expect(cycle?.evidence[0]?.file).toBe("src/b.ts");
    expect(cycle?.evidence[0]?.snippet).toContain('import { handler } from "./a.ts"');
    // A graph fact, not a guess: dependency-cruiser resolved the imports.
    expect(cycle?.confidence).toBe("high");
  });

  test("an orphan is reported as the candidate it is", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runDependencyCruiser(ctx);

    const orphan = result.findings[1];
    expect(orphan?.title).toBe("Orphan module candidate: src/orphan.ts");
    expect(orphan?.confidence).toBe("medium");
    expect(orphan?.description).toContain("This is a candidate");
  });

  test("generates a ruleset in the run dir when the target has none", async () => {
    const { ctx, fs, exec } = contextWith(() => ({ stdout: REPORT }));
    const result = await runDependencyCruiser(ctx);

    const configPath = join(RUN_DIR, "raw", DEPENDENCY_CRUISER_STEP, GENERATED_CONFIG_NAME);
    expect(fs.writes.map((write) => write.path)).toContain(configPath);
    expect(exec.runs[0]?.args.slice(0, 4)).toEqual([
      "--config",
      configPath,
      "--output-type",
      "json",
    ]);
    // Generating the ruleset is the normal path, not a degradation; the
    // generated file is an artifact so the report can point at what ran.
    expect(result.status).toBe("ok");
    expect(result.artifacts).toContain(configPath);
  });

  test("never writes into the repository under analysis", async () => {
    const { ctx, fs } = contextWith(() => ({ stdout: REPORT }));
    await runDependencyCruiser(ctx);

    for (const write of fs.writes) {
      expect(write.path.startsWith(TARGET)).toBe(false);
      expect(write.path.startsWith(RUN_DIR)).toBe(true);
    }
  });

  test("uses the target's own configuration when it has one", async () => {
    const { ctx, fs, exec } = contextWith(() => ({ stdout: REPORT }), {
      targetDir: fixtureRepo("depcruise-configured"),
    });
    await runDependencyCruiser(ctx);

    expect(exec.runs[0]?.args[1]).toBe(
      join(fixtureRepo("depcruise-configured"), ".dependency-cruiser.json"),
    );
    expect(fs.writes.map((write) => write.path)).not.toContain(
      join(RUN_DIR, "raw", DEPENDENCY_CRUISER_STEP, GENERATED_CONFIG_NAME),
    );
  });

  test("cruises the source directories the repository actually has", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: REPORT }));
    await runDependencyCruiser(ctx);
    expect(exec.runs[0]?.args.slice(4)).toEqual(["src"]);
  });

  test("hands dependency-cruiser a typescript it can parse .ts with", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: REPORT }));
    await runDependencyCruiser(ctx);

    const nodePath = exec.runs[0]?.options.env?.NODE_PATH;
    expect(nodePath).toBeDefined();
    // Sentinel's own copy, never the audited repository's.
    expect(nodePath?.startsWith(TARGET)).toBe(false);
  });

  test("an empty graph is skipped, not reported as a clean repository", async () => {
    const empty = JSON.stringify({
      modules: [],
      summary: { violations: [], totalCruised: 0 },
    });
    const { ctx } = contextWith(() => ({ stdout: empty }));
    const result = await runDependencyCruiser(ctx);

    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("nothing to cruise");
  });

  test("a non-zero exit with output is a violated ruleset, not a failure", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: REPORT }));
    const result = await runDependencyCruiser(ctx);
    expect(result.findings).toHaveLength(2);
  });

  test("a missing tool is skipped with what the run loses", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }), { tools: harnessResolver({}) });
    const result = await runDependencyCruiser(ctx);

    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("sentinel setup");
  });

  test("a crash with no output is a failure, with the tool's own words", async () => {
    const { ctx } = contextWith(() => ({
      exitCode: 1,
      stdout: "",
      stderr: "ERROR: Can't open a config file",
    }));
    const result = await runDependencyCruiser(ctx);

    expect(result.status).toBe("failed");
    expect(result.reason).toContain("Can't open a config file");
  });

  test("output that is not the expected shape is refused, not guessed at", async () => {
    const { ctx } = contextWith(() => ({ stdout: "<html>proxy error</html>" }));
    const result = await runDependencyCruiser(ctx);

    expect(result.status).toBe("failed");
    expect(result.reason).toContain("did not produce valid JSON");
  });
});

describe("generatedConfig", () => {
  test("is a valid ES module that asks for cycles and orphans", () => {
    const source = generatedConfig("tsconfig.json");
    expect(source).toContain("AUTO-GENERATED");
    const body = source.slice(source.indexOf("export default ") + "export default ".length, -2);
    const config: unknown = JSON.parse(body);
    expect(config).toMatchObject({
      forbidden: [
        { name: "no-circular", to: { circular: true } },
        { name: "no-orphans", from: { orphan: true } },
      ],
      options: { tsConfig: { fileName: "tsconfig.json" } },
    });
  });

  test("leaves the tsconfig out when the repository has none", () => {
    expect(generatedConfig(null)).not.toContain("tsConfig");
  });
});
