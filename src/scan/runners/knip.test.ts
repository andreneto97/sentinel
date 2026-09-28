import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import type { Finding } from "../../contracts/findings.ts";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import {
  type RunHandler,
  fixtureRepo,
  harnessExecutor,
  harnessFileSystem,
  harnessResolver,
} from "./__fixtures__/harness.ts";
import {
  GENERATED_CONFIG_NAME,
  KNIP_STEP,
  type KnipContext,
  type KnipFileSystem,
  knipEvidence,
  planKnipConfig,
  runKnip,
} from "./knip.ts";

/** Real `knip 6.37.0 --reporter json` output over the `node-demo` fixture repo. */
const REPORT = await Bun.file(
  join(import.meta.dir, "../parsers/__fixtures__/knip-report.json"),
).text();

const TARGET = fixtureRepo("node-demo");
const MONOREPO = fixtureRepo("nx-monorepo");
const BINARY = "/cache/sentinel/node/knip/6.37.0/node_modules/.bin/knip";
const RUN_DIR = "/runs/2026-09-22";

/**
 * The harness filesystem plus the real port's `glob`.
 *
 * The config planner asks the repository which projects it holds, which is a
 * question only a glob can answer; reads still hit the real fixtures and writes
 * still go nowhere.
 */
function globbingFileSystem(): KnipFileSystem & ReturnType<typeof harnessFileSystem> {
  const harness = harnessFileSystem();
  const real = createFileSystem();
  return Object.assign(harness, {
    glob: (patterns: string | readonly string[], options?: { cwd?: string; onlyFiles?: boolean }) =>
      real.glob(patterns, options),
  });
}

/** A context over the real fixture repo, with knip's output scripted. */
function contextWith(handler: RunHandler, overrides: Partial<KnipContext> = {}) {
  const fs = globbingFileSystem();
  const exec = harnessExecutor(handler);
  const ctx: KnipContext = {
    fs,
    exec,
    tools: harnessResolver({ knip: BINARY }),
    targetDir: TARGET,
    runDir: RUN_DIR,
    ...overrides,
  };
  return { ctx, fs, exec };
}

/** A profile that proves exactly the facts it is given. */
function profileWith(
  target: string,
  facts: ReadonlyArray<[DetectedFact["kind"], string]>,
): StackProfile {
  return {
    schemaVersion: "1.0",
    target,
    facts: facts.map(([kind, value]) => ({
      kind,
      value,
      confidence: "high",
      evidence: [{ file: "package.json", line: 1 }],
    })),
    absences: [],
    warnings: [],
    scan: { filesSeen: 9, filesRead: 9, truncated: false },
  };
}

/** The profile phase 0 produces for the `nx-monorepo` fixture. */
function monorepoProfile(): StackProfile {
  return profileWith(MONOREPO, [
    ["repo-layout", "monorepo"],
    ["monorepo-tool", "nx"],
    ["workspace-package", "packages/tool"],
    ["migrations-dir", "db/migrations"],
  ]);
}

/** The finding for one rule, or undefined when the runner did not emit it. */
function ruled(findings: readonly Finding[], rule: string): Finding | undefined {
  return findings.find((finding) => finding.rule === rule);
}

/** The generated configuration the runner wrote, parsed. */
function generatedConfig(writes: ReadonlyArray<{ path: string; content: string }>): {
  workspaces: Record<string, { entry: string[] }>;
} {
  const write = writes.find((entry) => entry.path.endsWith(GENERATED_CONFIG_NAME));
  if (write === undefined) throw new Error("no configuration was generated");
  return JSON.parse(write.content) as { workspaces: Record<string, { entry: string[] }> };
}

describe("runKnip", () => {
  test("normalises a real report into one finding per candidate", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runKnip(ctx);

    expect(result.step).toBe(KNIP_STEP);
    expect(result.findings).toHaveLength(6);
    expect(result.findings.map((finding) => finding.rule).sort()).toEqual([
      "deadcode.unlisted-dependency",
      "deadcode.unused-export",
      "deadcode.unused-file",
      "deadcode.unused-type-export",
      "dependencies.unused-dependency",
      "dependencies.unused-dev-dependency",
    ]);
  });

  test("runs knip with the JSON reporter and no failing exit code", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: REPORT }));
    await runKnip(ctx);

    expect(exec.runs).toHaveLength(1);
    expect(exec.runs[0]?.command).toBe(BINARY);
    expect(exec.runs[0]?.args).toEqual(["--reporter", "json", "--no-exit-code"]);
    expect(exec.runs[0]?.options.cwd).toBe(TARGET);
  });

  test("an unused dependency is a supply-chain finding, not a dead-code one", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runKnip(ctx);

    const unused = ruled(result.findings, "dependencies.unused-dependency");
    expect(unused?.domain).toBe("dependencies");
    expect(unused?.title).toBe("Unused dependency candidate: left-pad");
    expect(unused?.location.file).toBe("package.json");
    expect(unused?.location.line).toBe(7);
  });

  test("every finding is a candidate, never a verdict", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runKnip(ctx);

    for (const finding of result.findings) {
      expect(["low", "info"]).toContain(finding.severity);
      expect(finding.source).toEqual({ kind: "tool", name: "knip" });
    }
    expect(ruled(result.findings, "deadcode.unused-file")?.description).toContain(
      "candidate, not a verdict",
    );
  });

  test("the snippet is read from disk, not taken from knip", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const result = await runKnip(ctx);

    const unusedExport = ruled(result.findings, "deadcode.unused-export");
    expect(unusedExport?.location.file).toBe("src/b.ts");
    expect(unusedExport?.location.snippet).toContain("export function neverUsed");
    expect(unusedExport?.location.snippet).toContain("> 7 |");
  });

  test("ids are stable across runs", async () => {
    const first = await runKnip(contextWith(() => ({ stdout: REPORT })).ctx);
    const second = await runKnip(contextWith(() => ({ stdout: REPORT })).ctx);
    expect(first.findings.map((finding) => finding.id)).toEqual(
      second.findings.map((finding) => finding.id),
    );
  });

  test("keeps knip's untouched output as an artifact", async () => {
    const { ctx, fs } = contextWith(() => ({ stdout: REPORT, stderr: "" }));
    const result = await runKnip(ctx);

    expect(result.artifacts).toEqual([join(RUN_DIR, "raw", "knip", "knip.json")]);
    expect(fs.writes[0]?.content).toBe(REPORT);
  });

  test("a repository with no manifest is skipped, not failed", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }), { targetDir: fixtureRepo("no-such") });
    const result = await runKnip(ctx);

    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("no package.json");
    expect(result.findings).toEqual([]);
  });

  test("a missing tool is skipped with what the run loses", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }), { tools: harnessResolver({}) });
    const result = await runKnip(ctx);

    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("sentinel setup");
  });

  test("a crash with no output is a failure, with the tool's own words", async () => {
    const { ctx } = contextWith(() => ({
      exitCode: 1,
      stdout: "",
      stderr: "Error: Cannot find module 'knip/dist/index.js'",
    }));
    const result = await runKnip(ctx);

    expect(result.status).toBe("failed");
    expect(result.reason).toContain("Cannot find module");
    expect(result.findings).toEqual([]);
  });

  test("output that is not the expected shape is refused, not guessed at", async () => {
    const { ctx } = contextWith(() => ({ stdout: '{"issues": 3}' }));
    const result = await runKnip(ctx);

    expect(result.status).toBe("failed");
    expect(result.reason).toContain("unexpected shape");
  });

  test("a timeout is a failure the report can name", async () => {
    const { ctx } = contextWith(() => ({ timedOut: true, stdout: "" }), { timeoutMs: 1_000 });
    const result = await runKnip(ctx);

    expect(result.status).toBe("failed");
    expect(result.reason).toBe("knip timed out after 1000 ms");
  });

  test("a candidate whose file does not exist is dropped and counted", async () => {
    const report = JSON.stringify({
      issues: [
        {
          file: "src/deleted.ts",
          files: [{ name: "src/deleted.ts" }],
          dependencies: [],
          devDependencies: [],
          optionalPeerDependencies: [],
          unlisted: [],
          unresolved: [],
          exports: [],
          types: [],
        },
      ],
    });
    const { ctx } = contextWith(() => ({ stdout: report }));
    const result = await runKnip(ctx);

    expect(result.status).toBe("degraded");
    expect(result.findings).toEqual([]);
    expect(result.reason).toContain("1 candidate(s) dropped");
  });

  test("an error on knip's stderr is disclosed, not swallowed", async () => {
    const { ctx } = contextWith(() => ({
      stdout: REPORT,
      stderr: "ERROR: Error loading jest.config.ts (Cannot find module 'ts-jest')",
    }));
    const result = await runKnip(ctx);

    expect(result.status).toBe("degraded");
    expect(result.reason).toContain(
      "entry point that configuration would have declared is missing",
    );
    expect(result.reason).toContain("ts-jest");
    expect(result.findings).toHaveLength(6);
  });

  test("a rule over the volume threshold is named in the step's reason", async () => {
    const issues = Array.from({ length: 30 }, (_, index) => ({
      file: "src/b.ts",
      files: [],
      dependencies: [],
      devDependencies: [],
      optionalPeerDependencies: [],
      unlisted: [],
      unresolved: [],
      exports: [{ name: `symbol${index}`, line: 7, col: 1 }],
      types: [],
    }));
    const { ctx } = contextWith(() => ({ stdout: JSON.stringify({ issues }) }));
    const result = await runKnip(ctx);

    expect(result.findings).toHaveLength(30);
    expect(result.reason).toContain("volume threshold of 25");
    expect(result.reason).toContain("deadcode.unused-export (30)");
  });
});

describe("planKnipConfig", () => {
  test("a single-package repository keeps knip's own defaults", async () => {
    const { ctx, fs } = contextWith(() => ({ stdout: REPORT }));
    const plan = await planKnipConfig(ctx);

    expect(plan.source).toBe("default");
    expect(plan.monorepo).toBe(false);
    expect(plan.configPath).toBeNull();
    expect(fs.writes).toEqual([]);
  });

  test("a monorepo gets a configuration declaring its workspaces and entry points", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }), {
      targetDir: MONOREPO,
      profile: monorepoProfile(),
    });
    const plan = await planKnipConfig(ctx);

    expect(plan.source).toBe("generated");
    expect(plan.workspaces).toEqual([".", "packages/tool"]);
    expect(plan.entryPatterns).toContain("apps/api/src/main.ts");
    expect(plan.entryPatterns).toContain("db/migrations/*.{js,mjs,cjs,ts,mts,cts}");
    expect(plan.entryPatterns).toContain("**/*.{test,spec}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}");
    // knip's own defaults are repeated: a configured workspace loses them.
    expect(plan.entryPatterns).toContain("{index,cli,main}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}");
  });

  test("the generated configuration always declares the root workspace", async () => {
    const { ctx, fs } = contextWith(() => ({ stdout: REPORT }), {
      targetDir: MONOREPO,
      profile: monorepoProfile(),
    });
    await runKnip(ctx);

    const config = generatedConfig(fs.writes);
    // Without the `.` key every root pattern above is silently ignored by knip.
    expect(Object.keys(config.workspaces)).toContain(".");
    expect(config.workspaces["."]?.entry).toContain("apps/api/src/main.ts");
  });

  test("the configuration is written to the run directory, never to the target", async () => {
    const { ctx, fs, exec } = contextWith(() => ({ stdout: REPORT }), {
      targetDir: MONOREPO,
      profile: monorepoProfile(),
    });
    const result = await runKnip(ctx);

    for (const write of fs.writes) expect(write.path.startsWith(MONOREPO)).toBe(false);
    const configPath = join(RUN_DIR, "raw", KNIP_STEP, GENERATED_CONFIG_NAME);
    expect(fs.writes.map((write) => write.path)).toContain(configPath);
    expect(exec.runs[0]?.args).toEqual([
      "--reporter",
      "json",
      "--no-exit-code",
      "--config",
      configPath,
    ]);
    expect(result.artifacts).toContain(configPath);
    expect(result.reason).toContain("entry pattern(s)");
  });

  test("a repository with its own knip configuration is left to it", async () => {
    const { ctx, fs, exec } = contextWith(() => ({ stdout: REPORT }), {
      targetDir: MONOREPO,
      profile: monorepoProfile(),
      fs: Object.assign(globbingFileSystem(), {
        exists: async (path: string) =>
          path.endsWith("knip.json") || (await createFileSystem().exists(path)),
      }),
    });
    const plan = await planKnipConfig(ctx);
    await runKnip(ctx);

    expect(plan.source).toBe("target");
    expect(plan.document).toBeNull();
    expect(fs.writes.some((write) => write.path.endsWith(GENERATED_CONFIG_NAME))).toBe(false);
    expect(exec.runs[0]?.args).not.toContain("--config");
  });

  test("a monorepo whose entry points cannot be derived says so instead of guessing", async () => {
    // Phase 0 proved a monorepo, but there is no project directory, no test
    // runner and no migrations: nothing to declare that knip's defaults do not
    // already cover, so no configuration is written and the run is graded down.
    const { ctx } = contextWith(() => ({ stdout: REPORT }), {
      profile: profileWith(TARGET, [["repo-layout", "monorepo"]]),
    });
    const plan = await planKnipConfig(ctx);
    const result = await runKnip(ctx);

    expect(plan.source).toBe("default");
    expect(plan.monorepo).toBe(true);
    expect(plan.document).toBeNull();
    for (const finding of result.findings) expect(finding.confidence).toBe("low");
    expect(result.reason).toContain("another project in the repository imports");
  });

  test("a monorepo tool in a one-package repository does not make it a monorepo", async () => {
    // `turbo.json`, `nx.json` or a pnpm 10 settings file can sit in a repository
    // with exactly one project; a marker is a reason to look, not a verdict.
    const { ctx } = contextWith(() => ({ stdout: REPORT }), {
      fs: Object.assign(globbingFileSystem(), {
        exists: async (path: string) =>
          path.endsWith("turbo.json") || (await createFileSystem().exists(path)),
      }),
    });
    const plan = await planKnipConfig(ctx);

    expect(plan.source).toBe("default");
    expect(plan.monorepo).toBe(false);
    expect(plan.document).toBeNull();
  });

  test("a pnpm workspace file that lists no packages is not a monorepo marker", async () => {
    const settingsOnly = "ignoredBuiltDependencies:\n  - sharp\n";
    const { ctx } = contextWith(() => ({ stdout: REPORT }), {
      fs: Object.assign(globbingFileSystem(), {
        exists: async (path: string) =>
          path.endsWith("pnpm-workspace.yaml") || (await createFileSystem().exists(path)),
        readFile: async (path: string) =>
          path.endsWith("pnpm-workspace.yaml")
            ? settingsOnly
            : await createFileSystem().readFile(path),
      }),
    });
    const plan = await planKnipConfig(ctx);

    expect(plan.monorepo).toBe(false);
    expect(plan.source).toBe("default");
  });
});

describe("knipEvidence", () => {
  const generated = {
    source: "generated" as const,
    configPath: "/runs/raw/knip/knip.config.json",
    document: "{}",
    workspaces: [".", "packages/tool"],
    entryPatterns: ["apps/api/src/main.ts"],
    monorepo: true,
    derivations: ["one project entry file"],
  };

  test("a configured monorepo with its dependencies installed is medium confidence", () => {
    const evidence = knipEvidence(generated, true);

    expect(evidence.confidence).toBe("medium");
    expect(evidence.caveat).toContain("configuration Sentinel generated");
    expect(evidence.caveat).toContain("knip.config.json");
  });

  test("a monorepo knip read as one package is low confidence, and says why", () => {
    const evidence = knipEvidence({ ...generated, source: "default", monorepo: true }, true);

    expect(evidence.confidence).toBe("low");
    expect(evidence.caveat).toContain("another project in the repository imports");
  });

  test("a target whose dependencies are not installed is low confidence, and says why", () => {
    const evidence = knipEvidence(generated, false);

    expect(evidence.confidence).toBe("low");
    expect(evidence.caveat).toContain("dependencies are not installed");
  });

  test("the confidence and the reason reach the findings and the step", async () => {
    const { ctx } = contextWith(() => ({ stdout: REPORT }));
    const weak = await runKnip(ctx);
    for (const finding of weak.findings) expect(finding.confidence).toBe("low");
    expect(weak.status).toBe("degraded");
    expect(weak.reason).toContain("dependencies are not installed");

    const installed = contextWith(() => ({ stdout: REPORT }), {
      fs: Object.assign(globbingFileSystem(), {
        exists: async (path: string) =>
          path.endsWith("node_modules") || (await createFileSystem().exists(path)),
      }),
    });
    const strong = await runKnip(installed.ctx);
    for (const finding of strong.findings) expect(finding.confidence).toBe("medium");
    expect(strong.status).toBe("ok");
  });
});
