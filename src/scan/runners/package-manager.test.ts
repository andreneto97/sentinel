import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import type { Finding } from "../../contracts/findings.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import {
  type RunHandler,
  fixtureRepo,
  harnessExecutor,
  harnessFileSystem,
  harnessResolver,
} from "./__fixtures__/harness.ts";
import type { RunnerContext } from "./_runner-support.ts";
import { PACKAGE_MANAGER_STEP, runPackageManager } from "./package-manager.ts";

/** Reads one of the captured real outputs in the parser fixtures. */
async function fixture(name: string): Promise<string> {
  return await Bun.file(join(import.meta.dir, "../parsers/__fixtures__", name)).text();
}

/** Real `npm outdated --json --long` with node_modules installed. */
const NPM = await fixture("npm-outdated.json");
/** Real `bun outdated`, which has no JSON reporter. */
const BUN = await fixture("bun-outdated.txt");

/** A repository with one npm lockfile, overrides, and a dependency it omits. */
const PM_DEMO = fixtureRepo("pm-demo");
/** A repository with dependencies and no lockfile at all. */
const NODE_DEMO = fixtureRepo("node-demo");
const RUN_DIR = "/runs/2026-09-22";

/** A profile that proves one package manager, as phase 0 would. */
function profileFor(manager: string): StackProfile {
  return {
    schemaVersion: "1.0",
    target: PM_DEMO,
    facts: [
      {
        kind: "package-manager",
        value: manager,
        confidence: "high",
        evidence: [{ file: "package.json", line: 1 }],
      },
    ],
    absences: [],
    warnings: [],
    scan: { filesSeen: 2, filesRead: 2, truncated: false },
  };
}

/** A context over a real fixture repo, with the manager's output scripted. */
function contextWith(handler: RunHandler, overrides: Partial<RunnerContext> = {}) {
  const fs = harnessFileSystem();
  const exec = harnessExecutor(handler);
  const ctx: RunnerContext = {
    fs,
    exec,
    tools: harnessResolver({}),
    targetDir: PM_DEMO,
    runDir: RUN_DIR,
    profile: profileFor("npm"),
    ...overrides,
  };
  return { ctx, fs, exec };
}

/** The finding for one rule, or undefined when the runner did not emit it. */
function ruled(findings: readonly Finding[], rule: string): Finding | undefined {
  return findings.find((finding) => finding.rule === rule);
}

describe("runPackageManager — outdated", () => {
  test("separates patch, minor and major gaps", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    expect(result.step).toBe(PACKAGE_MANAGER_STEP);
    const outdated = result.findings.filter((finding) =>
      finding.rule.startsWith("dependencies.outdated-"),
    );
    expect(
      outdated.map((finding) => `${finding.rule}:${finding.title.split(" ")[0]}`).sort(),
    ).toEqual([
      "dependencies.outdated-major:chalk",
      "dependencies.outdated-major:rimraf",
      "dependencies.outdated-minor:semver",
    ]);
  });

  test("states current, wanted and latest, and cites the manifest line", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    const chalk = ruled(result.findings, "dependencies.outdated-major");
    expect(chalk?.title).toBe("chalk is a major release behind (4.1.2 to 6.0.0)");
    expect(chalk?.description).toContain("installed 4.1.2");
    expect(chalk?.description).toContain("allows up to 4.1.2");
    expect(chalk?.description).toContain("latest is 6.0.0");
    expect(chalk?.location.file).toBe("package.json");
    expect(chalk?.location.snippet).toContain('"chalk": "^4.0.0"');
    expect(chalk?.confidence).toBe("high");
  });

  test("a non-zero exit is how every manager says it found something", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test("keeps the manager's untouched output as an artifact", async () => {
    const { ctx, fs } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    expect(result.artifacts).toEqual([
      join(RUN_DIR, "raw", PACKAGE_MANAGER_STEP, "npm-outdated.json"),
    ]);
    expect(fs.writes.at(-1)?.content).toBe(NPM);
  });

  test("reads bun's table, since bun has no JSON reporter", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: BUN }), { profile: profileFor("bun") });
    const result = await runPackageManager(ctx);

    expect(exec.runs[0]?.command).toBe("bun");
    expect(exec.runs[0]?.args[0]).toBe("outdated");
    const biome = result.findings.find((finding) => finding.title.startsWith("@biomejs/biome"));
    expect(biome?.rule).toBe("dependencies.outdated-major");
  });
});

describe("runPackageManager — never touching the target", () => {
  test("points the registry cache outside the repository under analysis", async () => {
    const { ctx, exec } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    await runPackageManager(ctx);

    const env = exec.runs[0]?.options.env ?? {};
    expect(env.npm_config_cache).toBeDefined();
    expect(env.npm_config_cache?.startsWith(PM_DEMO)).toBe(false);
    expect(env.npm_config_ignore_scripts).toBe("true");
    expect(env.npm_config_audit).toBe("false");
  });

  test("writes nothing into the repository under analysis", async () => {
    const { ctx, fs } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    await runPackageManager(ctx);
    for (const write of fs.writes) expect(write.path.startsWith(PM_DEMO)).toBe(false);
  });

  test("only ever asks the manager what is outdated", async () => {
    const { ctx, exec } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    await runPackageManager(ctx);
    for (const run of exec.runs) expect(run.args[0]).toBe("outdated");
  });
});

describe("runPackageManager — lockfile hygiene", () => {
  test("a repository with no lockfile is a finding of its own", async () => {
    const { ctx } = contextWith(() => ({ notFound: true }), {
      targetDir: NODE_DEMO,
      profile: undefined,
    });
    const result = await runPackageManager(ctx);

    const missing = ruled(result.findings, "dependencies.missing-lockfile");
    expect(missing?.severity).toBe("medium");
    expect(missing?.location.file).toBe("package.json");
  });

  test("a dependency the lockfile never mentions is reported as drift", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    const drift = ruled(result.findings, "dependencies.lockfile-out-of-sync");
    expect(drift?.title).toBe("package-lock.json does not cover 1 declared dependency");
    expect(drift?.description).toContain("`dayjs`");
    expect(drift?.evidence[0]?.file).toBe("package-lock.json");
  });

  test("an override below the declared range is escalated", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    const below = ruled(result.findings, "dependencies.override-below-declared-range");
    expect(below?.title).toBe("`overrides` holds semver at 7.3.8, below the declared range");
    expect(below?.severity).toBe("medium");
    expect(below?.location.snippet).toContain('"semver": "7.3.8"');
  });

  test("an override on a package the manifest does not declare is still disclosed", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: NPM }));
    const result = await runPackageManager(ctx);

    const pinned = ruled(result.findings, "dependencies.pinned-override");
    expect(pinned?.title).toBe("`overrides` pins brace-expansion to 2.0.1");
    expect(pinned?.severity).toBe("low");
    expect(pinned?.description).toContain("patched version");
  });

  test("lockfile findings survive an outdated pass that could not run", async () => {
    const { ctx } = contextWith(() => ({ notFound: true }));
    const result = await runPackageManager(ctx);

    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("`npm` is not on PATH");
    expect(ruled(result.findings, "dependencies.lockfile-out-of-sync")).toBeDefined();
  });
});

describe("runPackageManager — degrading instead of hanging", () => {
  test("a registry that cannot be reached is reported as needing network", async () => {
    const { ctx } = contextWith(() => ({
      exitCode: 1,
      stdout: "",
      stderr: "npm ERR! code ENOTFOUND\nnpm ERR! getaddrinfo ENOTFOUND registry.npmjs.org",
    }));
    const result = await runPackageManager(ctx);

    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("needs network");
  });

  test("a timeout is reported, never waited out", async () => {
    const { ctx } = contextWith(() => ({ timedOut: true }), { timeoutMs: 5_000 });
    const result = await runPackageManager(ctx);

    expect(result.reason).toContain("needs network");
    expect(result.reason).toContain("5000 ms");
  });

  test("offline adds the manager's offline flag", async () => {
    const { ctx, exec } = contextWith(() => ({ exitCode: 1, stdout: NPM }), { offline: true });
    await runPackageManager(ctx);
    expect(exec.runs[0]?.args).toContain("--offline");
  });

  test("bun has no offline mode, so the check is skipped rather than attempted", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: BUN }), {
      profile: profileFor("bun"),
      offline: true,
    });
    const result = await runPackageManager(ctx);

    expect(exec.runs).toHaveLength(0);
    expect(result.reason).toContain("needs network");
  });

  test("yarn 2+ has no outdated command, and the report says so", async () => {
    const { ctx, exec } = contextWith(() => ({ stdout: "" }), {
      targetDir: fixtureRepo("yarn-berry-demo"),
      profile: undefined,
    });
    const result = await runPackageManager(ctx);

    expect(exec.runs).toHaveLength(0);
    expect(result.reason).toContain("yarn 2+");
  });

  test("output that cannot be parsed degrades the step, not the run", async () => {
    const { ctx } = contextWith(() => ({ exitCode: 1, stdout: "npm ERR! not json" }));
    const result = await runPackageManager(ctx);

    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("outdated check failed");
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test("a repository with no manifest is skipped, not failed", async () => {
    const { ctx } = contextWith(() => ({ stdout: "" }), { targetDir: fixtureRepo("no-such") });
    const result = await runPackageManager(ctx);

    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("no package.json");
  });
});
