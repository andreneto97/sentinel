import { describe, expect, test } from "bun:test";
import {
  CONFIG_FILE_NAME,
  ConfigFileSchema,
  type ConfigFileSystem,
  DEFAULT_MAX_PARALLEL,
  configPath,
  emptyConfigFile,
  loadConfig,
  resolveAnalyzeOptions,
  saveConfig,
  serializeConfig,
} from "./config.ts";
import { SCHEMA_VERSION } from "./findings.ts";
import { SentinelConfigSchema } from "./proposal.ts";

/** In-memory stand-in for the filesystem port, so these tests touch no disk. */
class MemoryFileSystem implements ConfigFileSystem {
  readonly files = new Map<string, string>();

  async writeFile(path: string, data: string): Promise<void> {
    this.files.set(path, data);
  }

  async readFile(path: string): Promise<string> {
    const content = this.files.get(path);
    if (content === undefined) throw new Error(`ENOENT: ${path}`);
    return content;
  }

  async exists(path: string): Promise<boolean> {
    return this.files.has(path);
  }
}

const CONFIG_PATH = `/repo/${CONFIG_FILE_NAME}`;

describe("ConfigFileSchema", () => {
  test("is the proposal contract plus the CLI-owned sections", () => {
    const config = emptyConfigFile();
    expect(config.schemaVersion).toBe(SCHEMA_VERSION);
    expect(config.answers).toEqual({});
    expect(config.domains).toEqual({ include: [], exclude: [] });
    expect(config.tools).toEqual({});
    expect(config.analyze).toEqual({});
  });

  test("accepts a document the propose phase wrote, which knows nothing of the extra sections", () => {
    const written = SentinelConfigSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      answers: { "iac.terraform": "on" },
    });
    const reread = ConfigFileSchema.safeParse(written);
    expect(reread.success).toBe(true);
    if (!reread.success) return;
    expect(reread.data.answers["iac.terraform"]).toBe("on");
    expect(reread.data.tools).toEqual({});
  });

  test("rejects an answer that is neither on nor off", () => {
    const parsed = ConfigFileSchema.safeParse({
      schemaVersion: SCHEMA_VERSION,
      answers: { iam: "maybe" },
    });
    expect(parsed.success).toBe(false);
  });

  test("rejects a domain override it does not know", () => {
    const parsed = ConfigFileSchema.safeParse({
      schemaVersion: SCHEMA_VERSION,
      domains: { include: ["astrology"], exclude: [] },
    });
    expect(parsed.success).toBe(false);
  });
});

describe("loadConfig", () => {
  test("treats a missing file as an empty config rather than an error", async () => {
    const result = await loadConfig(new MemoryFileSystem(), "/repo");
    expect(result.status).toBe("missing");
    if (result.status !== "missing") return;
    expect(result.path).toBe(CONFIG_PATH);
    expect(result.config).toEqual(emptyConfigFile());
  });

  test("validates the parsed document instead of trusting it", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile(
      CONFIG_PATH,
      JSON.stringify({ schemaVersion: SCHEMA_VERSION, analyze: { maxParallel: 3 } }),
    );
    const result = await loadConfig(fs, "/repo");
    expect(result.status).toBe("loaded");
    if (result.status !== "loaded") return;
    expect(result.config.analyze.maxParallel).toBe(3);
  });

  test("reports unparseable JSON without throwing", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile(CONFIG_PATH, "{ not json");
    const result = await loadConfig(fs, "/repo");
    expect(result.status).toBe("invalid");
    if (result.status !== "invalid") return;
    expect(result.error).toContain("not valid JSON");
  });

  test("reports a schema violation with the offending path", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile(
      CONFIG_PATH,
      JSON.stringify({ schemaVersion: SCHEMA_VERSION, analyze: { maxParallel: -4 } }),
    );
    const result = await loadConfig(fs, "/repo");
    expect(result.status).toBe("invalid");
    if (result.status !== "invalid") return;
    expect(result.error).toContain("analyze.maxParallel");
  });
});

describe("saveConfig", () => {
  test("round-trips through loadConfig, keeping the CLI sections", async () => {
    const fs = new MemoryFileSystem();
    const path = await saveConfig(fs, "/repo", {
      schemaVersion: SCHEMA_VERSION,
      answers: { iam: "on" },
      tools: { hadolint: { enabled: false } },
      analyze: { maxParallel: 4 },
    });
    expect(path).toBe(configPath("/repo"));

    const result = await loadConfig(fs, "/repo");
    expect(result.status).toBe("loaded");
    if (result.status !== "loaded") return;
    expect(result.config.answers.iam).toBe("on");
    expect(result.config.tools.hadolint).toEqual({ enabled: false });
    expect(result.config.analyze.maxParallel).toBe(4);
  });

  test("serialises answers in a stable order, newline-terminated", () => {
    const text = serializeConfig({
      schemaVersion: SCHEMA_VERSION,
      answers: { zebra: "on", alpha: "off" },
    });
    expect(text.endsWith("\n")).toBe(true);
    expect(text.indexOf("alpha")).toBeLessThan(text.indexOf("zebra"));
  });
});

describe("resolveAnalyzeOptions", () => {
  const base = { target: "/repo", cwd: "/work" };

  test("falls back to the built-in defaults", () => {
    const options = resolveAnalyzeOptions({ ...base, flags: {} });
    expect(options.target).toBe("/repo");
    expect(options.outDir).toBe("/repo/sentinel");
    expect(options.ai).toBe(true);
    expect(options.maxParallel).toBe(DEFAULT_MAX_PARALLEL);
    expect(options.skipScan).toBe(false);
    expect(options.proposeOnly).toBe(false);
    // Nothing said about the budget means "take the defaults", which this layer
    // expresses by saying nothing rather than by inventing a number: the ceilings
    // themselves live in `audit/budget.ts`.
    expect(options.auditBudget).toEqual({});
  });

  describe("the audit budget", () => {
    test("carries each ceiling the flags gave, under the budget's own names", () => {
      const options = resolveAnalyzeOptions({
        ...base,
        flags: { maxBatches: 12, maxUnits: 300, maxAuditMinutes: 5 },
      });
      expect(options.auditBudget).toEqual({ maxBatches: 12, maxUnits: 300, maxMinutes: 5 });
    });

    test("passes --no-budget through as `unbounded`", () => {
      const options = resolveAnalyzeOptions({ ...base, flags: { noBudget: true } });
      expect(options.auditBudget).toEqual({ unbounded: true });
    });

    test("omits a ceiling that was not given, so the default is not overwritten", () => {
      const options = resolveAnalyzeOptions({ ...base, flags: { maxBatches: 4 } });
      expect(options.auditBudget).toEqual({ maxBatches: 4 });
      expect("maxUnits" in options.auditBudget).toBe(false);
      expect("maxMinutes" in options.auditBudget).toBe(false);
    });
  });

  describe("--path", () => {
    test("defaults to the whole repository", () => {
      const options = resolveAnalyzeOptions({ ...base, flags: {} });
      expect(options.pathSelectors).toEqual([]);
      expect(options.pathFromFlag).toBe(false);
    });

    // Narrowing decides what a dossier does not cover, so it is made in the
    // invocation that produces the dossier -- never by a file an earlier run
    // left behind. The remembered value is carried so the run can report it.
    test("a remembered scope is reported but never applied on its own", () => {
      const config = ConfigFileSchema.parse({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      });
      const options = resolveAnalyzeOptions({ ...base, flags: {}, config });
      expect(options.pathSelectors).toEqual([]);
      expect(options.carriedScope).toEqual(["apps/api"]);
      expect(options.pathFromFlag).toBe(false);
    });

    test("--path is what narrows a run, and it clears the carried scope", () => {
      const config = ConfigFileSchema.parse({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      });
      const options = resolveAnalyzeOptions({ ...base, flags: { path: ["apps/workers"] }, config });
      expect(options.pathSelectors).toEqual(["apps/workers"]);
      expect(options.carriedScope).toEqual([]);
      expect(options.saveScope).toBe(false);
    });

    test("the flag replaces the config's list rather than extending it", () => {
      const config = ConfigFileSchema.parse({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      });
      const options = resolveAnalyzeOptions({
        ...base,
        flags: { path: ["libs/shared"] },
        config,
      });
      expect(options.pathSelectors).toEqual(["libs/shared"]);
      expect(options.pathFromFlag).toBe(true);
    });

    test("an empty flag widens the run back to the whole repository, deliberately", () => {
      const config = ConfigFileSchema.parse({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      });
      const options = resolveAnalyzeOptions({ ...base, flags: { path: [] }, config });
      expect(options.pathSelectors).toEqual([]);
      expect(options.pathFromFlag).toBe(true);
    });

    test("trims but never lower-cases: two cases are two directories", () => {
      const options = resolveAnalyzeOptions({
        ...base,
        flags: { path: ["  apps/API  ", "", "   "] },
      });
      expect(options.pathSelectors).toEqual(["apps/API"]);
    });
  });

  test("resolves a relative target against the cwd", () => {
    expect(resolveAnalyzeOptions({ target: "api", cwd: "/work", flags: {} }).target).toBe(
      "/work/api",
    );
  });

  test("prefers the config file over the defaults", () => {
    const config = ConfigFileSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      analyze: { maxParallel: 6, ai: false, skipScan: true, out: "reports" },
    });
    const options = resolveAnalyzeOptions({ ...base, flags: {}, config });
    expect(options.maxParallel).toBe(6);
    expect(options.ai).toBe(false);
    expect(options.skipScan).toBe(true);
    expect(options.outDir).toBe("/repo/reports");
  });

  test("prefers CLI flags over the config file", () => {
    const config = ConfigFileSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      analyze: { maxParallel: 6, ai: false, skipScan: true, out: "reports" },
    });
    const options = resolveAnalyzeOptions({
      ...base,
      config,
      flags: { maxParallel: 1, ai: true, skipScan: false, out: "out" },
    });
    expect(options.maxParallel).toBe(1);
    expect(options.ai).toBe(true);
    expect(options.skipScan).toBe(false);
    // A --out flag is relative to where the user typed it, not to the target.
    expect(options.outDir).toBe("/work/out");
  });

  test("honours an absolute out in the config", () => {
    const config = ConfigFileSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      analyze: { out: "/var/sentinel" },
    });
    expect(resolveAnalyzeOptions({ ...base, flags: {}, config }).outDir).toBe("/var/sentinel");
  });

  test("hands the scope the selectors, the remembered answers and the domain overrides", () => {
    const config = ConfigFileSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      answers: { iam: "on" },
      domains: { include: ["serverless"], exclude: ["deadcode"] },
    });
    const options = resolveAnalyzeOptions({
      ...base,
      config,
      flags: { include: [" Terraform ", ""], exclude: ["IAM"], yes: true },
    });
    expect(options.scope.include).toEqual(["terraform"]);
    expect(options.scope.exclude).toEqual(["iam"]);
    expect(options.scope.acceptDefaults).toBe(true);
    expect(options.scope.previousAnswers).toEqual({ iam: "on" });
    expect(options.scope.domainOverrides).toEqual({
      include: ["serverless"],
      exclude: ["deadcode"],
    });
  });

  test("passes the reporting flags straight through", () => {
    const options = resolveAnalyzeOptions({ ...base, flags: { json: true, proposeOnly: true } });
    expect(options.json).toBe(true);
    expect(options.proposeOnly).toBe(true);
    expect(options.verbose).toBe(false);
    expect(options.quiet).toBe(false);
  });

  test("exposes the config's tool overrides", () => {
    const config = ConfigFileSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      tools: { hadolint: { enabled: false } },
    });
    const options = resolveAnalyzeOptions({ ...base, flags: {}, config });
    expect(options.toolOverrides.hadolint).toEqual({ enabled: false });
  });
});
