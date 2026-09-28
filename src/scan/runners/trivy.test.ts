import { describe, expect, test } from "bun:test";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createStubProcessExecutor } from "../../ports/process-executor.ts";
import {
  TRIVY_STEP,
  type TrivyFileSystem,
  type TrivyRunContext,
  configArgs,
  misconfigPlan,
  runTrivy,
  sbomArgs,
  vulnerabilityArgs,
} from "./trivy.ts";

/** The fixture repository the fixture payloads were really captured against. */
const TARGET_DIR = `${import.meta.dir}/../parsers/__fixtures__/repo`;
const FIXTURES = `${import.meta.dir}/../parsers/__fixtures__`;
const RUN_DIR = "/tmp/sentinel-run";

const fsReport = await Bun.file(`${FIXTURES}/trivy-fs.json`).text();
const sbomReport = await Bun.file(`${FIXTURES}/trivy-sbom.cdx.json`).text();
const configReport = await Bun.file(`${FIXTURES}/trivy-config.json`).text();

/** Reads through the real port, captures every write in memory. */
function recordingFileSystem(): { fs: TrivyFileSystem; written: Map<string, string> } {
  const real = createFileSystem();
  const written = new Map<string, string>();
  return {
    written,
    fs: {
      readFile: (path) => real.readFile(path),
      readFileBytes: (path) => real.readFileBytes(path),
      realpath: (path) => real.realpath(path),
      exists: (path) => real.exists(path),
      mkdirp: async () => undefined,
      writeFile: async (path, data) => {
        written.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
      },
    },
  };
}

/** Which pass a spawned command is, judged the way trivy's own flags read. */
function passOf(args: readonly string[]): "config" | "sbom" | "vuln" {
  if (args[0] === "config") return "config";
  return args.includes("cyclonedx") ? "sbom" : "vuln";
}

interface Spawn {
  readonly command: string;
  readonly args: readonly string[];
}

/** What a scripted trivy prints for each pass. */
interface Script {
  readonly vuln?: { stdout?: string; stderr?: string; exitCode?: number; timedOut?: boolean };
  readonly sbom?: { stdout?: string; stderr?: string; exitCode?: number };
  readonly config?: { stdout?: string; stderr?: string; exitCode?: number };
}

function harness(script: Script = {}, context: Partial<TrivyRunContext> = {}) {
  const spawns: Spawn[] = [];
  const { fs, written } = recordingFileSystem();
  const exec = createStubProcessExecutor((command, args) => {
    spawns.push({ command, args });
    const pass = passOf(args);
    const scripted = script[pass];
    const fallback = pass === "vuln" ? fsReport : pass === "sbom" ? sbomReport : configReport;
    return {
      stdout: scripted?.stdout ?? fallback,
      stderr: scripted?.stderr ?? "",
      exitCode: scripted?.exitCode ?? 0,
      ...(pass === "vuln" && script.vuln?.timedOut === true ? { timedOut: true } : {}),
    };
  });
  const full: TrivyRunContext = {
    fs,
    exec,
    tools: { resolve: async () => "/opt/trivy/trivy" },
    targetDir: TARGET_DIR,
    runDir: RUN_DIR,
    ...context,
  };
  return { context: full, spawns, written };
}

/** A profile that proves exactly the delivery technologies it is given. */
function profileWith(facts: ReadonlyArray<[DetectedFact["kind"], string]>): StackProfile {
  return {
    schemaVersion: "1.0",
    target: TARGET_DIR,
    facts: facts.map(([kind, value]) => ({
      kind,
      value,
      confidence: "high",
      evidence: [{ file: "package.json", line: 1 }],
    })),
    absences: [],
    warnings: [],
    scan: { filesSeen: 6, filesRead: 6, truncated: false },
  };
}

describe("trivy passes", () => {
  test("runs the three documented passes, in the repository", async () => {
    const { context, spawns } = harness();
    await runTrivy(context);
    expect(spawns.map((spawn) => passOf(spawn.args))).toEqual(["vuln", "sbom", "config"]);
    expect(spawns.every((spawn) => spawn.command === "/opt/trivy/trivy")).toBe(true);
  });

  test("asks for the package graph and keeps secrets out of the vulnerability pass", () => {
    const args = vulnerabilityArgs({ targetDir: "." } as TrivyRunContext, ".");
    expect(args.slice(0, 6)).toEqual([
      "fs",
      "--format",
      "json",
      "--scanners",
      "vuln",
      "--list-all-pkgs",
    ]);
    expect(args).not.toContain("--skip-db-update");
    expect(args.at(-1)).toBe(".");
  });

  test("generates the SBOM without touching the vulnerability database", () => {
    const args = sbomArgs({} as TrivyRunContext, ".");
    expect(args).toContain("cyclonedx");
    expect(args).toContain("license");
    expect(args).not.toContain("vuln");
  });

  test("an offline run reuses the cached database and checks, and says so", async () => {
    const { context, spawns } = harness({}, { offline: true });
    const outcome = await runTrivy(context);
    expect(spawns[0]?.args).toContain("--skip-db-update");
    expect(spawns[2]?.args).toContain("--skip-check-update");
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("vulnerability database was not updated");
  });

  test("honours a cache directory override", () => {
    const args = configArgs({ cacheDir: "/cache/trivy" } as TrivyRunContext, ".", ["dockerfile"]);
    expect(args).toContain("--cache-dir");
    expect(args[args.indexOf("--cache-dir") + 1]).toBe("/cache/trivy");
  });
});

describe("choosing what the misconfiguration pass scans", () => {
  test("derives the scanners from the profile", () => {
    const plan = misconfigPlan(
      profileWith([
        ["container", "dockerfile"],
        ["iac", "kubernetes"],
        ["iac", "terraform"],
      ]),
    );
    expect(plan.scanners).toEqual(["dockerfile", "kubernetes", "terraform"]);
    expect(plan.uncovered).toEqual([]);
  });

  test("discloses what trivy has no checks for instead of dropping it", () => {
    const plan = misconfigPlan(
      profileWith([
        ["container", "docker-compose"],
        ["iac", "pulumi"],
      ]),
    );
    expect(plan.scanners).toEqual([]);
    expect(plan.uncovered.join(" ")).toContain("docker-compose");
    expect(plan.uncovered.join(" ")).toContain("Pulumi");
  });

  test("scans everything supported when there is no profile to narrow it", () => {
    expect(misconfigPlan(undefined).scanners).toContain("helm");
  });

  test("skips the pass, and only that pass, when the repository has no config files", async () => {
    const { context, spawns } = harness({}, { profile: profileWith([["package-manager", "npm"]]) });
    const outcome = await runTrivy(context);
    expect(spawns.map((spawn) => passOf(spawn.args))).toEqual(["vuln", "sbom"]);
    expect(outcome.status).toBe("ok");
    expect(outcome.reason).toContain("no Dockerfile");
    expect(outcome.findings.some((finding) => finding.domain === "delivery")).toBe(false);
  });

  test("passes the narrowed scanner list to trivy", async () => {
    const { context, spawns } = harness(
      {},
      {
        profile: profileWith([
          ["container", "dockerfile"],
          ["iac", "terraform"],
        ]),
      },
    );
    await runTrivy(context);
    const args = spawns[2]?.args ?? [];
    expect(args[args.indexOf("--misconfig-scanners") + 1]).toBe("dockerfile,terraform");
  });
});

describe("normalised output", () => {
  test("returns every domain the three passes cover, verified against disk", async () => {
    const { context } = harness();
    const outcome = await runTrivy(context);

    expect(outcome.step).toBe(TRIVY_STEP);
    expect(outcome.status).toBe("ok");
    const rules = new Map<string, number>();
    for (const finding of outcome.findings) {
      rules.set(finding.rule, (rules.get(finding.rule) ?? 0) + 1);
    }
    expect(rules.get("dependencies.vulnerable-package")).toBe(5);
    expect(rules.get("dependencies.copyleft-license")).toBe(2);
    expect(rules.get("dependencies.unknown-license")).toBe(1);
    expect(rules.get("delivery.dockerfile-misconfig")).toBe(3);
    expect(rules.get("delivery.kubernetes-misconfig")).toBe(2);
    expect(rules.get("delivery.terraform-misconfig")).toBe(2);
  });

  test("every snippet is extracted from the repository, never from trivy's text", async () => {
    const { context } = harness();
    const outcome = await runTrivy(context);
    for (const finding of outcome.findings) {
      expect(finding.location.snippet).toBeDefined();
    }
    const latestTag = outcome.findings.find((finding) => finding.title.includes("DS-0001"));
    expect(latestTag?.location.snippet).toContain("FROM node:latest");
    const bodyParser = outcome.findings.find((finding) => finding.title.includes("CVE-2024-45590"));
    expect(bodyParser?.location.snippet).toContain("node_modules/body-parser");
  });

  test("reads the target's own package.json to tell direct from transitive", async () => {
    const { context } = harness();
    const outcome = await runTrivy(context);
    const request = outcome.findings.find((finding) => finding.title.includes("CVE-2023-28155"));
    expect(request?.description).toContain("Direct dependency");
    const qs = outcome.findings.find((finding) => finding.title.includes("CVE-2022-24999"));
    expect(qs?.description).toContain("Transitive dependency");
    expect(qs?.description).toContain("express@4.17.1 → qs@6.7.0");
  });

  test("writes each pass's untouched output under raw/trivy/ and lists it", async () => {
    const { context, written } = harness();
    const outcome = await runTrivy(context);
    expect(outcome.artifacts).toEqual([
      `${RUN_DIR}/raw/trivy/fs.json`,
      `${RUN_DIR}/raw/trivy/sbom.cdx.json`,
      `${RUN_DIR}/raw/trivy/config.json`,
    ]);
    expect(written.get(`${RUN_DIR}/raw/trivy/fs.json`)).toBe(fsReport);
    expect(written.get(`${RUN_DIR}/raw/trivy/config.json`)).toBe(configReport);
  });
});

describe("degrading honestly", () => {
  test("a missing trivy is skipped, with what the report loses", async () => {
    const { context, spawns } = harness({}, { tools: { resolve: async () => null } });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("skipped");
    expect(outcome.findings).toEqual([]);
    expect(outcome.artifacts).toEqual([]);
    expect(outcome.reason).toContain("sentinel setup");
    expect(outcome.reason).toContain("misconfiguration");
    expect(spawns).toEqual([]);
  });

  test("a non-zero exit with parseable findings is a success", async () => {
    const { context } = harness({
      vuln: { exitCode: 1 },
      sbom: { exitCode: 1 },
      config: { exitCode: 1 },
    });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("ok");
    expect(outcome.findings.length).toBeGreaterThan(0);
  });

  test("an admitted fallback to embedded checks is degraded, not ok", async () => {
    const { context } = harness({
      config: {
        stderr:
          '2026-09-22T16:16:53-03:00\tERROR\t[misconfig] Falling back to embedded checks\terr="failed to check cache"\n',
      },
    });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("Falling back to embedded checks");
  });

  test("a fatal trivy with nothing on stdout fails, quoting its own error", async () => {
    const fatal =
      "2026-09-22T16:16:53-03:00\tFATAL\tFatal error\trun error: init error: DB error: --skip-db-update cannot be specified on the first run\n";
    const { context } = harness({
      vuln: { stdout: "", stderr: fatal, exitCode: 1 },
      sbom: { stdout: "", stderr: fatal, exitCode: 1 },
      config: { stdout: "", stderr: fatal, exitCode: 1 },
    });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("failed");
    expect(outcome.reason).toContain("cannot be specified on the first run");
    expect(outcome.findings).toEqual([]);
    // The stderr is still kept as evidence of what happened.
    expect(outcome.artifacts).toContain(`${RUN_DIR}/raw/trivy/fs.json.stderr.log`);
  });

  test("output that is not JSON degrades that pass instead of crashing the run", async () => {
    const { context } = harness({ config: { stdout: "not json at all\n" } });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("not valid JSON");
    // The other two passes still contributed.
    expect(outcome.findings.some((finding) => finding.domain === "dependencies")).toBe(true);
    expect(outcome.findings.some((finding) => finding.domain === "delivery")).toBe(false);
  });

  test("a timeout fails that pass and says how long it waited", async () => {
    const { context } = harness({ vuln: { stdout: "", timedOut: true } }, { timeoutMs: 1_000 });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("timed out after 1000 ms");
  });

  test("a citation trivy reports for a file that is not there is dropped and counted", async () => {
    const report = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Target: "does-not-exist/package-lock.json",
          Class: "lang-pkgs",
          Type: "npm",
          Packages: [{ ID: "lodash@4.17.15", Name: "lodash", Version: "4.17.15" }],
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2021-23337",
              PkgID: "lodash@4.17.15",
              PkgName: "lodash",
              InstalledVersion: "4.17.15",
              Severity: "HIGH",
            },
          ],
        },
      ],
    });
    const { context } = harness({ vuln: { stdout: report } });
    const outcome = await runTrivy(context);
    expect(outcome.status).toBe("degraded");
    // The CVE, plus the copyleft finding that inherits the same bogus manifest path.
    expect(outcome.reason).toContain("2 finding(s) dropped");
    expect(
      outcome.findings.some((finding) => finding.rule === "dependencies.vulnerable-package"),
    ).toBe(false);
  });
});
