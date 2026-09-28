import { describe, expect, test } from "bun:test";
import { emptyFailureCounts } from "../agents/errors.ts";
import type { AgentRunStats } from "../agents/types.ts";
import { ZERO_USAGE } from "../agents/usage.ts";
import type { BatchReport, DropAccounting } from "../audit/artifacts.ts";
import { buildAuditReport } from "../audit/artifacts.ts";
import {
  DEFAULT_MAX_BATCHES,
  DEFAULT_MAX_WALL_CLOCK_MS,
  UNBOUNDED_BUDGET,
} from "../audit/budget.ts";
import type { KindCoverage, UnitTotals } from "../audit/coverage.ts";
import { emptySkipCounts as emptyCauseCounts } from "../audit/coverage.ts";
import { type AuditProgress, createProgressTracker } from "../audit/progress.ts";
import type { Assurance, AuditUnit, Coverage, Finding } from "../contracts/findings.ts";
import { DomainSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { DroppedUnit } from "../contracts/inventory.ts";
import { InventoryDocumentSchema, zeroCounts } from "../contracts/inventory.ts";
import type { AnalysisScope } from "../contracts/scope.ts";
import { AnalysisScopeSchema } from "../contracts/scope.ts";
import { FakeClock } from "../ports/clock.ts";
import { createFileSystem } from "../ports/file-system.ts";
import { fixturePath } from "../profile/__fixtures__/fixture-file-system.ts";
import type { ProfileDirEntry } from "../profile/file-system-port.ts";
import { ScanReportSchema, buildFindingsDocument, toStepReport } from "../scan/artifacts.ts";
import type { ScanResult } from "../scan/scan.ts";
import type { StepOutcome } from "../scan/types.ts";
import type { Asker } from "./_shared/ask.ts";
import {
  type AnalyzeDeps,
  type AnalyzeFileSystem,
  type AuditOutcome,
  type AuditRequest,
  type InventoryOutcome,
  type InventoryRequest,
  type ScanRequest,
  analyzeCommand,
  plural as pluralFor,
} from "./analyze.ts";
import { type AnalyzeInvocation, type CliContext, EXIT, defaultContext } from "./index.ts";

/** A fake repository that also records what analyze wrote and which dirs it made. */
interface MemoryFileSystem extends AnalyzeFileSystem {
  readonly written: Map<string, string>;
  readonly dirs: string[];
}

/** A fake repository: absolute path → file contents. Directories are implied. */
function memoryFileSystem(files: Readonly<Record<string, string>>): MemoryFileSystem {
  const written = new Map<string, string>();
  const dirs: string[] = [];
  const all = (): Map<string, string> => new Map([...Object.entries(files), ...written]);
  const isDir = (path: string): boolean =>
    [...all().keys()].some((file) => file.startsWith(`${path}/`)) || dirs.includes(path);
  return {
    written,
    dirs,
    async readFile(path: string): Promise<string> {
      const body = all().get(path);
      if (body === undefined) throw new Error(`ENOENT: ${path}`);
      return body;
    },
    async writeFile(path: string, data: string): Promise<void> {
      written.set(path, data);
    },
    async mkdirp(path: string): Promise<void> {
      dirs.push(path);
    },
    async exists(path: string): Promise<boolean> {
      return all().has(path) || isDir(path);
    },
    async readDir(path: string): Promise<readonly ProfileDirEntry[]> {
      if (!isDir(path)) throw new Error(`ENOTDIR: ${path}`);
      const entries = new Map<string, ProfileDirEntry>();
      for (const file of all().keys()) {
        if (!file.startsWith(`${path}/`)) continue;
        const rest = file.slice(path.length + 1);
        const slash = rest.indexOf("/");
        const name = slash < 0 ? rest : rest.slice(0, slash);
        entries.set(name, { name, isFile: slash < 0, isDirectory: slash >= 0 });
      }
      return [...entries.values()];
    },
  };
}

/** A finding shaped like a real one, so the document it goes into is a real document. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "0123456789abcdef",
    domain: "delivery",
    rule: "delivery.container.root-user",
    severity: "high",
    confidence: "high",
    title: "The image runs as root",
    description: "No USER instruction, so the container runs as uid 0.",
    location: { file: "Dockerfile", line: 1 },
    evidence: [],
    impact: "A process escape starts with root in the container.",
    recommendation: "Add a non-root USER before the entrypoint.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "rule", name: "container-rules" },
    ...overrides,
  };
}

/**
 * A phase 1 result shaped exactly like the orchestrator's, built through the
 * same schemas: a stub that could not survive `findings.json` would prove
 * nothing about the seam it stands in for.
 */
function scanResult(request: ScanRequest, findings: readonly Finding[] = []): ScanResult {
  const outcomes: StepOutcome[] = [
    { step: "trivy", status: "ok", findings, artifacts: [], durationMs: 1_200 },
    {
      step: "hadolint",
      status: "skipped",
      reason: "the target has no Dockerfile",
      findings: [],
      artifacts: [],
      durationMs: 3,
    },
  ];
  const coverage: Coverage[] = request.domains.map((domain) => ({
    domain,
    unitsTotal: 2,
    unitsAudited: 1,
    skipped: [{ unitId: "hadolint", reason: "skipped: the target has no Dockerfile" }],
  }));
  const document = buildFindingsDocument({
    runId: request.runId,
    target: request.targetDir,
    findings,
    coverage,
    droppedFindings: 0,
  });
  const report = ScanReportSchema.parse({
    schemaVersion: document.schemaVersion,
    runId: request.runId,
    target: request.targetDir,
    aborted: false,
    durationMs: 1_203,
    steps: outcomes.map(toStepReport),
    dropped: { findings: 0, evidence: 0, byReason: {} },
    relocated: 0,
    merged: [],
    escalations: [],
  });
  return {
    runId: request.runId,
    target: request.targetDir,
    outcomes,
    findings: document.findings,
    coverage,
    document,
    report,
    outOfScope: 0,
    outsideScope: 0,
    aborted: false,
    durationMs: 1_203,
    artifacts: [`${request.runDir}/findings.json`, `${request.runDir}/scan-report.json`],
  };
}

/** The run id a fixed clock and a fixed random source always produce. */
const RUN_ID = "20240102T030405-abababab";

/** A unit shaped like a real one, so the document it goes into is a real document. */
function unit(overrides: Partial<AuditUnit> = {}): AuditUnit {
  return {
    id: "fedcba9876543210",
    kind: "route",
    label: "GET /users",
    location: { file: "src/server.js", line: 2 },
    attributes: { method: "GET", authCheck: "none" },
    ...overrides,
  };
}

/** A phase 2 outcome built through the real schema, like the orchestrator's. */
function inventoryOutcome(
  request: InventoryRequest,
  units: readonly AuditUnit[],
  extra: { readonly dropped?: readonly DroppedUnit[] } = {},
): InventoryOutcome {
  const counts = zeroCounts();
  for (const entry of units) counts[entry.kind] += 1;
  const document = InventoryDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: request.runId,
    target: request.targetDir,
    units,
    counts,
    enumerators: [
      { name: "routes", status: "ok", kinds: ["route"], units: units.length },
      {
        name: "queue-consumers",
        status: "skipped",
        reason: "no queue consumer is declared in this repository",
        kinds: ["queue-consumer"],
        units: 0,
      },
    ],
    dropped: extra.dropped ?? [],
  });
  return {
    document,
    artifacts: [`${request.runDir}/inventory.json`],
    durationMs: 900,
  };
}

/** Run `analyze` with captured streams over an injectable filesystem. */
async function run(
  target: string,
  flags: AnalyzeInvocation["flags"],
  deps: Partial<AnalyzeDeps> & { readonly fs: AnalyzeFileSystem },
) {
  let stdout = "";
  let stderr = "";
  const requests: ScanRequest[] = [];
  const context: CliContext = {
    ...defaultContext(),
    cwd: "/work",
    clock: new FakeClock(Date.UTC(2024, 0, 2, 3, 4, 5)),
    random: { hex: (bytes: number) => "ab".repeat(bytes) },
    write: (text) => {
      stdout += text;
    },
    writeError: (text) => {
      stderr += text;
    },
  };
  const provided: Partial<AnalyzeDeps> & { readonly fs: AnalyzeFileSystem } = deps;
  const scan = provided.scan ?? ((request: ScanRequest) => Promise.resolve(scanResult(request)));

  const code = await analyzeCommand(
    context,
    { target, cwd: "/work", flags },
    {
      availableTools: async () => [],
      // Phase 2 enumerates nothing by default, which is what makes the audit
      // unreachable unless a test opts into it by returning units.
      inventory: async (request) => inventoryOutcome(request, []),
      audit: async () => {
        throw new Error("the audit ran without a test asking for it");
      },
      ...provided,
      // Wrapped last, and around whatever the test injected: the real phase 1
      // leaves `findings.json` and `scan-report.json` on disk, and phases 6 and
      // 7 read them back off it. A scan runner that returned a document without
      // writing one would make every dossier assertion below a test of nothing.
      scan: async (request) => {
        requests.push(request);
        const result = await scan(request);
        await provided.fs.writeFile(
          `${request.runDir}/findings.json`,
          `${JSON.stringify(result.document, null, 2)}\n`,
        );
        await provided.fs.writeFile(
          `${request.runDir}/scan-report.json`,
          `${JSON.stringify(result.report, null, 2)}\n`,
        );
        return result;
      },
    },
  );
  return { code, stdout, stderr, requests };
}

/** A repo with a Dockerfile and Terraform: enough to make two proposals fire. */
const REPO: Readonly<Record<string, string>> = {
  "/repo/package.json": JSON.stringify({
    name: "api",
    dependencies: { express: "4.19.2", pg: "8.11.5" },
  }),
  "/repo/src/server.js": "const express = require('express');\napp.get('/users', handler);\n",
  "/repo/Dockerfile": "FROM node:20-alpine\nCOPY . .\n",
  "/repo/infra/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
};

describe("analyze", () => {
  test("profiles the repo and prints the proposals it would otherwise skip", async () => {
    const result = await run("/repo", { proposeOnly: true }, { fs: memoryFileSystem(REPO) });
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Profiled /repo");
    expect(result.stdout).toContain("backend-framework");
    expect(result.stdout).toContain("Terraform present but not scanned");
    expect(result.stdout).toContain("--include delivery.iac.terraform");
    expect(result.stdout).toContain("nothing was analysed and nothing was written");
  });

  test("asks the operator about every proposal and records the answers", async () => {
    const asked: string[] = [];
    const ask: Asker = async (question) => {
      asked.push(question);
      return question.includes("Terraform");
    };
    const result = await run("/repo", {}, { fs: memoryFileSystem(REPO), ask });

    expect(asked.length).toBeGreaterThan(1);
    expect(asked.some((question) => question.includes("Terraform"))).toBe(true);
    expect(result.stdout).toContain("Accepted: 1");
    // Saying no to the rest has to stay visible: declined, not silently absent.
    expect(result.stdout).toContain("Declined:");
    expect(result.stdout).not.toContain("Never answered (off): 3");
    // The run completed, so it ends with a dossier rather than a disclosure
    // about phases that have not been written yet.
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Scorecard");
  });

  test("never asks under --propose-only, --yes, --json or --quiet", async () => {
    const fs = memoryFileSystem(REPO);
    const ask: Asker = async () => {
      throw new Error("must not ask");
    };
    for (const flags of [{ proposeOnly: true }, { yes: true }, { json: true }, { quiet: true }]) {
      // The asker throws, so reaching any exit code at all is the assertion.
      const result = await run("/repo", flags, { fs, ask });
      expect(result.stderr).not.toContain("must not ask");
    }
  });

  test("--yes takes each proposal's default answer", async () => {
    const result = await run(
      "/repo",
      { proposeOnly: true, yes: true },
      { fs: memoryFileSystem(REPO), availableTools: async () => ["trivy", "hadolint"] },
    );
    // `trivy` is installed, so scanning the Terraform is cheap and defaults on.
    expect(result.stdout).toContain("Accepted: 1");
    // gitleaks and opengrep are still missing, so their install offers default off.
    expect(result.stdout).toContain("Declined: 2");
  });

  test("a proposal whose tool is missing defaults off even under --yes", async () => {
    const result = await run(
      "/repo",
      { proposeOnly: true, yes: true },
      { fs: memoryFileSystem(REPO) },
    );
    // Nothing is installed: accepting would buy nothing, so every offer is declined.
    expect(result.stdout).toContain("Accepted: 0");
    expect(result.stdout).toContain("Declined: 5");
  });

  test("an unanswered proposal stays off and is reported as unanswered", async () => {
    const result = await run("/repo", { proposeOnly: true }, { fs: memoryFileSystem(REPO) });
    expect(result.stdout).toContain("Never answered (off): ");
    expect(result.stdout).toContain("not answered, stayed off: delivery.iac.terraform");
  });

  test("--include accepts a proposal without asking", async () => {
    const result = await run(
      "/repo",
      { proposeOnly: true, include: ["delivery.iac.terraform"] },
      { fs: memoryFileSystem(REPO) },
    );
    expect(result.stdout).toContain("Accepted: 1");
  });

  test("reports a tool an accepted proposal needs but cannot find", async () => {
    const result = await run(
      "/repo",
      { proposeOnly: true, json: true, include: ["delivery.iac.terraform"] },
      { fs: memoryFileSystem(REPO) },
    );
    const payload = JSON.parse(result.stdout);
    expect(payload.decision.blockedOnMissingTool).toEqual([
      { proposalId: "delivery.iac.terraform", tool: "trivy" },
    ]);
  });

  test("emits a validated JSON document under --json", async () => {
    const result = await run(
      "/repo",
      { proposeOnly: true, json: true },
      { fs: memoryFileSystem(REPO) },
    );
    const payload = JSON.parse(result.stdout);
    expect(payload.schemaVersion).toBe("1.0");
    expect(payload.target).toBe("/repo");
    expect(payload.profile.scan.filesSeen).toBeGreaterThan(0);
    expect(payload.proposals.length).toBeGreaterThan(0);
    expect(payload.decision.enabledDomains).toContain("delivery");
  });

  test("a remembered answer is not asked again", async () => {
    const fs = memoryFileSystem({
      ...REPO,
      "/repo/sentinel.config.json": JSON.stringify({
        schemaVersion: "1.0",
        answers: { "delivery.iac.terraform": "on" },
      }),
    });
    const asked: string[] = [];
    const ask: Asker = async (question) => {
      asked.push(question);
      return false;
    };
    const result = await run("/repo", {}, { fs, ask });
    expect(asked.some((question) => question.includes("Terraform"))).toBe(false);
    expect(result.stdout).toContain("Accepted: 1");
  });

  test("refuses to guess at a malformed config", async () => {
    const fs = memoryFileSystem({ ...REPO, "/repo/sentinel.config.json": "{ not json" });
    const result = await run("/repo", { proposeOnly: true }, { fs });
    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("is unusable");
  });

  test("reports a missing target as a preflight failure", async () => {
    const result = await run("/nope", { proposeOnly: true }, { fs: memoryFileSystem(REPO) });
    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("does not exist");
  });

  test("runs over a real fixture repository through the real filesystem port", async () => {
    // The real port, unnarrowed: this fails to compile the day `FileSystem`
    // stops satisfying what analyze asks for.
    const fs: AnalyzeFileSystem = createFileSystem();
    const result = await run(fixturePath("monorepo"), { proposeOnly: true }, { fs });
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Terraform present but not scanned");
    expect(result.stdout).toContain("k8s/deployment.yaml");
  });
});

describe("phase 1", () => {
  test("creates the run directory and writes the phase 0 and 0.5 artifacts into it", async () => {
    const fs = memoryFileSystem(REPO);
    const result = await run("/repo", { yes: true }, { fs });

    expect(result.code).toBe(EXIT.ok);
    expect(fs.dirs).toContain(`/repo/sentinel/${RUN_ID}/raw`);
    expect(fs.written.get("/repo/sentinel/.latest")).toBe(`${RUN_ID}\n`);

    const profile = fs.written.get(`/repo/sentinel/${RUN_ID}/stack-profile.json`);
    expect(profile).toBeDefined();
    expect(JSON.parse(profile ?? "").target).toBe("/repo");

    const scope = fs.written.get(`/repo/sentinel/${RUN_ID}/scope-proposal.json`);
    expect(scope).toBeDefined();
    expect(JSON.parse(scope ?? "").decision.enabledDomains).toContain("delivery");
  });

  test("hands the scan the run it just created and the domains the scope turned on", async () => {
    const result = await run("/repo", { yes: true }, { fs: memoryFileSystem(REPO) });
    expect(result.requests).toHaveLength(1);
    const request = result.requests[0];
    expect(request?.runId).toBe(RUN_ID);
    expect(request?.runDir).toBe(`/repo/sentinel/${RUN_ID}`);
    expect(request?.targetDir).toBe("/repo");
    expect(request?.profile.target).toBe("/repo");
    expect(request?.domains).toEqual(["dependencies", "appsec", "data", "delivery", "deadcode"]);
  });

  test("an excluded domain never reaches the scan and is reported as off, not as clean", async () => {
    const result = await run(
      "/repo",
      { yes: true, exclude: ["delivery"] },
      { fs: memoryFileSystem(REPO) },
    );
    expect(result.requests[0]?.domains).not.toContain("delivery");
    expect(result.stdout).toContain("delivery      off — outside this run's scope");
    // The domains that did run are counted, so "off" cannot be read as "zero".
    expect(result.stdout).toContain("dependencies  0 findings");
  });

  test("a domain no phase has a check for says so instead of reporting zero findings", async () => {
    const result = await run(
      "/repo",
      { yes: true, include: ["serverless"] },
      {
        fs: memoryFileSystem(REPO),
        // What the orchestrator really produces for an enabled domain no step
        // covers: a 0/0 row. It must not read as "checked, found nothing".
        scan: async (request) => {
          const base = scanResult(request);
          return {
            ...base,
            coverage: base.coverage.map((entry) =>
              entry.domain === "serverless"
                ? { domain: entry.domain, unitsTotal: 0, unitsAudited: 0, skipped: [] }
                : entry,
            ),
          };
        },
      },
    );
    expect(result.stdout).toContain("on, but no phase has a check for it yet");
  });

  test("prints one line per step: status, findings, duration and the reason it did not run", async () => {
    const result = await run("/repo", { yes: true }, { fs: memoryFileSystem(REPO) });
    expect(result.stdout).toContain(`Scan ${RUN_ID} — 2 steps in 1.2s`);
    expect(result.stdout).toContain("[ ok ]  trivy");
    expect(result.stdout).toContain("[skip]  hadolint");
    expect(result.stdout).toContain("the target has no Dockerfile");
  });

  test("counts the findings the scan produced, per domain", async () => {
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        scan: async (request) =>
          scanResult(request, [
            finding(),
            finding({ id: "beef", location: { file: "Dockerfile", line: 2 } }),
          ]),
      },
    );
    expect(result.stdout).toContain("delivery      2 findings");
    expect(result.stdout).toContain("2 findings in findings.json");
  });

  test("--skip-scan runs nothing and says nothing was written", async () => {
    const fs = memoryFileSystem(REPO);
    const result = await run("/repo", { yes: true, skipScan: true }, { fs });
    expect(result.code).toBe(EXIT.ok);
    expect(result.requests).toHaveLength(0);
    expect(fs.dirs).toEqual([]);
    expect(result.stderr).toContain("no run directory was written");
  });

  test("--json carries the scan beside the scope, and only when one ran", async () => {
    const withScan = await run("/repo", { yes: true, json: true }, { fs: memoryFileSystem(REPO) });
    const payload = JSON.parse(withScan.stdout);
    expect(payload.scan.runId).toBe(RUN_ID);
    expect(payload.scan.steps.map((step: { step: string }) => step.step)).toEqual([
      "trivy",
      "hadolint",
    ]);
    expect(payload.scan.byDomain).toEqual({
      dependencies: 0,
      appsec: 0,
      data: 0,
      delivery: 0,
      deadcode: 0,
    });
    expect(payload.scan.domainsOff).toEqual(["serverless", "api", "reliability"]);
    // Coverage travels with the counts, so a zero can be told apart from a
    // domain no step covers.
    expect(payload.scan.coverage.map((entry: { domain: string }) => entry.domain)).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "deadcode",
    ]);

    const without = await run(
      "/repo",
      { proposeOnly: true, json: true },
      { fs: memoryFileSystem(REPO) },
    );
    expect(JSON.parse(without.stdout).scan).toBeUndefined();
  });

  test("a cancelled scan exits 130 and says the run directory is incomplete", async () => {
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        scan: async (request) => ({ ...scanResult(request), aborted: true }),
      },
    );
    expect(result.code).toBe(EXIT.interrupted);
    expect(result.stderr).toContain("incomplete");
  });

  test("an accepted proposal whose tool is missing is reported, not silently skipped", async () => {
    const result = await run(
      "/repo",
      { yes: true, include: ["delivery.iac.terraform"] },
      { fs: memoryFileSystem(REPO) },
    );
    expect(result.stderr).toContain("trivy is not installed");
  });
});

describe("phases 2 to 4", () => {
  /**
   * A phase 4 result shaped exactly like the orchestrator's, with one finding,
   * one assurance and one unit phase 3 chose not to batch. Built through
   * `buildAuditReport` and the real coverage types for the same reason the phase
   * 1 stub is: a stub that could not survive `audit.json` proves nothing.
   */
  function auditOutcome(request: AuditRequest, units: readonly AuditUnit[]): AuditOutcome {
    const claim = finding({
      id: "aaaabbbbccccdddd",
      domain: "appsec",
      rule: "appsec.idor",
      title: "The handler loads a row by id alone",
      location: { file: "src/server.js", line: 2 },
      source: { kind: "agent", name: "audit" },
    });
    const coverage: Coverage[] = [
      { domain: "appsec", unitsTotal: units.length, unitsAudited: units.length, skipped: [] },
    ];
    const kinds: KindCoverage[] = [
      { kind: "route", unitsTotal: units.length, unitsAudited: units.length, skipped: [] },
    ];
    const batches: BatchReport[] = [
      {
        batchId: "batch-1",
        domain: "appsec",
        kinds: ["route"],
        units: units.length,
        status: "audited",
        attempts: 1,
        verdicts: units.length,
        findings: 1,
        durationMs: 8_000,
        transcripts: [],
      },
    ];
    const totals: UnitTotals = {
      total: units.length,
      audited: units.length,
      skipped: 0,
      byCause: emptyCauseCounts(),
    };
    const dropped: DropAccounting = {
      unresolved: 1,
      unresolvedEvidence: 0,
      outOfSlice: 2,
      outOfSliceEvidence: 0,
      duplicates: 0,
      relocated: 0,
      strayVerdicts: 0,
      assuranceEvidence: 0,
      byReason: {
        "outside-repo": 0,
        "no-such-file": 0,
        "not-a-file": 0,
        unreadable: 0,
        "out-of-range": 0,
        "binary-file": 0,
        "quote-not-found": 0,
      },
    };
    const stats: AgentRunStats = {
      metadata: {
        kind: "fixture",
        model: undefined,
        concurrency: 2,
        maxAttempts: 3,
        timeoutMs: 240_000,
        synthetic: true,
      },
      dispatches: 1,
      retries: 0,
      failures: emptyFailureCounts(),
      usage: ZERO_USAGE,
      quotaExhausted: false,
    };
    const assurances: Assurance[] = [
      {
        id: "1111222233334444",
        domain: "appsec",
        check: "appsec.ownership-asserted-before-write",
        scope: "mutation handlers",
        unitsChecked: units.length,
        evidence: [{ file: "src/server.js", line: 2 }],
      },
    ];
    const report = buildAuditReport({
      schemaVersion: SCHEMA_VERSION,
      runId: request.runId,
      target: request.targetDir,
      aborted: false,
      durationMs: 8_100,
      runtime: {
        kind: stats.metadata.kind,
        concurrency: stats.metadata.concurrency,
        maxAttempts: stats.metadata.maxAttempts,
        timeoutMs: stats.metadata.timeoutMs,
        synthetic: stats.metadata.synthetic,
      },
      dispatches: stats.dispatches,
      retries: stats.retries,
      failures: stats.failures,
      quotaExhausted: stats.quotaExhausted,
      usage: stats.usage,
      batches,
      units: totals,
      coverage,
      kinds,
      findingsKept: 1,
      assurances: assurances.length,
      dropped,
    });
    return {
      result: {
        runId: request.runId,
        target: request.targetDir,
        findings: [claim],
        assurances,
        coverage,
        kinds,
        batches,
        units: totals,
        bound: report.bound,
        dropped,
        stats,
        report,
        document: null,
        aborted: false,
        durationMs: 8_100,
        artifacts: [`${request.runDir}/audit.json`, `${request.runDir}/assurances.json`],
      },
      plan: {
        bound: report.bound,
        batches: [],
        skipped: [
          {
            unitId: "deadbeefdeadbeef",
            kind: "container",
            reason: "audited deterministically in phase 1 by hadolint",
          },
        ],
        notes: ["route batch 1/1: 1 shared context block(s) were dropped"],
        stack: {
          frameworks: [],
          dataLayers: [],
          databases: [],
          authProviders: [],
          authHelpers: [],
          hasFrontend: false,
          validatesConfig: false,
          notes: [],
        },
      },
    };
  }

  test("phase 2 runs after the scan and prints its units by kind", async () => {
    const units = [unit(), unit({ id: "1234abcd1234abcd", kind: "migration", label: "m1" })];
    const result = await run(
      "/repo",
      { yes: true, ai: false },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
      },
    );
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Inventory — 2 units");
    expect(result.stdout).toContain("route");
    expect(result.stdout).toContain("migration");
  });

  test("--no-ai skips phases 3 and 4 and says so on every line they would have filled", async () => {
    const audited: AuditRequest[] = [];
    const result = await run(
      "/repo",
      { yes: true, ai: false },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, [unit()]),
        audit: async (request) => {
          audited.push(request);
          throw new Error("unreachable");
        },
      },
    );
    expect(audited).toHaveLength(0);
    expect(result.stdout).toContain("Audit — skipped (--no-ai)");
    // The point of the block: a skipped audit must not read as a clean one.
    expect(result.stdout).toContain("verdicts    0/1 units audited");
    expect(result.stdout).toContain("none from a model");
    expect(result.stderr).toContain("no model audited this run");
  });

  test("the audit is handed the inventory's units and the scope decision", async () => {
    const units = [unit()];
    const requests: AuditRequest[] = [];
    await run(
      "/repo",
      { yes: true, exclude: ["deadcode"] },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => {
          requests.push(request);
          return auditOutcome(request, units);
        },
      },
    );
    expect(requests).toHaveLength(1);
    expect(requests[0]?.units).toEqual(units);
    // The same scope phase 1 got: an excluded domain is not audited either.
    expect(requests[0]?.domains).not.toContain("deadcode");
    expect(requests[0]?.domains).toContain("appsec");
  });

  test("prints verdicts, findings, assurances and the units phase 3 did not batch", async () => {
    const units = [unit()];
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => auditOutcome(request, units),
      },
    );
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("verdicts    1/1 units audited");
    expect(result.stdout).toContain("findings    1 kept");
    // Both halves of what Sentinel refused have to be visible, not just the kept half.
    expect(result.stdout).toContain("1 unresolvable and 2 out-of-slice claim(s) refused");
    expect(result.stdout).toContain("assurances  1");
    expect(result.stdout).toContain("1 unit was not batched");
    expect(result.stdout).toContain("audited deterministically in phase 1 by hadolint");
    // A run that reached the audit has nothing left to disclose on stderr.
    expect(result.stderr).toBe("");
  });

  test("hands phase 4 the resolved budget, with the flags' own ceilings", async () => {
    const units = [unit()];
    let seen: AuditRequest | undefined;
    await run(
      "/repo",
      { yes: true, maxBatches: 12, maxAuditMinutes: 5 },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => {
          seen = request;
          return auditOutcome(request, units);
        },
      },
    );
    expect(seen?.budget).toEqual({
      maxBatches: 12,
      maxUnits: null,
      maxWallClockMs: 300_000,
    });
  });

  test("hands phase 4 the default budget when no flag bounds it", async () => {
    const units = [unit()];
    let seen: AuditRequest | undefined;
    await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => {
          seen = request;
          return auditOutcome(request, units);
        },
      },
    );
    // Defaults *on*: a run nobody bounded is still bounded, because the ceiling
    // exists to make a monorepo survivable without being asked for.
    expect(seen?.budget.maxBatches).toBe(DEFAULT_MAX_BATCHES);
    expect(seen?.budget.maxWallClockMs).toBe(DEFAULT_MAX_WALL_CLOCK_MS);
  });

  test("--no-budget turns every ceiling off", async () => {
    const units = [unit()];
    let seen: AuditRequest | undefined;
    await run(
      "/repo",
      { yes: true, noBudget: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => {
          seen = request;
          return auditOutcome(request, units);
        },
      },
    );
    expect(seen?.budget).toEqual(UNBOUNDED_BUDGET);
  });

  test("prints the audit's bound, so a budgeted run cannot read as a complete one", async () => {
    const units = [unit()];
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => auditOutcome(request, units),
      },
    );
    expect(result.stdout).toContain("bound       ");
    // The fixture's bound is a complete run, and it says so in the same slot a
    // budgeted one would say what it left out.
    expect(result.stdout).toContain("the run reached no budget");
  });

  test("puts the bound on the --json surface too", async () => {
    const units = [unit()];
    const result = await run(
      "/repo",
      { yes: true, json: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => auditOutcome(request, units),
      },
    );
    const payload = JSON.parse(result.stdout);
    expect(payload.audit.bound.statement).toContain("the run reached no budget");
    expect(payload.audit.bound.stop).toBe("complete");
  });

  test("a crashed audit is reported and drops the exit code, keeping the earlier artifacts", async () => {
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, [unit()]),
        audit: async () => {
          throw new Error("the subscription refused the request");
        },
      },
    );
    expect(result.code).toBe(EXIT.failure);
    expect(result.stderr).toContain("the audit phase failed");
    expect(result.stderr).toContain("the subscription refused the request");
    // The scan and the inventory still happened, and the footer still says where.
    expect(result.stdout).toContain("Inventory — 1 unit");
    expect(result.stdout).toContain("Wrote /repo/sentinel/");
  });

  test("a crashed inventory is reported, and no audit is attempted over nothing", async () => {
    const audited: AuditRequest[] = [];
    const result = await run(
      "/repo",
      { yes: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async () => {
          throw new Error("ast-grep died");
        },
        audit: async (request) => {
          audited.push(request);
          throw new Error("unreachable");
        },
      },
    );
    expect(result.code).toBe(EXIT.failure);
    expect(audited).toHaveLength(0);
    expect(result.stderr).toContain("the inventory phase failed");
    expect(result.stderr).toContain("ast-grep died");
  });

  test("units phase 2 dropped are reported, never silently missing from the count", async () => {
    const result = await run(
      "/repo",
      { yes: true, ai: false },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) =>
          inventoryOutcome(request, [unit()], {
            dropped: [
              {
                kind: "route",
                label: "GET /gone",
                location: { file: "src/removed.js", line: 9 },
                enumerator: "routes",
                reason: "out-of-range: the file has 3 lines",
              },
            ],
          }),
      },
    );
    expect(result.stdout).toContain("1 unit did not survive verification");
    expect(result.stdout).toContain("src/removed.js:9");
    expect(result.stdout).toContain("out-of-range");
  });

  test("--json carries a section per phase and one merged coverage table", async () => {
    const units = [unit()];
    const result = await run(
      "/repo",
      { yes: true, json: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => auditOutcome(request, units),
      },
    );
    const payload = JSON.parse(result.stdout);
    expect(payload.inventory.units).toBe(1);
    expect(payload.inventory.byKind.route).toBe(1);
    expect(payload.audit.skipped).toBe(false);
    expect(payload.audit.unitsAudited).toBe(1);
    expect(payload.audit.findings).toBe(1);
    expect(payload.audit.unitsNotBatched).toBe(1);
    // Phase 1 counted steps and phase 4 counted units; appsec carries both.
    const appsec = payload.coverage.find((row: Coverage) => row.domain === "appsec");
    expect(appsec.unitsTotal).toBe(3);
    expect(appsec.unitsAudited).toBe(2);
  });

  test("--json records why the audit did not run under --no-ai", async () => {
    const result = await run(
      "/repo",
      { yes: true, ai: false, json: true },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, [unit()]),
      },
    );
    const payload = JSON.parse(result.stdout);
    expect(payload.audit.skipped).toBe(true);
    expect(payload.audit.reason).toBe("--no-ai");
    expect(payload.audit.unitsAudited).toBe(0);
  });

  // -------------------------------------------------------------------------
  // `--path`: bounding the run, and saying what the bound left out
  // -------------------------------------------------------------------------

  /** An Nx-shaped workspace: one deployable, one library, one historical migration. */
  const MONOREPO: Readonly<Record<string, string>> = {
    "/mono/package.json": JSON.stringify({
      name: "workspace",
      private: true,
      workspaces: ["apps/*", "libs/*"],
      dependencies: { express: "4.19.2", pg: "8.11.5" },
    }),
    "/mono/nx.json": "{}",
    "/mono/apps/api/src/server.js": "const express = require('express');\napp.get('/users', h);\n",
    "/mono/libs/persistence/package.json": JSON.stringify({ name: "@acme/persistence" }),
    "/mono/libs/persistence/src/repo.js": "module.exports.all = () => pool.query('select 1');\n",
    "/mono/libs/persistence/migrations/001-init.js": "exports.up = () => {};\n",
  };

  /** Units on both sides of an `apps/api` boundary. */
  const IN_SCOPE = unit({
    id: "a".repeat(16),
    location: { file: "apps/api/src/server.js", line: 2 },
  });
  const OUT_OF_SCOPE = [
    unit({
      id: "b".repeat(16),
      kind: "data-access",
      label: "pool.query",
      location: { file: "libs/persistence/src/repo.js", line: 1 },
    }),
    unit({
      id: "c".repeat(16),
      kind: "migration",
      label: "001-init",
      location: { file: "libs/persistence/migrations/001-init.js", line: 1 },
    }),
  ];
  const ALL_UNITS = [IN_SCOPE, ...OUT_OF_SCOPE];

  /** The scope artifact a run left behind, parsed through its own schema. */
  function scopeArtifact(fs: MemoryFileSystem, runDir = `/mono/sentinel/${RUN_ID}`): AnalysisScope {
    const raw = fs.written.get(`${runDir}/analysis-scope.json`);
    expect(raw).toBeDefined();
    return AnalysisScopeSchema.parse(JSON.parse(raw ?? "{}"));
  }

  test("the audit is handed the units inside --path and no others", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const requests: AuditRequest[] = [];
    const result = await run(
      "/mono",
      { yes: true, path: ["apps/api"] },
      {
        fs,
        inventory: async (request) => inventoryOutcome(request, ALL_UNITS),
        audit: async (request) => {
          requests.push(request);
          return auditOutcome(request, request.units);
        },
      },
    );
    expect(result.code).toBe(EXIT.ok);
    // The whole point: phase 2 enumerated three units, phase 4 was asked about one.
    expect(requests[0]?.units).toEqual([IN_SCOPE]);
    expect(result.stdout).toContain("Auditing 1 unit on the Claude subscription");
    // And phase 2 is still told what the scope is, as data.
    expect(result.stdout).toContain("Inventory — 3 units");
  });

  test("the run states what it analysed and what it did not, in units", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    const statement =
      "This run analysed `apps/api` (1 unit); the other 2 units in this repository " +
      "(1 data-access call site, 1 migration) were not analysed.";
    expect(result.stdout).toContain(statement);
    // Prominent means prominent: the banner before the proposals, the line after
    // the inventory, the scorecard headline and the footer all carry it.
    expect(result.stdout).toContain("Analysis scope — this run was narrowed with --path");
    expect(result.stdout).toContain("Scorecard for `apps/api`");
    expect(scopeArtifact(fs).statement).toBe(statement);
  });

  test("writes analysis-scope.json, with the counts on both sides of the boundary", async () => {
    const fs = memoryFileSystem(MONOREPO);
    await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    const scope = scopeArtifact(fs);
    expect(scope.wholeRepository).toBe(false);
    expect(scope.paths).toEqual(["apps/api"]);
    expect(scope.units).toEqual({
      total: 3,
      inScope: 1,
      outOfScope: 2,
      byKind: [
        { kind: "route", inScope: 1, outOfScope: 0 },
        { kind: "data-access", inScope: 0, outOfScope: 1 },
        { kind: "migration", inScope: 0, outOfScope: 1 },
      ],
    });
    // The exemptions are named in the artifact, not only on the terminal.
    expect(scope.unscopedPhases.map((entry) => entry.phase)).toContain("dependency scan");
  });

  test("the dossier the run renders carries the scope, not just the terminal", async () => {
    const fs = memoryFileSystem(MONOREPO);
    await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"], pdf: false },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    const markdown = fs.written.get(`/mono/sentinel/${RUN_ID}/report.md`) ?? "";
    expect(markdown).toContain("scoped to `apps/api`");
    expect(markdown).toContain("This run analysed `apps/api` (1 unit)");
    expect(markdown).toContain("### Analysed subtree");
    expect(markdown).toContain("What `--path` did not narrow, and why:");
  });

  test("an unscoped run says so, and prints no scope banner", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, ai: false },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(result.stdout).not.toContain("Analysis scope");
    const scope = scopeArtifact(fs);
    expect(scope.wholeRepository).toBe(true);
    expect(scope.units.inScope).toBe(3);
    expect(scope.units.outOfScope).toBe(0);
  });

  test("a --path that matches nothing stops the run instead of analysing everything", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, path: ["apps/nope"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("--path apps/nope");
    expect(result.stderr).toContain("no such directory");
    // Nothing was written: no run directory, no half-scoped dossier.
    expect([...fs.written.keys()]).toEqual([]);
  });

  test("a workspace package name resolves to the directory it lives in", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, ai: false, path: ["@acme/persistence"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(result.code).toBe(EXIT.ok);
    expect(scopeArtifact(fs).paths).toEqual(["libs/persistence"]);
    expect(result.stdout).toContain("@acme/persistence -> `libs/persistence`");
  });

  test("a scope with no units in it is not the same as a repository with none", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, path: ["libs/persistence/migrations"] },
      { fs, inventory: async (request) => inventoryOutcome(request, [IN_SCOPE]) },
    );
    expect(result.stdout).toContain("is outside `libs/persistence/migrations`");
    expect(result.stdout).not.toContain("there is nothing to audit");
  });

  test("--save-scope is what writes into the target repo; a plain run writes nothing there", async () => {
    const quiet = memoryFileSystem(MONOREPO);
    await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      { fs: quiet, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect([...quiet.written.keys()]).not.toContain("/mono/sentinel.config.json");

    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"], saveScope: true },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    const config = fs.written.get("/mono/sentinel.config.json") ?? "";
    expect(JSON.parse(config).analyze.path).toEqual(["apps/api"]);
    expect(result.stdout).toContain("Remembered this scope in /mono/sentinel.config.json");
  });

  test("a remembered scope is announced, not applied: the run still covers the repository", async () => {
    const fs = memoryFileSystem({
      ...MONOREPO,
      "/mono/sentinel.config.json": JSON.stringify({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      }),
    });
    const result = await run(
      "/mono",
      { yes: true, ai: false },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(scopeArtifact(fs).wholeRepository).toBe(true);
    expect([...fs.written.keys()]).not.toContain("/mono/sentinel.config.json");
    expect(result.stdout).toContain("remembers the scope");
    expect(result.stdout).toContain("did not apply it");
  });

  test("re-running with the same --path does not rewrite the config", async () => {
    const fs = memoryFileSystem({
      ...MONOREPO,
      "/mono/sentinel.config.json": JSON.stringify({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      }),
    });
    await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect([...fs.written.keys()]).not.toContain("/mono/sentinel.config.json");
  });

  test("--path . widens the run back, and clears the scope it was widened from", async () => {
    const fs = memoryFileSystem({
      ...MONOREPO,
      "/mono/sentinel.config.json": JSON.stringify({
        schemaVersion: SCHEMA_VERSION,
        analyze: { path: ["apps/api"] },
      }),
    });
    const result = await run(
      "/mono",
      { yes: true, ai: false, path: ["."], saveScope: true },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(scopeArtifact(fs).wholeRepository).toBe(true);
    // A config still saying `apps/api` would silently re-narrow the next run.
    const config = fs.written.get("/mono/sentinel.config.json") ?? "";
    expect(JSON.parse(config).analyze.path).toEqual([]);
    expect(result.stdout).toContain("Cleared the remembered scope");
  });

  test("widening a repository that never had a scope writes no config at all", async () => {
    const fs = memoryFileSystem(MONOREPO);
    await run(
      "/mono",
      { yes: true, ai: false, path: ["."] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect([...fs.written.keys()]).not.toContain("/mono/sentinel.config.json");
  });

  test("--json carries the scope on every run, scoped or not", async () => {
    const scoped = await run(
      "/mono",
      { yes: true, ai: false, json: true, path: ["apps/api"] },
      {
        fs: memoryFileSystem(MONOREPO),
        inventory: async (request) => inventoryOutcome(request, ALL_UNITS),
      },
    );
    const payload = JSON.parse(scoped.stdout);
    expect(payload.analysisScope.wholeRepository).toBe(false);
    expect(payload.analysisScope.units.outOfScope).toBe(2);

    const whole = await run(
      "/mono",
      { yes: true, ai: false, json: true },
      {
        fs: memoryFileSystem(MONOREPO),
        inventory: async (request) => inventoryOutcome(request, ALL_UNITS),
      },
    );
    // Present either way: a consumer that has to check for the key before it can
    // tell a bounded run from a complete one is a consumer that will forget.
    expect(JSON.parse(whole.stdout).analysisScope.wholeRepository).toBe(true);
  });

  test("phase 1 is handed the scope, and is not narrowed by it", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const result = await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      { fs, inventory: async (request) => inventoryOutcome(request, ALL_UNITS) },
    );
    expect(result.requests[0]?.paths).toEqual(["apps/api"]);
    // The repository root, not the subtree: a lockfile and a git history have
    // no subtree, and the run says which phases those are.
    expect(result.requests[0]?.targetDir).toBe("/mono");
    expect(result.stdout).toContain("What --path does not narrow, and why:");
    expect(result.stdout).toContain("a lockfile, its CVEs and its licences");
  });

  test("phase 2 is told the scope as data, and still enumerates the repository", async () => {
    const fs = memoryFileSystem(MONOREPO);
    const seen: InventoryRequest[] = [];
    await run(
      "/mono",
      { yes: true, ai: false, path: ["apps/api"] },
      {
        fs,
        inventory: async (request) => {
          seen.push(request);
          return inventoryOutcome(request, ALL_UNITS);
        },
      },
    );
    expect(seen[0]?.paths).toEqual(["apps/api"]);
    expect(seen[0]?.targetDir).toBe("/mono");
  });

  /**
   * Eight synthetic batch completions, reported through the writer phase 4 was
   * handed. The batch facts stand in for a real dispatch; the tracker, the
   * formatter and the sinks are the production ones, so what these tests assert
   * on is the bytes a watching operator sees.
   */
  function reportEightBatches(progress: AuditProgress): void {
    let clock = 0;
    const tracker = createProgressTracker({
      report: progress,
      batchesTotal: 8,
      unitsTotal: 112,
      concurrency: 2,
      startedAt: 0,
      now: () => clock,
    });
    for (let index = 0; index < 8; index += 1) {
      // Two in flight, a minute each: thirty seconds of wall clock per batch.
      clock += 30_000;
      const failed = index === 5;
      tracker.completed({
        batchId: `appsec-route-${String(index + 1).padStart(4, "0")}`,
        domain: "appsec",
        kinds: ["route"],
        units: 14,
        status: failed ? "failed" : "audited",
        ...(failed ? { failure: "timeout" as const, reason: "no reply within 240000ms" } : {}),
        verdicts: failed ? 0 : 14,
        findings: index === 0 ? 1 : 0,
        durationMs: 60_000,
      });
    }
  }

  /** Runs the audit with a runner that reports eight batches and then succeeds. */
  async function runWithProgress(flags: AnalyzeInvocation["flags"]) {
    const units = [unit()];
    const requests: AuditRequest[] = [];
    const result = await run(
      "/repo",
      { yes: true, ...flags },
      {
        fs: memoryFileSystem(REPO),
        inventory: async (request) => inventoryOutcome(request, units),
        audit: async (request) => {
          requests.push(request);
          if (request.progress !== undefined) reportEightBatches(request.progress);
          return auditOutcome(request, units);
        },
      },
    );
    return { ...result, requests };
  }

  test("the phase that takes an hour reports every batch as it finishes", async () => {
    const result = await runWithProgress({});
    expect(result.code).toBe(EXIT.ok);
    expect(result.requests[0]?.progress).toBeDefined();
    // The header says the lines are coming, which is the other half of the fix:
    // silence you were warned about is not the same as silence.
    expect(result.stdout).toContain("one line per batch as it finishes");
    // Early on, three batches are not a rate.
    expect(result.stdout).toContain(
      "[1/8] route × 14 · 14/112 units · 1 finding · 30s elapsed · ~estimating\n",
    );
    expect(result.stdout).toContain(
      "[4/8] route × 14 · 56/112 units · 1 finding · 2m elapsed · ~2m left\n",
    );
    // The last line has nothing left to project, so it does not pretend to.
    expect(result.stdout).toContain(
      "[8/8] route × 14 · 98/112 units · 1 finding · 4m elapsed · 1 failed\n",
    );
  });

  test("a batch lost mid-run is classified on the spot, not summed at the end", async () => {
    const result = await runWithProgress({});
    expect(result.stdout).toContain(
      "[6/8] route × 14 failed (timeout) · 70/112 units · 1 finding · 3m elapsed · ~1m left · 1 failed\n" +
        "    no reply within 240000ms\n",
    );
    // And the loss stays on every line after it, for a reader who scrolled past.
    expect(result.stdout).toContain("[7/8] route × 14 · 84/112 units · 1 finding · 3m elapsed");
    expect(result.stdout).toContain("· 1 failed\n");
  });

  test("--verbose adds the batch id to every progress line", async () => {
    const result = await runWithProgress({ verbose: true });
    expect(result.stdout).toContain("[1/8] appsec-route-0001 · route × 14 · 14/112 units");
  });

  test("--json emits one object per batch on stderr, never into the run's document", async () => {
    const result = await runWithProgress({ json: true });
    const emitted = result.stderr
      .split("\n")
      .filter((line) => line.startsWith("{"))
      .map((line) => JSON.parse(line));
    expect(emitted).toHaveLength(8);
    expect(emitted[0]).toMatchObject({
      event: "audit-batch",
      batchesDone: 1,
      batchesTotal: 8,
      remainingMs: null,
      estimating: true,
    });
    expect(emitted[5]).toMatchObject({
      status: "failed",
      failure: "timeout",
      batchesFailed: 1,
      estimating: false,
    });
    // Stdout stays exactly one parseable document, and no prose line reached it.
    const payload = JSON.parse(result.stdout);
    expect(payload.audit.batchesRun).toBe(1);
    expect(result.stdout).not.toContain("audit-batch");
    expect(result.stdout).not.toContain("elapsed");
  });

  test("--quiet builds no writer at all, so nothing is printed and nothing counted", async () => {
    const result = await runWithProgress({ quiet: true });
    expect(result.requests[0]?.progress).toBeUndefined();
    expect(result.stdout).toBe("");
  });
});

describe("phases 6 and 7", () => {
  test("a full run ends with the scorecard and the three dossier files", async () => {
    const fs = memoryFileSystem(REPO);
    const result = await run("/repo", { yes: true }, { fs });

    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Scorecard");
    // Every domain of the contract appears, scored or not: a scorecard that
    // listed only what it could score would be the silence this tool exists to
    // remove.
    for (const domain of DomainSchema.options) expect(result.stdout).toContain(domain);

    const dir = `/repo/sentinel/${RUN_ID}`;
    expect([...fs.written.keys()]).toEqual(
      expect.arrayContaining([`${dir}/report.md`, `${dir}/issues.md`, `${dir}/report.pdf`]),
    );
  });

  test("--no-pdf drops only the PDF; the scorecard and the two markdown files stay", async () => {
    const fs = memoryFileSystem(REPO);
    const result = await run("/repo", { yes: true, pdf: false }, { fs });

    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Scorecard");
    const written = [...fs.written.keys()];
    const dir = `/repo/sentinel/${RUN_ID}`;
    expect(written).toContain(`${dir}/report.md`);
    expect(written).toContain(`${dir}/issues.md`);
    expect(written).not.toContain(`${dir}/report.pdf`);
  });

  test("a domain that ran too few checks is never printed as a clean zero", async () => {
    // The fixture's coverage is 1 of 2 for every domain, which is below the
    // gate: phase 6 refuses a number and the terminal has to say so in words.
    const result = await run("/repo", { yes: true }, { fs: memoryFileSystem(REPO) });
    expect(result.stdout).toContain("not assessed");
    expect(result.stdout).toContain("Not scored:");
  });

  test("the scorecard travels in --json, with every domain", async () => {
    const result = await run("/repo", { yes: true, json: true }, { fs: memoryFileSystem(REPO) });
    const payload = JSON.parse(result.stdout);
    expect(payload.scorecard.domains).toHaveLength(DomainSchema.options.length);
    expect(payload.report).toEqual(expect.arrayContaining([`/repo/sentinel/${RUN_ID}/report.md`]));
  });

  test("a render that fails warns, names the retry, and keeps the run's exit code", async () => {
    // Rendering is free and reads only the run directory, so a failure here is
    // never worth failing a run that already spent minutes producing findings.
    const fs = memoryFileSystem(REPO);
    const guarded: AnalyzeFileSystem = {
      ...fs,
      writeFile: async (path: string, data: string | Uint8Array) => {
        if (path.endsWith("report.pdf")) throw new Error("disk full");
        await fs.writeFile(path, data);
      },
    };
    const result = await run("/repo", { yes: true }, { fs: guarded });

    expect(result.code).toBe(EXIT.ok);
    expect(result.stderr).toContain("the dossier could not be rendered (disk full)");
    expect(result.stderr).toContain("sentinel report /repo/sentinel/");
    // Phase 1's own artifacts are untouched by the failure.
    expect([...fs.written.keys()]).toContain(`/repo/sentinel/${RUN_ID}/findings.json`);
  });
});

describe("formatMillis and plural", () => {
  test("a noun ending in a sibilant pluralises with -es", () => {
    expect(pluralFor(0, "batch")).toBe("0 batches");
    expect(pluralFor(1, "batch")).toBe("1 batch");
    expect(pluralFor(2, "batch")).toBe("2 batches");
    expect(pluralFor(2, "finding")).toBe("2 findings");
    expect(pluralFor(1, "unit")).toBe("1 unit");
  });
});
