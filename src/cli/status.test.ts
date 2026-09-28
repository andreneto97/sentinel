import { describe, expect, test } from "bun:test";
import { captureCli, outputFlags } from "./_shared/_cli-context.ts";
import {
  MemoryRunFs,
  RENDERED_ALL,
  analysisScope,
  auditReport,
  batchReport,
  completeRun,
  coverageRow,
  finding,
  findingsDocument,
  inventoryDocument,
  scanReport,
  writeRunFixture,
} from "./_shared/_run-fixtures.ts";
import { loadRunArtifacts } from "./_shared/run-artifacts.ts";
import { EXIT } from "./index.ts";
import { type StatusJson, buildDomainRows, collectSkipped, statusCommand } from "./status.ts";

const RUN = "/out/20260923T004014-d60d94c9";

/** Runs the verb against an in-memory run directory. */
async function run(
  fs: MemoryRunFs,
  options: { runDir?: string; json?: boolean; quiet?: boolean } = {},
) {
  const captured = captureCli();
  const code = await statusCommand(
    captured.context,
    {
      runDir: options.runDir ?? RUN,
      cwd: "/work",
      output: outputFlags({ json: options.json ?? false, quiet: options.quiet ?? false }),
    },
    { fs },
  );
  return { code, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe("sentinel status", () => {
  test("a finished run reads as shareable and exits zero", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs);

    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Yes — this run is complete enough to share");
    expect(result.stdout).toContain("[done] audit");
    expect(result.stdout).toContain("Units of audit (4)");
  });

  test("an incomplete run exits non-zero and lists what is missing", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const result = await run(fs);

    expect(result.code).toBe(EXIT.failure);
    expect(result.stdout).toContain("No — this run is not complete enough to share");
    expect(result.stdout).toContain("no model audited this run");
    expect(result.stdout).toContain("the dossier is not rendered");
  });

  test("a scoped run cannot be mistaken for a whole-repository one", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
      analysisScope: analysisScope({ total: 1000, inScope: 300 }),
    });
    const result = await run(fs);

    // Beside the repository it names, and again over the counts that are the
    // repository's rather than the run's.
    expect(result.stdout).toContain("scope      This run analysed `apps/api` (300 units)");
    expect(result.stdout).toContain("only those were analysed");
  });

  test("a whole-repository run says nothing about a scope", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs);
    expect(result.stdout).not.toContain("scope      ");
  });

  test("--json carries the scope for a machine reader too", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      inventory: inventoryDocument(),
      analysisScope: analysisScope({ total: 1000, inScope: 300 }),
    });
    const result = await run(fs, { json: true });
    const payload = JSON.parse(result.stdout);
    expect(payload.analysisScope.paths).toEqual(["apps/api"]);
    expect(payload.analysisScope.units.inScope).toBe(300);
  });

  test("writes nothing at all", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const before = new Set(fs.files.keys());
    await run(fs);
    expect(new Set(fs.files.keys())).toEqual(before);
  });

  test("prints every phase's own reason for not being complete", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport({
        steps: [
          {
            step: "hadolint",
            status: "skipped",
            reason: "the target has no Dockerfile",
            findings: 0,
            artifacts: [],
            durationMs: 0,
          },
        ],
      }),
    });
    const result = await run(fs);

    expect(result.stdout).toContain("analyzer hadolint");
    expect(result.stdout).toContain("the target has no Dockerfile");
  });

  test("--json carries the phases, the counts and the verdict", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { json: true });
    const payload = JSON.parse(result.stdout) as StatusJson;

    expect(payload.runId).toBe("20260923T004014-d60d94c9");
    expect(payload.phases).toHaveLength(6);
    expect(payload.units.total).toBe(4);
    expect(payload.findings.total).toBe(1);
    expect(payload.assurances.total).toBe(1);
    expect(payload.verdict.shareable).toBe(true);
    expect(payload.startedAt).toBe("2026-09-23 00:40 UTC");
  });

  test("--quiet prints one line a script can read", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { quiet: true });
    expect(result.stdout.trim()).toBe(`shareable 20260923T004014-d60d94c9 ${RUN}`);
  });

  test("a missing directory is a preflight failure, not an empty report", async () => {
    const fs = new MemoryRunFs();
    const result = await run(fs, { runDir: "/nowhere" });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("/nowhere does not exist");
  });

  test("a corrupt artifact blocks sharing and is named", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await fs.writeFile(`${RUN}/audit.json`, "{ truncated");
    const result = await run(fs);

    expect(result.code).toBe(EXIT.failure);
    expect(result.stdout).toContain("audit.json is on disk but unusable");
  });

  test("groups the units that came back without a verdict by reason", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        kinds: [
          {
            kind: "route",
            unitsTotal: 4,
            unitsAudited: 2,
            skipped: [
              { unitId: "u1", reason: "inconclusive: the agent declined to decide" },
              { unitId: "u2", reason: "inconclusive: the agent declined to decide" },
            ],
          },
        ],
      }),
    });
    const result = await run(fs);

    expect(result.stdout).toContain("Units without a verdict (2)");
    expect(result.stdout).toContain("2 × inconclusive: the agent declined to decide");
  });
});

describe("buildDomainRows", () => {
  test("keeps a domain that was checked and found nothing", () => {
    const rows = buildDomainRows([], [coverageRow("delivery", 5, 5)], ["delivery"]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.findings).toBe(0);
    expect(rows[0]?.inScope).toBe(true);
  });

  test("marks a domain the scope left out, so zero cannot read as clean", () => {
    const rows = buildDomainRows(
      [finding({ id: "f1", domain: "api" })],
      [coverageRow("appsec", 2, 2)],
      ["appsec"],
    );
    const api = rows.find((row) => row.domain === "api");
    expect(api?.inScope).toBe(false);
    expect(api?.findings).toBe(1);
  });

  test("omits a domain nothing in the run mentions", () => {
    const rows = buildDomainRows([], [coverageRow("appsec", 1, 1)], ["appsec"]);
    expect(rows.map((row) => row.domain)).toEqual(["appsec"]);
  });
});

describe("collectSkipped", () => {
  test("collects analyzers, enumerators and batches with their own words", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      rendered: RENDERED_ALL,
      scan: scanReport({
        steps: [
          {
            step: "gitleaks",
            status: "failed",
            reason: "the binary is not installed",
            findings: 0,
            artifacts: [],
            durationMs: 1,
          },
        ],
      }),
      inventory: inventoryDocument(2, {
        enumerators: [
          {
            name: "queue-consumers",
            status: "skipped",
            reason: "no queue consumer is declared",
            kinds: ["queue-consumer"],
            units: 0,
          },
        ],
      }),
      audit: auditReport({
        batches: [
          batchReport({ batchId: "b1", status: "failed", reason: "the dispatch timed out" }),
        ],
      }),
    });
    const skipped = collectSkipped(await loadRunArtifacts(fs, RUN));

    expect(skipped.map((entry) => entry.what)).toEqual([
      "analyzer gitleaks",
      "enumerator queue-consumers",
      "batch b1",
    ]);
    expect(skipped[2]?.reason).toContain("the dispatch timed out");
  });
});
