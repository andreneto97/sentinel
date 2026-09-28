import { describe, expect, test } from "bun:test";
import { captureCli, outputFlags } from "./_shared/_cli-context.ts";
import {
  MemoryRunFs,
  assurance,
  auditReport,
  completeRun,
  finding,
  findingsDocument,
  inventoryDocument,
  scanReport,
  writeRunFixture,
} from "./_shared/_run-fixtures.ts";
import { loadRunArtifacts } from "./_shared/run-artifacts.ts";
import { EXIT } from "./index.ts";
import {
  type ReportFormat,
  type ReportJson,
  formatBytes,
  renderDossier,
  reportCommand,
  selectionFor,
} from "./report.ts";

const RUN = "/out/20260923T004014-d60d94c9";

/** Runs the verb against an in-memory run directory. */
async function run(
  fs: MemoryRunFs,
  options: {
    runDir?: string;
    format?: ReportFormat;
    out?: string;
    json?: boolean;
    triage?: string;
    brief?: boolean;
  } = {},
) {
  const captured = captureCli();
  const code = await reportCommand(
    captured.context,
    {
      runDir: options.runDir ?? RUN,
      cwd: "/work",
      output: outputFlags({ json: options.json ?? false }),
      format: options.format ?? "all",
      ...(options.out === undefined ? {} : { out: options.out }),
      ...(options.triage === undefined ? {} : { triage: options.triage }),
      ...(options.brief === undefined ? {} : { brief: options.brief }),
    },
    { fs },
  );
  return { code, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe("sentinel report", () => {
  test("renders the three files into the run directory", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs);

    expect(result.code).toBe(EXIT.ok);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(true);
    expect(fs.files.has(`${RUN}/issues.md`)).toBe(true);
    expect(fs.files.has(`${RUN}/report.pdf`)).toBe(true);
    expect(result.stdout).toContain("Rendered 20260923T004014-d60d94c9");
  });

  test("the PDF is a PDF and the markdown is markdown", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await run(fs);

    const pdf = fs.files.get(`${RUN}/report.pdf`);
    expect(pdf).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode((pdf as Uint8Array).slice(0, 5))).toBe("%PDF-");
    expect(String(fs.files.get(`${RUN}/report.md`))).toContain("# Sentinel dossier");
  });

  test("--format renders only what was asked for", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({ findings: [finding({ id: "f1" })] }),
      audit: auditReport(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const result = await run(fs, { format: "md" });

    expect(result.code).toBe(EXIT.ok);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(true);
    expect(fs.files.has(`${RUN}/report.pdf`)).toBe(false);
    expect(fs.files.has(`${RUN}/issues.md`)).toBe(false);
  });

  test("--brief adds the two brief files beside the dossier", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { brief: true });

    expect(result.code).toBe(EXIT.ok);
    // Additive: the dossier is still there, and the brief sits beside it.
    expect(fs.files.has(`${RUN}/report.pdf`)).toBe(true);
    expect(fs.files.has(`${RUN}/report-brief.pdf`)).toBe(true);
    expect(fs.files.has(`${RUN}/report-brief.md`)).toBe(true);
    expect(String(fs.files.get(`${RUN}/report-brief.md`))).toContain("# Sentinel executive brief");
    // And the terminal repeats the brief's own disclosure, so the operator who
    // forwards it does not have to open it to learn what it leaves out.
    expect(result.stdout).toContain("report-brief.pdf details");
    expect(result.stdout).toContain("It is a summary, not the audit");
    expect(result.stdout).toContain("carry no human review");
  });

  test("--format brief renders the brief alone, for a run whose dossier is huge", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({ findings: [finding({ id: "f1" })] }),
      audit: auditReport(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const result = await run(fs, { format: "brief" });

    expect(result.code).toBe(EXIT.ok);
    expect(fs.files.has(`${RUN}/report-brief.pdf`)).toBe(true);
    expect(fs.files.has(`${RUN}/report-brief.md`)).toBe(true);
    expect(fs.files.has(`${RUN}/report.pdf`)).toBe(false);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(false);
  });

  test("--json reports the split the brief made", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { format: "brief", json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    expect(payload.brief).toBeDefined();
    expect((payload.brief?.detailed ?? 0) + (payload.brief?.counted ?? 0)).toBe(payload.findings);
  });

  test("no --brief means no brief files", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    expect(fs.files.has(`${RUN}/report-brief.pdf`)).toBe(false);
    expect(payload.brief).toBeUndefined();
  });

  test("--out writes elsewhere and says the run directory is unchanged", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({ findings: [finding({ id: "f1" })] }),
      audit: auditReport(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const result = await run(fs, { out: "/elsewhere" });

    expect(result.code).toBe(EXIT.ok);
    expect(fs.files.has("/elsewhere/report.md")).toBe(true);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(false);
    expect(result.stdout).toContain("outside the run directory");
  });

  test("a relative --out resolves against the working directory", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await run(fs, { out: "dossier" });
    expect(fs.files.has("/work/dossier/report.md")).toBe(true);
  });

  test("refuses, naming the file, when findings.json is missing", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, { runDir: RUN, scan: scanReport(), profile: true });
    const result = await run(fs);

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain(`${RUN}/findings.json is missing`);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(false);
  });

  test("refuses a path that is neither a run directory nor an output directory", async () => {
    const fs = new MemoryRunFs();
    await fs.mkdirp("/out/whatever");
    const result = await run(fs, { runDir: "/out/whatever" });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("neither a run directory nor an output directory");
  });

  test("resolves an output directory through its .latest pointer", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await fs.writeFile("/out/.latest", "20260923T004014-d60d94c9\n");
    const result = await run(fs, { runDir: "/out" });

    expect(result.code).toBe(EXIT.ok);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(true);
  });

  test("--json reports what was written, the score and whether the run can be shared", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const result = await run(fs, { json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    expect(payload.runId).toBe("20260923T004014-d60d94c9");
    expect(payload.written.map((entry) => entry.file).sort()).toEqual([
      "issues.md",
      "report.md",
      "report.pdf",
    ]);
    expect(payload.written.every((entry) => entry.bytes > 0)).toBe(true);
    expect(payload.shareable).toBe(true);
    expect(payload.blockers).toEqual([]);
    expect(payload.confidence).toBeString();
  });

  test("says what an absent optional artifact cost the document", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({ findings: [finding({ id: "f1" })] }),
    });
    const result = await run(fs, { json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    expect(payload.degraded.join(" ")).toContain("inventory.json is absent");
    expect(payload.degraded.join(" ")).toContain("audit.json is absent");
    expect(payload.shareable).toBe(false);
  });
});

describe("renderDossier", () => {
  test("is a pure function of the artifacts: two renders are byte-identical", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const artifacts = await loadRunArtifacts(fs, RUN);

    const first = await renderDossier(artifacts, { select: selectionFor("all") });
    const second = await renderDossier(artifacts, { select: selectionFor("all") });

    expect(first.files.map((file) => file.file)).toEqual(second.files.map((file) => file.file));
    for (const [index, file] of first.files.entries()) {
      const other = second.files[index];
      if (typeof file.data === "string") expect(file.data).toBe(String(other?.data));
      else expect(Array.from(file.data)).toEqual(Array.from(other?.data as Uint8Array));
    }
  });

  test("scores the run from its own artifacts, without reading the repository", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const artifacts = await loadRunArtifacts(fs, RUN);
    const rendered = await renderDossier(artifacts, { select: selectionFor("md") });

    expect(rendered.scorecard.runId).toBe("20260923T004014-d60d94c9");
    expect(rendered.scorecard.domains.some((domain) => domain.score !== null)).toBe(true);
    expect(rendered.files).toHaveLength(1);
  });

  test("a run with no findings still renders, and says the assurances it has", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({ assurances: [assurance({ id: "a1" })] }),
      audit: auditReport(),
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const rendered = await renderDossier(artifacts, { select: selectionFor("md") });
    expect(String(rendered.files[0]?.data)).toContain("0 findings");
  });
});

describe("helpers", () => {
  test("formats bytes the way a human reads them", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(12_400)).toBe("12.4 kB");
    expect(formatBytes(2_500_000)).toBe("2.5 MB");
  });
});

describe("sentinel report --triage", () => {
  const TRIAGE = "/work/triage.json";

  /** A run with three findings, two of which a reviewer looked at. */
  async function reviewableRun(fs: MemoryRunFs): Promise<void> {
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({
        findings: [
          finding({ id: "kept", title: "Membership list is not tenant-scoped" }),
          finding({
            id: "withdrawn",
            severity: "critical",
            title: "SQL built by interpolation",
            rule: "appsec.sql-injection",
            location: { file: "src/reports/purchases.ts", line: 68 },
          }),
          finding({ id: "unreviewed", severity: "low", title: "Query selects every column" }),
        ],
        assurances: [assurance({ id: "a1" })],
      }),
      audit: auditReport(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
  }

  /** The reviewer's file, on the same in-memory disk the run lives on. */
  async function writeTriage(
    fs: MemoryRunFs,
    verdicts: readonly Record<string, unknown>[],
    path = TRIAGE,
  ): Promise<void> {
    await fs.writeFile(
      path,
      `${JSON.stringify(
        {
          schemaVersion: "1.0",
          reviewer: "manual verification, 2026-09-23 (two reviewers)",
          verdicts,
        },
        null,
        2,
      )}\n`,
    );
  }

  const CONFIRMED = {
    id: "kept",
    rule: "appsec.missing-authorization",
    file: "src/api/orders.ts",
    line: 12,
    reportedSeverity: "high",
    verdict: "true",
    note: "Confirmed: any authenticated caller reads every tenant's memberships.",
  };

  const WITHHELD = {
    id: "withdrawn",
    rule: "appsec.sql-injection",
    file: "src/reports/purchases.ts",
    line: 68,
    reportedSeverity: "critical",
    verdict: "false",
    severity: "informational",
    note: "The interpolated value is a module constant validated by a zod enum.",
  };

  test("writes findings.triaged.json and never touches findings.json", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    const before = String(fs.files.get(`${RUN}/findings.json`));
    await writeTriage(fs, [CONFIRMED, WITHHELD]);

    const result = await run(fs, { triage: TRIAGE });

    expect(result.code).toBe(EXIT.ok);
    expect(String(fs.files.get(`${RUN}/findings.json`))).toBe(before);
    const triaged = JSON.parse(String(fs.files.get(`${RUN}/findings.triaged.json`))) as {
      findings: { id: string }[];
    };
    expect(triaged.findings.map((entry) => entry.id)).toEqual(["kept", "unreviewed"]);
  });

  test("the withheld finding is absent from the findings and present in the withheld table", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [CONFIRMED, WITHHELD]);
    await run(fs, { triage: TRIAGE });

    const markdown = String(fs.files.get(`${RUN}/report.md`));
    expect(markdown).toContain("## Human verification");
    expect(markdown).toContain("### Withheld by review (1)");
    expect(markdown).toContain("SQL built by interpolation");
    expect(markdown).toContain("The interpolated value is a module constant");
    const findings = markdown.slice(markdown.indexOf("## Findings"));
    expect(findings).not.toContain("SQL built by interpolation");
    // And it is gone from the tracker too: a withdrawn claim must not arrive as
    // a GitHub issue.
    expect(String(fs.files.get(`${RUN}/issues.md`))).not.toContain("SQL built by interpolation");
  });

  test("the counts reconcile: two of three reviewed, one withheld, one left unreviewed", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [CONFIRMED, WITHHELD]);
    const result = await run(fs, { triage: TRIAGE, json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    expect(payload.findings).toBe(2);
    expect(payload.triage).toEqual({
      reviewer: "manual verification, 2026-09-23 (two reviewers)",
      file: TRIAGE,
      findingsFile: `${RUN}/findings.triaged.json`,
      reviewed: 2,
      confirmed: 1,
      corrected: 0,
      withheld: 1,
      contested: 0,
      unreviewed: 1,
    });
    expect(payload.written.map((entry) => entry.file)).toContain("findings.triaged.json");
  });

  test("the terminal output states the reach of the review and its limit", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [CONFIRMED, WITHHELD]);
    const result = await run(fs, { triage: TRIAGE });

    expect(result.stdout).toContain("2 of 3 findings in this run were verified");
    expect(result.stdout).toContain("The other 1 finding in this dossier carries no human review");
    expect(result.stdout).toContain("2 finding(s)");
  });

  test("a corrected severity reaches the scores, not just the prose", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [
      { ...WITHHELD, verdict: "overstated", severity: "low", note: "Real, but bounded to admins." },
    ]);
    const result = await run(fs, { triage: TRIAGE, json: true });
    const payload = JSON.parse(result.stdout) as ReportJson;

    const plain = new MemoryRunFs();
    await reviewableRun(plain);
    const before = JSON.parse((await run(plain, { json: true })).stdout) as ReportJson;

    expect(payload.findings).toBe(3);
    // The critical became a low, so phase 6 has less to deduct.
    expect(payload.score ?? 0).toBeGreaterThan(before.score ?? 0);
    expect(String(fs.files.get(`${RUN}/report.md`))).toContain(
      "### Severity corrected by review (1)",
    );
  });

  test("--out sends the rendered files elsewhere, the triaged findings stay beside the original", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [WITHHELD]);
    await run(fs, { triage: TRIAGE, out: "/elsewhere" });

    expect(fs.files.has("/elsewhere/report.md")).toBe(true);
    expect(fs.files.has(`${RUN}/findings.triaged.json`)).toBe(true);
    expect(fs.files.has("/elsewhere/findings.triaged.json")).toBe(false);
  });

  test("a relative --triage resolves against the working directory", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [WITHHELD], "/work/review/triage.json");
    const result = await run(fs, { triage: "review/triage.json" });
    expect(result.code).toBe(EXIT.ok);
  });

  test("refuses a triage that names a finding this run does not contain, by id", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await writeTriage(fs, [
      CONFIRMED,
      { ...WITHHELD, id: "f934d9efac08df15", note: "not in this run" },
    ]);
    const result = await run(fs, { triage: TRIAGE });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("f934d9efac08df15");
    expect(result.stderr).toContain("belongs to one run");
    // Nothing was written: a stale triage must not leave a half-corrected dossier.
    expect(fs.files.has(`${RUN}/findings.triaged.json`)).toBe(false);
    expect(fs.files.has(`${RUN}/report.md`)).toBe(false);
  });

  test("refuses a triage file that is not there", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    const result = await run(fs, { triage: "/work/nope.json" });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("/work/nope.json does not exist");
    expect(fs.files.has(`${RUN}/report.md`)).toBe(false);
  });

  test("refuses a triage file that is not a triage document, naming the field", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await fs.writeFile(TRIAGE, JSON.stringify({ schemaVersion: "1.0", verdicts: [] }));
    const result = await run(fs, { triage: TRIAGE });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("is not a valid triage document");
    expect(result.stderr).toContain("reviewer");
  });

  test("refuses a triage file that is not JSON", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await fs.writeFile(TRIAGE, "verdicts: none");
    const result = await run(fs, { triage: TRIAGE });

    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("is not valid JSON");
  });

  test("without --triage the dossier says nothing about a review", async () => {
    const fs = new MemoryRunFs();
    await reviewableRun(fs);
    await run(fs);
    expect(String(fs.files.get(`${RUN}/report.md`))).not.toContain("Human verification");
    expect(fs.files.has(`${RUN}/findings.triaged.json`)).toBe(false);
  });
});
