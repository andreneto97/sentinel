import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  type Assurance,
  type Coverage,
  type Finding,
  type FindingsDocument,
  FindingsDocumentSchema,
  SCHEMA_VERSION,
} from "../contracts/findings.ts";
import { InventoryDocumentSchema, zeroCounts } from "../contracts/inventory.ts";
import { FINDINGS_FILE } from "../scan/artifacts.ts";
import { FIXTURE_RUN_DIR, brokenUnit, recordingFileSystem } from "./__fixtures__/harness.ts";
import {
  ASSURANCES_FILE,
  AUDIT_FILE,
  AuditReportSchema,
  buildAssurancesDocument,
  buildAuditReport,
  mergeAuditIntoFindings,
  mergeCoverage,
  readFindingsDocument,
  readInventoryDocument,
  writeAssurancesDocument,
  writeAuditReport,
} from "./artifacts.ts";

/** A minimal valid finding, varied per test. */
function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    domain: "appsec",
    rule: "appsec.missing-ownership-check",
    severity: "high",
    confidence: "medium",
    title: "Handler mutates without an ownership predicate",
    description: "The update runs on an id taken from the path.",
    location: { file: "src/api/invoices.ts", line: 9, snippet: "9 | await db.invoice.update(" },
    evidence: [],
    impact: "Any caller can void another tenant's invoice.",
    recommendation: "Constrain the update by the authenticated principal.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

/** A minimal valid assurance. */
function assurance(id: string, overrides: Partial<Assurance> = {}): Assurance {
  return {
    id,
    domain: "appsec",
    check: "ownership asserted before write",
    scope: "3/3 route handlers",
    unitsChecked: 3,
    evidence: [],
    ...overrides,
  };
}

/** A coverage row. */
function coverage(overrides: Partial<Coverage> = {}): Coverage {
  return { domain: "appsec", unitsTotal: 2, unitsAudited: 2, skipped: [], ...overrides };
}

/** A findings document as phase 1 would have left it. */
function baseDocument(overrides: Partial<FindingsDocument> = {}): FindingsDocument {
  return FindingsDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: "20240101T000000-0000abcd",
    target: "/repo",
    findings: [],
    assurances: [],
    coverage: [],
    droppedFindings: 0,
    ...overrides,
  });
}

/** The smallest report that validates, varied per test. */
function report(overrides: Record<string, unknown> = {}) {
  return buildAuditReport({
    schemaVersion: SCHEMA_VERSION,
    runId: "20240101T000000-0000abcd",
    target: "/repo",
    aborted: false,
    durationMs: 12,
    runtime: {
      kind: "fixture",
      concurrency: 2,
      maxAttempts: 3,
      timeoutMs: 1000,
      synthetic: true,
    },
    dispatches: 1,
    retries: 0,
    failures: {
      "malformed-output": 0,
      "truncated-output": 0,
      timeout: 0,
      quota: 0,
      transient: 0,
      refusal: 0,
    },
    quotaExhausted: false,
    usage: {},
    batches: [],
    units: {
      total: 0,
      audited: 0,
      skipped: 0,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 0,
        cancelled: 0,
        budget: 0,
      },
    },
    coverage: [],
    kinds: [],
    findingsKept: 0,
    assurances: 0,
    dropped: {
      unresolved: 0,
      unresolvedEvidence: 0,
      outOfSlice: 0,
      outOfSliceEvidence: 0,
      duplicates: 0,
      relocated: 0,
      strayVerdicts: 0,
      assuranceEvidence: 0,
      byReason: {},
    },
    ...overrides,
  });
}

describe("readInventoryDocument", () => {
  test("reads back what phase 2 wrote", async () => {
    const fs = recordingFileSystem();
    const unit = await brokenUnit();
    const document = InventoryDocumentSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      runId: "20240101T000000-0000abcd",
      target: "/repo",
      units: [unit],
      counts: { ...zeroCounts(), route: 1 },
      enumerators: [{ name: "next-routes", status: "ok", kinds: ["route"], units: 1 }],
      dropped: [],
    });
    await fs.writeFile(join(FIXTURE_RUN_DIR, "inventory.json"), JSON.stringify(document));

    const read = await readInventoryDocument(fs, FIXTURE_RUN_DIR);
    expect(read.units).toHaveLength(1);
    expect(read.units[0]?.id).toBe(unit.id);
  });

  test("refuses a file that is not JSON, naming the file", async () => {
    const fs = recordingFileSystem();
    await fs.writeFile(join(FIXTURE_RUN_DIR, "inventory.json"), "{not json");
    await expect(readInventoryDocument(fs, FIXTURE_RUN_DIR)).rejects.toThrow(/inventory\.json/);
  });

  test("refuses a document that would not survive being read back", async () => {
    const fs = recordingFileSystem();
    await fs.writeFile(
      join(FIXTURE_RUN_DIR, "inventory.json"),
      JSON.stringify({ schemaVersion: SCHEMA_VERSION, runId: "r", target: "/repo" }),
    );
    await expect(readInventoryDocument(fs, FIXTURE_RUN_DIR)).rejects.toThrow(
      /is not a valid document/,
    );
  });
});

describe("readFindingsDocument", () => {
  test("returns null when phase 1 left nothing to merge into", async () => {
    expect(await readFindingsDocument(recordingFileSystem(), FIXTURE_RUN_DIR)).toBeNull();
  });

  test("reads back a document phase 1 wrote", async () => {
    const fs = recordingFileSystem();
    await fs.writeFile(
      join(FIXTURE_RUN_DIR, FINDINGS_FILE),
      JSON.stringify(baseDocument({ findings: [finding("aaa")] })),
    );
    const read = await readFindingsDocument(fs, FIXTURE_RUN_DIR);
    expect(read?.findings).toHaveLength(1);
  });
});

describe("mergeCoverage", () => {
  test("sums the step-based and unit-based rows of one domain", () => {
    const merged = mergeCoverage(
      [
        coverage({
          unitsTotal: 4,
          unitsAudited: 3,
          skipped: [{ unitId: "hadolint", reason: "skipped: no Dockerfile" }],
        }),
      ],
      [
        coverage({
          unitsTotal: 12,
          unitsAudited: 11,
          skipped: [{ unitId: "unit-1", reason: "batch-failed: timeout" }],
        }),
      ],
    );
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ domain: "appsec", unitsTotal: 16, unitsAudited: 14 });
    expect(merged[0]?.skipped).toHaveLength(2);
  });

  test("keeps the reconciliation invariant across the merge", () => {
    const merged = mergeCoverage(
      [
        coverage({
          unitsTotal: 2,
          unitsAudited: 1,
          skipped: [{ unitId: "knip", reason: "failed: crashed" }],
        }),
      ],
      [
        coverage({
          unitsTotal: 3,
          unitsAudited: 1,
          skipped: [
            { unitId: "u1", reason: "no-verdict: nothing came back" },
            { unitId: "u2", reason: "batch-failed: quota" },
          ],
        }),
      ],
    );
    for (const row of merged) {
      expect(row.unitsAudited + row.skipped.length).toBe(row.unitsTotal);
    }
  });

  test("keeps a domain only one side has", () => {
    const merged = mergeCoverage(
      [coverage({ domain: "dependencies" })],
      [coverage({ domain: "data" })],
    );
    expect(merged.map((row) => row.domain)).toEqual(["dependencies", "data"]);
  });

  test("does not list the same skip twice", () => {
    const entry = { unitId: "unit-1", reason: "batch-failed: timeout" };
    const merged = mergeCoverage(
      [coverage({ unitsTotal: 1, unitsAudited: 0, skipped: [entry] })],
      [coverage({ unitsTotal: 1, unitsAudited: 1, skipped: [entry] })],
    );
    expect(merged[0]?.skipped).toHaveLength(1);
  });

  test("orders rows by the contract's domain order", () => {
    const merged = mergeCoverage(
      [coverage({ domain: "deadcode" }), coverage({ domain: "data" })],
      [coverage({ domain: "dependencies" })],
    );
    expect(merged.map((row) => row.domain)).toEqual(["dependencies", "data", "deadcode"]);
  });
});

describe("mergeAuditIntoFindings", () => {
  test("adds the audit's findings and assurances to phase 1's document", () => {
    const merged = mergeAuditIntoFindings(baseDocument({ findings: [finding("tool-1")] }), {
      runId: "r",
      target: "/repo",
      findings: [finding("agent-1")],
      assurances: [assurance("ass-1")],
      coverage: [coverage()],
      droppedFindings: 2,
    });
    expect(merged.findings.map((entry) => entry.id).sort()).toEqual(["agent-1", "tool-1"]);
    expect(merged.assurances).toHaveLength(1);
    expect(merged.droppedFindings).toBe(2);
  });

  test("keeps phase 1's finding when both phases produced the same identity", () => {
    const merged = mergeAuditIntoFindings(
      baseDocument({ findings: [finding("same", { source: { kind: "tool", name: "opengrep" } })] }),
      {
        runId: "r",
        target: "/repo",
        findings: [finding("same")],
        assurances: [],
        coverage: [],
        droppedFindings: 0,
      },
    );
    expect(merged.findings).toHaveLength(1);
    expect(merged.findings[0]?.source.name).toBe("opengrep");
  });

  test("adds the dropped counters rather than replacing them", () => {
    const merged = mergeAuditIntoFindings(baseDocument({ droppedFindings: 3 }), {
      runId: "r",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: [],
      droppedFindings: 4,
    });
    expect(merged.droppedFindings).toBe(7);
  });

  test("works with no phase 1 document at all", () => {
    const merged = mergeAuditIntoFindings(null, {
      runId: "audit-only",
      target: "/repo",
      findings: [finding("agent-1")],
      assurances: [],
      coverage: [coverage()],
      droppedFindings: 0,
    });
    expect(merged.runId).toBe("audit-only");
    expect(merged.findings).toHaveLength(1);
  });

  test("is deterministic: the order the findings arrive in cannot change the bytes", () => {
    const first = finding("aaa", { severity: "low", location: { file: "src/z.ts", line: 3 } });
    const second = finding("bbb", {
      severity: "critical",
      location: { file: "src/a.ts", line: 9 },
    });
    const third = finding("ccc", { severity: "high", domain: "data", rule: "data.n-plus-one" });
    const forwards = mergeAuditIntoFindings(baseDocument({ findings: [first] }), {
      runId: "r",
      target: "/repo",
      findings: [second, third],
      assurances: [assurance("z"), assurance("a")],
      coverage: [coverage()],
      droppedFindings: 0,
    });
    const backwards = mergeAuditIntoFindings(baseDocument({ findings: [first] }), {
      runId: "r",
      target: "/repo",
      findings: [third, second],
      assurances: [assurance("a"), assurance("z")],
      coverage: [coverage()],
      droppedFindings: 0,
    });
    expect(JSON.stringify(forwards)).toBe(JSON.stringify(backwards));
    // Sorted by severity first, which is phase 1's own order.
    expect(forwards.findings.map((entry) => entry.severity)).toEqual(["critical", "high", "low"]);
  });

  test("produces a document that survives being read back", () => {
    const merged = mergeAuditIntoFindings(null, {
      runId: "r",
      target: "/repo",
      findings: [finding("a")],
      assurances: [assurance("b")],
      coverage: [coverage()],
      droppedFindings: 1,
    });
    expect(() => FindingsDocumentSchema.parse(JSON.parse(JSON.stringify(merged)))).not.toThrow();
  });
});

describe("writeAuditReport", () => {
  test("writes audit.json with a trailing newline and re-reads as the same document", async () => {
    const fs = recordingFileSystem();
    const path = await writeAuditReport(fs, FIXTURE_RUN_DIR, report());
    expect(path).toBe(join(FIXTURE_RUN_DIR, AUDIT_FILE));
    const raw = fs.written.get(path) ?? "";
    expect(raw.endsWith("\n")).toBe(true);
    expect(() => AuditReportSchema.parse(JSON.parse(raw))).not.toThrow();
  });

  test("refuses a report whose numbers are not numbers", () => {
    expect(() => report({ dispatches: -1 })).toThrow();
  });

  test("carries the out-of-slice counter separately from the unresolvable one", () => {
    const built = report({
      dropped: {
        unresolved: 1,
        unresolvedEvidence: 0,
        outOfSlice: 4,
        outOfSliceEvidence: 2,
        duplicates: 0,
        relocated: 3,
        strayVerdicts: 1,
        assuranceEvidence: 0,
        byReason: { "file-not-found": 1 },
      },
    });
    expect(built.dropped.outOfSlice).toBe(4);
    expect(built.dropped.unresolved).toBe(1);
  });
});

describe("writeAssurancesDocument", () => {
  test("writes assurances.json with the assurances in a stable order", async () => {
    const fs = recordingFileSystem();
    const document = buildAssurancesDocument({
      runId: "r",
      target: "/repo",
      assurances: [assurance("z", { check: "z check" }), assurance("a", { check: "a check" })],
      coverage: [coverage()],
    });
    const path = await writeAssurancesDocument(fs, FIXTURE_RUN_DIR, document);
    expect(path).toBe(join(FIXTURE_RUN_DIR, ASSURANCES_FILE));
    expect(document.assurances.map((entry) => entry.check)).toEqual(["a check", "z check"]);
  });
});
