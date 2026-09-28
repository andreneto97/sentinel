import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { AgentFailureKindSchema } from "../agents/errors.ts";
import { type AuditUnit, type CodeRef, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { AuditUnitKind } from "../contracts/inventory.ts";
import { InventoryDocumentSchema, zeroCounts } from "../contracts/inventory.ts";
import { FINDINGS_FILE } from "../scan/artifacts.ts";
import { unit } from "./__fixtures__/batch-fixtures.ts";
import {
  FIXTURE_RUN_DIR,
  FIXTURE_TARGET,
  INVOICES_FILE,
  LEGACY_FILE,
  ORDERS_FILE,
  type ScriptedFinding,
  type ScriptedVerdict,
  auditContext,
  brokenUnit,
  cleanUnit,
  fixturePrompt,
  fixtureRuntime,
  lineOf,
  realBatch,
  recordingFileSystem,
  replyOf,
  routeUnit,
  verdictSource,
} from "./__fixtures__/harness.ts";
import { ASSURANCES_FILE, AUDIT_FILE, AuditReportSchema } from "./artifacts.ts";
import {
  type AuditBatch,
  batchTimeoutMs,
  buildSliceIndex,
  gateFinding,
  gateRef,
  partialReason,
  runAudit,
  stopFor,
} from "./audit.ts";
import { buildBatches, buildPrompt, citedRanges, wasShown } from "./batch.ts";
import { UNBOUNDED_BUDGET, buildAuditBound } from "./budget.ts";
import { coverageReconciles, emptySkipCounts } from "./coverage.ts";
import type { UnitOutcome } from "./coverage.ts";
import type { BatchProgress } from "./progress.ts";
import { checkIdsFor, rulesFor } from "./prompts/index.ts";
import { RISK_ORDERING } from "./risk.ts";
import { verdictSource as realVerdictSource } from "./verdict.ts";

const OWNERSHIP_CHECK = "appsec.ownership-asserted-before-write";

/** A flagged finding the agent could plausibly return about the broken handler. */
function idorClaim(line: number, overrides: Partial<ScriptedFinding> = {}): ScriptedFinding {
  return {
    rule: "appsec.idor",
    severity: "high",
    confidence: "medium",
    title: "Invoice voided without an ownership predicate",
    description: "The handler takes the invoice id from the path and updates the row.",
    impact: "Any authenticated caller can void another tenant's invoice.",
    recommendation: "Constrain the update by the authenticated principal.",
    location: { file: INVOICES_FILE, line },
    cwe: ["CWE-639"],
    ...overrides,
  };
}

/** The clean verdict for the ownership handler, asserting the check it passes. */
function cleanVerdict(unitId: string, evidenceLine: number): ScriptedVerdict {
  return {
    unitId,
    status: "clean",
    checks: [
      {
        id: OWNERSHIP_CHECK,
        statement: "ownership asserted before write",
        subject: "mutation handlers",
        evidence: [{ file: ORDERS_FILE, line: evidenceLine }],
      },
    ],
  };
}

describe("the slice gate", () => {
  const index = buildSliceIndex(
    [
      { file: "src/api/invoices.ts", startLine: 7, endLine: 12 },
      { file: "./src/api/orders.ts", startLine: 9, endLine: 20 },
      { file: "../outside/secrets.ts", startLine: 1, endLine: 4 },
    ],
    FIXTURE_TARGET,
  );

  /** A citation as it looks once the verifier has proved it. */
  function ref(file: string, line: number, endLine?: number): CodeRef {
    return { file, line, ...(endLine === undefined ? {} : { endLine }), snippet: "…" };
  }

  test("passes a citation inside a range the batch provided", () => {
    expect(gateRef(ref("src/api/invoices.ts", 9), index)).toMatchObject({ line: 9 });
  });

  test("refuses a citation the agent was never shown, in a file it was shown", () => {
    expect(gateRef(ref("src/api/invoices.ts", 40), index)).toBeNull();
  });

  test("refuses a citation in a file no slice came from", () => {
    expect(gateRef(ref("src/legacy/exports.ts", 3), index)).toBeNull();
  });

  test("normalises the slice's own path, so `./x` and `x` are one file", () => {
    expect(gateRef(ref("src/api/orders.ts", 10), index)).not.toBeNull();
  });

  test("drops a slice that resolves outside the target repository", () => {
    expect(index.has("../outside/secrets.ts")).toBe(false);
  });

  test("clamps an extent that runs past the slice, and says so in the ref", () => {
    const gated = gateRef(ref("src/api/invoices.ts", 8, 500), index);
    expect(gated?.endLine).toBe(12);
    expect(gated?.note).toContain("extent clamped to line 12");
  });

  test("drops the extent entirely when the clamp collapses it onto the line", () => {
    const gated = gateRef(ref("src/api/invoices.ts", 12, 500), index);
    expect(gated?.endLine).toBeUndefined();
    expect(gated?.note).toContain("extent clamped");
  });

  test("a `shown` test rejects a line the slice elided, which the extent admits", () => {
    const ref: CodeRef = { file: "src/api/invoices.ts", line: 9, snippet: "…" };
    // The extent covers line 9; the batch says it never printed it.
    expect(gateRef(ref, index)).not.toBeNull();
    expect(gateRef(ref, index, (_file, line) => line !== 9)).toBeNull();
  });

  test("gateFinding filters out-of-slice evidence and counts it", () => {
    const gated = gateFinding(
      {
        id: "x",
        domain: "appsec",
        rule: "appsec.idor",
        severity: "high",
        confidence: "medium",
        title: "t",
        description: "d",
        location: ref("src/api/invoices.ts", 9),
        evidence: [ref("src/api/orders.ts", 10), ref("src/legacy/exports.ts", 3)],
        impact: "i",
        recommendation: "r",
        acceptanceCriteria: [],
        cwe: [],
        owasp: [],
        source: { kind: "agent", name: "audit" },
      },
      index,
    );
    expect(gated?.droppedEvidence).toBe(1);
    expect(gated?.finding.evidence).toHaveLength(1);
  });

  test("gateFinding refuses the whole finding when its location is out of slice", () => {
    const gated = gateFinding(
      {
        id: "x",
        domain: "appsec",
        rule: "appsec.idor",
        severity: "high",
        confidence: "medium",
        title: "t",
        description: "d",
        location: ref("src/legacy/exports.ts", 3),
        evidence: [],
        impact: "i",
        recommendation: "r",
        acceptanceCriteria: [],
        cwe: [],
        owasp: [],
        source: { kind: "agent", name: "audit" },
      },
      index,
    );
    expect(gated).toBeNull();
  });
});

describe("runAudit", () => {
  test("turns a flagged verdict into a finding whose snippet came from disk", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean, broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime, dispatcher } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              batchId: "appsec-routes-1",
              verdicts: [
                cleanVerdict(clean.id, ownershipLine),
                { unitId: broken.id, status: "flagged", findings: [idorClaim(updateLine)] },
              ],
            }),
            // The prompt has to contain the code, because the agent cannot read it.
            expectPromptContains: [
              "export async function voidInvoice",
              "ownerId: session.userId",
              clean.id,
            ],
          },
        ],
      },
    ]);

    const ctx = auditContext();
    const result = await runAudit(ctx, {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(dispatcher.calls).toHaveLength(1);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding).toMatchObject({
      rule: "appsec.idor",
      domain: "appsec",
      severity: "high",
      source: { kind: "agent", name: "audit" },
    });
    expect(finding?.location.file).toBe(INVOICES_FILE);
    expect(finding?.location.line).toBe(updateLine);
    // Extracted by Sentinel, never taken from the model's reply.
    expect(finding?.location.snippet).toContain("db.invoice.update");

    expect(result.batches[0]).toMatchObject({
      batchId: "appsec-routes-1",
      status: "audited",
      units: 2,
      verdicts: 2,
      findings: 1,
    });
    expect(result.units).toMatchObject({ total: 2, audited: 2, skipped: 0 });
    expect(result.coverage).toEqual([
      { domain: "appsec", unitsTotal: 2, unitsAudited: 2, skipped: [] },
    ]);
    expect(result.kinds[0]).toMatchObject({ kind: "route", unitsTotal: 2, unitsAudited: 2 });
    expect(coverageReconciles(result.coverage)).toBe(true);
    expect(coverageReconciles(result.kinds)).toBe(true);
    expect(result.stats.metadata.synthetic).toBe(true);
    expect(result.dropped).toMatchObject({ unresolved: 0, outOfSlice: 0, strayVerdicts: 0 });
  });

  test("turns a clean verdict into an assurance with evidence read from disk", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean, broken]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                cleanVerdict(clean.id, ownershipLine),
                { unitId: broken.id, status: "flagged", findings: [idorClaim(updateLine)] },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.assurances).toHaveLength(1);
    const assurance = result.assurances[0];
    expect(assurance).toMatchObject({
      domain: "appsec",
      check: "ownership asserted before write",
      scope: "1/2 mutation handlers",
      unitsChecked: 1,
    });
    expect(assurance?.evidence[0]?.file).toBe(ORDERS_FILE);
    expect(assurance?.evidence[0]?.snippet).toContain("ownerId: session.userId");
  });

  test("drops a citation the batch never provided, separately from one that does not exist", async () => {
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const legacyLine = await lineOf(LEGACY_FILE, "export function renderLegacyExport");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                {
                  unitId: broken.id,
                  status: "flagged",
                  findings: [
                    idorClaim(updateLine),
                    // Real code on disk, never pasted into this prompt: the model
                    // is answering from memory of the repository.
                    idorClaim(legacyLine, {
                      rule: "appsec.unsafe-export",
                      location: { file: LEGACY_FILE, line: legacyLine },
                    }),
                    // Code that does not exist at all.
                    idorClaim(3, {
                      rule: "appsec.missing-auth",
                      location: { file: "src/api/ghost.ts", line: 3 },
                    }),
                  ],
                },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
    });

    expect(result.findings.map((entry) => entry.rule)).toEqual(["appsec.idor"]);
    expect(result.dropped.outOfSlice).toBe(1);
    expect(result.dropped.unresolved).toBe(1);
    expect(result.dropped.byReason["file-not-found"]).toBe(1);
    // Both halves are claims the reader never sees, so both are disclosed.
    expect(result.document?.droppedFindings).toBe(2);
    // The unit was still audited: a dropped claim is not a missing verdict.
    expect(result.units).toMatchObject({ total: 1, audited: 1 });
  });

  test("corrects a drifted line number when, and only when, the agent quoted the line", async () => {
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const quote =
      "await db.invoice.update({ where: { id: params.id }, data: { voidedAt: new Date() } });";

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                {
                  unitId: broken.id,
                  status: "flagged",
                  findings: [
                    idorClaim(updateLine, {
                      // One line off, but it quoted what it read.
                      location: { file: INVOICES_FILE, line: updateLine - 1, quote },
                    }),
                  ],
                },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
    });

    expect(result.findings[0]?.location.line).toBe(updateLine);
    expect(result.findings[0]?.location.note).toContain(`relocated from line ${updateLine - 1}`);
    expect(result.dropped.relocated).toBe(1);
    // And the quote never reaches the report: the snippet is Sentinel's own.
    expect(result.findings[0]?.location.snippet).toContain("db.invoice.update");
  });

  test("drops out-of-slice evidence without dropping the finding", async () => {
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const legacyLine = await lineOf(LEGACY_FILE, "export function escapeCell");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                {
                  unitId: broken.id,
                  status: "flagged",
                  findings: [
                    idorClaim(updateLine, { evidence: [{ file: LEGACY_FILE, line: legacyLine }] }),
                  ],
                },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.evidence).toEqual([]);
    expect(result.dropped.outOfSliceEvidence).toBe(1);
  });

  test("a failed batch loses its units to `skipped`, and never to `clean`", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ reply: replyOf({ verdicts: [cleanVerdict(clean.id, ownershipLine)] }) }],
        },
        {
          batchId: "appsec-routes-2",
          turns: [{ failure: { kind: "timeout", detail: "no reply within 240000ms" } }],
        },
      ],
      { maxAttempts: 1 },
    );

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.batches[1]).toMatchObject({
      batchId: "appsec-routes-2",
      status: "failed",
      failure: "timeout",
      verdicts: 0,
    });
    expect(result.units).toMatchObject({ total: 2, audited: 1, skipped: 1 });
    expect(result.units.byCause["batch-failed"]).toBe(1);
    const appsec = result.coverage.find((row) => row.domain === "appsec");
    expect(appsec).toMatchObject({ unitsTotal: 2, unitsAudited: 1 });
    expect(appsec?.skipped[0]).toEqual({
      unitId: broken.id,
      reason: "batch-failed: no reply within 240000ms (timeout)",
    });
    expect(coverageReconciles(result.coverage)).toBe(true);
    // The batch that worked still contributed.
    expect(result.assurances).toHaveLength(1);
    expect(result.aborted).toBe(false);
  });

  test("a subscription limit stops the phase and says how far it got", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);

    const { runtime, dispatcher } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ failure: { kind: "quota", detail: "5-hour limit reached" } }],
        },
        {
          batchId: "appsec-routes-2",
          turns: [{ reply: replyOf({ verdicts: [] }) }],
        },
      ],
      { concurrency: 1, maxAttempts: 1 },
    );

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.stats.quotaExhausted).toBe(true);
    expect(result.aborted).toBe(true);
    expect(result.batches.map((entry) => entry.failure)).toEqual(["quota", "quota"]);
    expect(result.units).toMatchObject({ total: 2, audited: 0, skipped: 2 });
    expect(result.findings).toEqual([]);
    // The second batch was never sent: the runtime latched shut instead.
    expect(dispatcher.calls.map((call) => call.batchId)).toEqual(["appsec-routes-1"]);
    expect(dispatcher.remaining()).toEqual([{ batchId: "appsec-routes-2", unplayedTurns: 1 }]);
  });

  test("an inconclusive verdict is not audited, and a missing one says so", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean, broken]);

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                {
                  unitId: clean.id,
                  status: "inconclusive",
                  note: "the ownership check may sit in a helper I was not shown",
                },
                // A verdict about a unit this batch never carried.
                { unitId: "0000000000000000", status: "clean" },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.dropped.strayVerdicts).toBe(1);
    expect(result.batches[0]).toMatchObject({ status: "partial", verdicts: 0 });
    expect(result.units).toMatchObject({ total: 2, audited: 0, skipped: 2 });
    const reasons = (result.coverage[0]?.skipped ?? []).map((entry) => entry.reason).sort();
    expect(reasons).toEqual([
      "inconclusive: the ownership check may sit in a helper I was not shown",
      "no-verdict: the agent returned no verdict for this unit",
    ]);
    expect(coverageReconciles(result.coverage)).toBe(true);
  });

  test("a unit no batch covered is reported, not forgotten", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [cleanVerdict(clean.id, ownershipLine)] }) }],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.units).toMatchObject({ total: 2, audited: 1 });
    expect(result.units.byCause["no-batch"]).toBe(1);
    expect(result.coverage[0]?.skipped[0]).toEqual({
      unitId: broken.id,
      reason: "no-batch: no batch covered this unit",
    });
  });

  test("a domain whose batch was deferred counts the unit against its own total", async () => {
    // One unit, two domains: a route is audited for access control and for its
    // API contract. The access-control batch was dispatched; the contract batch
    // was deferred by a ceiling. The `api` row must read 0 of 1 — not 0 of 0, and
    // certainly not a clean 1 of 1 — because nobody asked that unit D6's
    // questions. Before the outcome loop knew about domains, the unit was claimed
    // by its `appsec` verdict and vanished from the `api` table altogether.
    const clean = await cleanUnit();
    const appsec = await realBatch("appsec-routes-1", [clean], "appsec");
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);
    const planner = Object.assign(() => [appsec], {
      plan: () => ({
        skipped: [
          {
            unitId: clean.id,
            domain: "api" as const,
            cause: "budget" as const,
            reason: "the run reached its batch budget — deferred for the api domain",
          },
        ],
      }),
    });

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: planner,
      prompt: fixturePrompt,
      units: [clean],
      domains: ["appsec", "api"],
    });

    expect(result.coverage.find((row) => row.domain === "appsec")).toMatchObject({
      unitsTotal: 1,
      unitsAudited: 1,
    });
    const api = result.coverage.find((row) => row.domain === "api");
    expect(api).toMatchObject({ unitsTotal: 1, unitsAudited: 0 });
    expect(api?.skipped[0]?.reason).toBe(
      "budget: the run reached its batch budget — deferred for the api domain",
    );
    // At run level the unit is audited: one unit, one verdict, counted once.
    expect(result.units).toMatchObject({ total: 1, audited: 1 });
    expect(result.kinds[0]).toMatchObject({ kind: "route", unitsTotal: 1, unitsAudited: 1 });
    expect(coverageReconciles(result.coverage)).toBe(true);
  });

  test("a batch cannot inflate coverage with a unit the inventory never enumerated", async () => {
    const clean = await cleanUnit();
    const invented = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean, invented]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                cleanVerdict(clean.id, ownershipLine),
                { unitId: invented.id, status: "clean" },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
    });

    expect(result.units).toMatchObject({ total: 1, audited: 1 });
    expect(result.batches[0]?.units).toBe(1);
    expect(result.dropped.strayVerdicts).toBe(1);
  });

  test("collapses two verdicts that describe the same problem into one finding", async () => {
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const readLine = await lineOf(INVOICES_FILE, "db.invoice.findUnique");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                {
                  unitId: broken.id,
                  status: "flagged",
                  findings: [
                    idorClaim(updateLine),
                    idorClaim(readLine, { location: { file: INVOICES_FILE, line: readLine } }),
                  ],
                },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
    });

    expect(result.findings).toHaveLength(1);
    expect(result.dropped.duplicates).toBe(1);
  });

  test("does not dispatch a batch for a domain outside the run's scope", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("api-routes-1", [clean], "api");

    const { runtime, dispatcher } = fixtureRuntime([
      { batchId: "api-routes-1", turns: [{ reply: replyOf({ verdicts: [] }) }] },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
      domains: ["appsec"],
    });

    expect(dispatcher.calls).toEqual([]);
    expect(result.batches).toEqual([]);
    expect(result.coverage.map((row) => row.domain)).toEqual(["appsec"]);
    expect(result.coverage[0]?.skipped[0]?.reason).toBe("no-batch: no batch covered this unit");
  });

  test("reads its units from inventory.json when it is not handed any", async () => {
    const fs = recordingFileSystem();
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const inventory = InventoryDocumentSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      runId: "20240101T000000-0000abcd",
      target: FIXTURE_TARGET,
      units: [clean, broken] satisfies AuditUnit[],
      counts: { ...zeroCounts(), route: 2 },
      enumerators: [{ name: "next-routes", status: "ok", kinds: ["route"], units: 2 }],
      dropped: [],
    });
    await fs.writeFile(join(FIXTURE_RUN_DIR, "inventory.json"), JSON.stringify(inventory));

    const batch = await realBatch("appsec-routes-1", [clean, broken]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                cleanVerdict(clean.id, ownershipLine),
                { unitId: broken.id, status: "clean" },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext({ fs }), {
      runtime,
      verdicts: verdictSource,
      batches: (units) => [{ ...batch, units: [...units] } satisfies AuditBatch],
      prompt: fixturePrompt,
    });

    expect(result.units).toMatchObject({ total: 2, audited: 2 });
  });

  test("writes the three artifacts, merging into phase 1's findings.json", async () => {
    const fs = recordingFileSystem();
    const base = {
      schemaVersion: SCHEMA_VERSION,
      runId: "20240101T000000-0000abcd",
      target: FIXTURE_TARGET,
      findings: [],
      assurances: [],
      coverage: [
        {
          domain: "appsec",
          unitsTotal: 3,
          unitsAudited: 2,
          skipped: [{ unitId: "gitleaks", reason: "skipped: not installed" }],
        },
      ],
      droppedFindings: 1,
    };
    await fs.writeFile(join(FIXTURE_RUN_DIR, FINDINGS_FILE), JSON.stringify(base));

    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [
          {
            reply: replyOf({
              verdicts: [
                { unitId: broken.id, status: "flagged", findings: [idorClaim(updateLine)] },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await runAudit(auditContext({ fs }), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
    });

    expect(result.artifacts).toEqual(
      [
        join(FIXTURE_RUN_DIR, ASSURANCES_FILE),
        join(FIXTURE_RUN_DIR, AUDIT_FILE),
        join(FIXTURE_RUN_DIR, FINDINGS_FILE),
      ].sort(),
    );

    // findings.json keeps phase 1's coverage row and adds the audit's.
    const merged = JSON.parse(fs.written.get(join(FIXTURE_RUN_DIR, FINDINGS_FILE)) ?? "{}") as {
      findings: unknown[];
      coverage: Array<{ domain: string; unitsTotal: number; unitsAudited: number }>;
      droppedFindings: number;
    };
    expect(merged.findings).toHaveLength(1);
    expect(merged.coverage[0]).toMatchObject({ domain: "appsec", unitsTotal: 4, unitsAudited: 3 });
    expect(merged.droppedFindings).toBe(1);

    const auditJson = fs.written.get(join(FIXTURE_RUN_DIR, AUDIT_FILE)) ?? "";
    const report = AuditReportSchema.parse(JSON.parse(auditJson));
    expect(report.runtime.synthetic).toBe(true);
    expect(report.batches).toHaveLength(1);
    expect(report.findingsKept).toBe(1);
  });

  test("writes nothing when writing is turned off", async () => {
    const fs = recordingFileSystem();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [broken]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: broken.id, status: "clean" }] }) }],
      },
    ]);

    const result = await runAudit(auditContext({ fs }), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [broken],
      write: false,
    });

    expect(fs.written.size).toBe(0);
    expect(result.artifacts).toEqual([]);
    expect(result.document).toBeNull();
    expect(result.report.units.audited).toBe(1);
  });

  test("a prompt that cannot be built costs its own batch and nothing else", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [cleanVerdict(clean.id, ownershipLine)] }) }],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second],
      prompt: (batch) => {
        if (batch.id === "appsec-routes-2") throw new Error("no template for this unit kind");
        return fixturePrompt(batch);
      },
      units: [clean, broken],
    });

    expect(result.batches[1]).toMatchObject({ status: "failed", failure: "transient" });
    expect(result.batches[1]?.reason).toContain("no template for this unit kind");
    expect(result.units).toMatchObject({ total: 2, audited: 1, skipped: 1 });
    expect(result.assurances).toHaveLength(1);
  });

  test("a cancelled run reports its units as cancelled, not as clean", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const controller = new AbortController();
    controller.abort();

    const { runtime, dispatcher } = fixtureRuntime([
      { batchId: "appsec-routes-1", turns: [{ reply: replyOf({ verdicts: [] }) }] },
    ]);

    const result = await runAudit(auditContext({ signal: controller.signal }), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
    });

    expect(dispatcher.calls).toEqual([]);
    expect(result.aborted).toBe(true);
    expect(result.units.byCause.cancelled).toBe(1);
    expect(result.coverage[0]?.skipped[0]?.reason).toContain("cancelled: the run was cancelled");
  });

  test("composes with the real batch planner, prompt builder and verdict schema", async () => {
    // The seams this phase declares are structural, so the only way to know they
    // fit is to wire the real `src/audit/batch.ts`, `src/audit/prompts/` and
    // `src/audit/verdict.ts` into them and run a batch end to end.
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const ctx = auditContext();

    const planned = await buildBatches([clean, broken], ctx);
    expect(planned.length).toBeGreaterThan(0);
    const batch = planned[0];
    if (batch === undefined) throw new Error("the planner produced no batch");

    const checkIds = checkIdsFor("route");
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");
    const updateLine = await lineOf(INVOICES_FILE, "db.invoice.update");
    const firstCheck = checkIds[0];
    const rule = rulesFor("route")[0];
    if (firstCheck === undefined || rule === undefined) {
      throw new Error("the route prompt declares no checks or no rules");
    }

    // Their wire format: `checks` is a map keyed by the prompt's check ids, and a
    // passing check may carry the line that proves it.
    const passing = Object.fromEntries(checkIds.map((id) => [id, "pass"]));
    const reply = JSON.stringify({
      batchId: batch.id,
      verdicts: [
        {
          unitId: clean.id,
          checks: {
            ...passing,
            [firstCheck]: { result: "pass", evidence: { file: ORDERS_FILE, line: ownershipLine } },
          },
        },
        {
          unitId: broken.id,
          checks: { ...passing, [firstCheck]: "fail" },
          findings: [
            {
              rule,
              title: "Invoice voided without an ownership predicate",
              description: "The handler takes the invoice id from the path and updates the row.",
              severity: "high",
              location: { file: INVOICES_FILE, line: updateLine },
              impact: "Any authenticated caller can void another tenant's invoice.",
              recommendation: "Constrain the update by the authenticated principal.",
            },
          ],
        },
      ],
    });

    const ranges = new Map(planned.map((entry) => [entry.id, citedRanges(entry)]));
    const { runtime } = fixtureRuntime([{ batchId: batch.id, turns: [{ reply }] }]);
    const result = await runAudit(ctx, {
      runtime,
      verdicts: realVerdictSource(),
      batches: buildBatches,
      prompt: buildPrompt,
      units: [clean, broken],
      // The precise gate: the lines the prompt actually printed, from the gutter.
      // Indexed by batch id, because the hook is handed the structural batch.
      shown: (planBatch) => {
        const own = ranges.get(planBatch.id);
        return (file, line) => own === undefined || wasShown(own, file, line);
      },
    });

    expect(result.units).toMatchObject({ total: 2, audited: 2, skipped: 0 });
    expect(result.findings.map((entry) => entry.rule)).toEqual([rule]);
    expect(result.findings[0]?.location.snippet).toContain("db.invoice.update");
    expect(result.findings[0]?.source).toEqual({ kind: "agent", name: "audit" });
    expect(result.assurances.length).toBeGreaterThan(0);
    expect(result.dropped).toMatchObject({ unresolved: 0, outOfSlice: 0, strayVerdicts: 0 });
    expect(coverageReconciles(result.coverage)).toBe(true);
    expect(result.batches[0]?.status).toBe("audited");
  });

  test("a reply that does not validate costs its batch, not the phase", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);

    const { runtime } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ reply: "I could not complete this audit." }],
        },
      ],
      { maxAttempts: 1 },
    );

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
    });

    expect(result.batches[0]?.status).toBe("failed");
    expect(result.units).toMatchObject({ total: 1, audited: 0, skipped: 1 });
    expect(result.findings).toEqual([]);
  });
});

describe("partialReason", () => {
  test("an inconclusive unit and a silent one are reported as different failures", () => {
    // A model that says "I cannot decide" did what the certainty rule asks of it;
    // a reply with a hole in it did not. Reporting both as "came back without a
    // verdict" would call an honest answer a malformed one.
    const outcomes: UnitOutcome[] = [
      { unitId: "a", kind: "route", domain: "appsec", audited: true },
      {
        unitId: "b",
        kind: "route",
        domain: "appsec",
        audited: false,
        cause: "inconclusive",
        reason: "the auth helper was not shown",
      },
      {
        unitId: "c",
        kind: "route",
        domain: "appsec",
        audited: false,
        cause: "no-verdict",
        reason: "the agent returned no verdict for this unit",
      },
    ];
    expect(partialReason(3, outcomes)).toBe(
      "2 of 3 units have no verdict: 1 the agent declined to decide, 1 it returned no verdict for",
    );
  });

  test("only inconclusive units are not described as missing answers", () => {
    const outcomes: UnitOutcome[] = [
      { unitId: "a", kind: "migration", domain: "data", audited: false, cause: "inconclusive" },
    ];
    expect(partialReason(8, outcomes)).toBe(
      "1 of 8 units have no verdict: 1 the agent declined to decide",
    );
  });
});

describe("stopFor", () => {
  test("Ctrl-C outranks every ceiling the operator chose", () => {
    expect(
      stopFor({ cancelled: true, quota: true, clock: "wall-clock", planned: "batch-budget" }),
    ).toBe("cancelled");
  });

  test("a usage limit outranks a ceiling, because it is not the operator's decision", () => {
    expect(
      stopFor({ cancelled: false, quota: true, clock: "wall-clock", planned: "batch-budget" }),
    ).toBe("quota");
  });

  test("the clock outranks the plan's own budget, because it fired later", () => {
    expect(
      stopFor({ cancelled: false, quota: false, clock: "wall-clock", planned: "batch-budget" }),
    ).toBe("wall-clock");
  });

  test("nothing firing is a complete run", () => {
    expect(stopFor({ cancelled: false, quota: false, clock: undefined, planned: undefined })).toBe(
      "complete",
    );
  });
});

describe("the per-kind dispatch budget", () => {
  /** A batch carrying exactly these kinds; only `units` decides the budget. */
  function batchOfKinds(...kinds: readonly AuditUnitKind[]): AuditBatch {
    return {
      id: `batch-${kinds.join("-")}`,
      units: kinds.map((kind, index) =>
        unit({ id: `u${index}`, kind, label: kind, file: "a.ts", line: 1 }),
      ),
      slices: [],
    };
  }

  test("a kind whose slow tail leaves headroom under the default does not override it", () => {
    expect(batchTimeoutMs(batchOfKinds("route"))).toBeUndefined();
    expect(batchTimeoutMs(batchOfKinds("cron", "sink"))).toBeUndefined();
  });

  test("the most verbose kind gets the raised ceiling its slow tail needs", () => {
    expect(batchTimeoutMs(batchOfKinds("migration"))).toBe(480_000);
  });

  test("a mixed batch is bounded by the slowest kind it carries, not the first", () => {
    expect(batchTimeoutMs(batchOfKinds("data-access", "migration"))).toBe(480_000);
    expect(batchTimeoutMs(batchOfKinds("route", "data-access"))).toBe(360_000);
  });

  test("an empty batch falls back to the runtime's own default", () => {
    expect(batchTimeoutMs({ id: "empty", units: [], slices: [] })).toBeUndefined();
  });
});

describe("the wall-clock ceiling", () => {
  /** A clock a test moves by hand, so a ceiling can be proved without waiting. */
  function steppingClock(stepMs: number): () => number {
    let value = 0;
    return () => {
      const current = value;
      value += stepMs;
      return current;
    };
  }

  test("stops between batches and never truncates one in flight", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);
    // Only the first batch is scripted: if the second were dispatched, the
    // replay would fail rather than quietly returning nothing.
    const { runtime } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
        },
      ],
      { concurrency: 1 },
    );

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second],
      prompt: fixturePrompt,
      units: [clean, broken],
      // Each read of the clock advances it by a minute: the phase start and the
      // first batch's gate are inside the ceiling, the second batch's is not.
      now: steppingClock(60_000),
      maxWallClockMs: 3 * 60_000,
    });

    expect(result.batches.map((batch) => batch.batchId)).toEqual(["appsec-routes-1"]);
    expect(result.bound.stop).toBe("wall-clock");
    expect(result.bound.batchesDispatched).toBe(1);
    expect(result.bound.batchesDeferred).toBe(1);
    // The unit of the batch that was never sent is not clean and is not missing:
    // it is budget-skipped, with the reason a reader can act on.
    expect(result.units.byCause.budget).toBe(1);
    expect(result.units.audited).toBe(1);
    const skipped = result.coverage.flatMap((row) => row.skipped);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]?.unitId).toBe(broken.id);
    expect(skipped[0]?.reason).toStartWith("budget: ");
    expect(skipped[0]?.reason).toContain("wall-clock ceiling");
    expect(coverageReconciles(result.coverage)).toBe(true);
    expect(result.bound.statement).toStartWith("1 of 2 units were not audited: ");
  });

  test("no ceiling means every batch is dispatched", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
      now: steppingClock(60 * 60_000),
      maxWallClockMs: null,
    });

    expect(result.bound.stop).toBe("complete");
    expect(result.bound.statement).toBe("all 1 unit was audited; the run reached no budget");
  });
});

describe("the bound the phase reports", () => {
  test("takes the planner's ceilings and its own counts", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);

    // A planner that batched one unit and deferred the other, as `planBatches`
    // does when it reaches a ceiling.
    const planner = Object.assign(() => [batch], {
      plan: () => ({
        skipped: [
          {
            unitId: broken.id,
            cause: "budget" as const,
            reason: "1 of 2 units were not audited: the run reached its batch budget of 1 batch",
          },
        ],
        bound: buildAuditBound({
          stop: "batch-budget",
          limits: { maxBatches: 1, maxUnits: null, maxWallClockMs: null },
          unitsTotal: 2,
          unitsDispatched: 1,
          unitsAudited: 1,
          unitsDeferred: 1,
          unitsCarriedOver: 0,
          batchesPlanned: 2,
          batchesDispatched: 1,
          batchesDeferred: 1,
          ordering: RISK_ORDERING,
          reasons: ["reachable without authentication"],
        }),
      }),
    });

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: planner,
      prompt: fixturePrompt,
      units: [clean, broken],
    });

    expect(result.bound.stop).toBe("batch-budget");
    expect(result.bound.limits.maxBatches).toBe(1);
    expect(result.bound.unitsTotal).toBe(2);
    expect(result.bound.unitsAudited).toBe(1);
    expect(result.bound.unitsDeferred).toBe(1);
    expect(result.bound.reasons).toEqual(["reachable without authentication"]);
    // Phase 3's own sentence reaches the coverage table, not this phase's
    // generic "no batch covered this unit".
    const skipped = result.coverage.flatMap((row) => row.skipped);
    expect(skipped[0]?.reason).toStartWith("budget: ");
    expect(skipped[0]?.reason).toContain("batch budget of 1 batch");
    expect(result.units.byCause.budget).toBe(1);
  });

  test("reaches `audit.json`, so the dossier cannot read as a complete run", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);
    const ctx = auditContext();
    await ctx.fs.writeFile(
      join(FIXTURE_RUN_DIR, "inventory.json"),
      JSON.stringify(
        InventoryDocumentSchema.parse({
          schemaVersion: SCHEMA_VERSION,
          runId: "20240101T000000-0000abcd",
          target: FIXTURE_TARGET,
          units: [clean],
          counts: { ...zeroCounts(), route: 1 },
          enumerators: [],
          dropped: [],
        }),
      ),
    );

    const result = await runAudit(ctx, {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
    });

    const written = ctx.fs.written.get(join(FIXTURE_RUN_DIR, AUDIT_FILE));
    expect(written).toBeDefined();
    const document = AuditReportSchema.parse(JSON.parse(written ?? "{}"));
    expect(document.bound).toEqual(result.bound);
    expect(document.bound.statement.length).toBeGreaterThan(20);
  });

  test("a report written before budgets existed reads back as an unbounded one", () => {
    // The field is defaulted rather than required: an older `audit.json` must
    // still parse, and what it says about itself must still be true.
    const document = AuditReportSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      runId: "20240101T000000-0000abcd",
      target: FIXTURE_TARGET,
      aborted: false,
      durationMs: 1,
      runtime: {
        kind: "fixture",
        concurrency: 1,
        maxAttempts: 1,
        timeoutMs: 1000,
        synthetic: true,
      },
      dispatches: 0,
      retries: 0,
      failures: Object.fromEntries(
        AgentFailureKindSchema.options.map((kind) => [kind, 0]),
      ) as Record<string, number>,
      quotaExhausted: false,
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
        costUsd: 0,
      },
      batches: [],
      units: { total: 0, audited: 0, skipped: 0, byCause: emptySkipCounts() },
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
    });
    expect(document.bound.stop).toBe("complete");
    expect(document.bound.limits).toEqual(UNBOUNDED_BUDGET);
  });
});

describe("resuming a budget-ended run", () => {
  test("a carried-over unit is not re-asked about and not reported as a gap", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    // The second attempt is given the whole inventory and told which unit the
    // first one already answered for; only the other reaches a batch.
    const batch = await realBatch("appsec-routes-2", [broken]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-2",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: broken.id, status: "clean" }] }) }],
      },
    ]);

    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: (units) => {
        // The planner is handed the pending units only, which is the whole of
        // what `alreadyAudited` buys a resume.
        expect(units.map((unit) => unit.id)).toEqual([broken.id]);
        return [batch];
      },
      prompt: fixturePrompt,
      units: [clean, broken],
      alreadyAudited: [clean.id],
    });

    // This attempt's coverage is about this attempt: `sentinel resume`
    // recomposes it with the previous report rather than double-counting.
    expect(result.units.total).toBe(1);
    expect(result.units.audited).toBe(1);
    expect(result.coverage.flatMap((row) => row.skipped)).toEqual([]);
    // The sentence, though, is about the repository.
    expect(result.bound.unitsCarriedOver).toBe(1);
    expect(result.bound.unitsTotal).toBe(2);
    expect(result.bound.unitsAudited).toBe(2);
    expect(result.bound.statement).toBe("all 2 units were audited; the run reached no budget");
  });
});

describe("the wall-clock default", () => {
  test("is on without the CLI passing it, and takes the planner's own limit", async () => {
    // The batch budget defaults on; a clock that defaulted off would mean a
    // library caller had half a budget and did not know it.
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);
    const planner = Object.assign(() => [batch], {
      plan: () => ({
        skipped: [],
        bound: buildAuditBound({
          stop: "complete",
          limits: { maxBatches: 40, maxUnits: null, maxWallClockMs: 60_000 },
          unitsTotal: 1,
          unitsDispatched: 1,
          unitsAudited: 1,
          unitsDeferred: 0,
          unitsCarriedOver: 0,
          batchesPlanned: 1,
          batchesDispatched: 1,
          batchesDeferred: 0,
          ordering: RISK_ORDERING,
          reasons: [],
        }),
      }),
    });

    // A clock already past the planner's own one-minute limit: the phase adopts
    // that limit without being told, so nothing is dispatched.
    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: planner,
      prompt: fixturePrompt,
      units: [clean],
      now: (() => {
        let value = 0;
        return () => {
          const current = value;
          value += 120_000;
          return current;
        };
      })(),
    });

    expect(result.batches).toEqual([]);
    expect(result.bound.stop).toBe("wall-clock");
    expect(result.units.byCause.budget).toBe(1);
  });
});

describe("progress while the phase runs", () => {
  test("reports every batch as it finishes, with the classification of the ones it loses", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const helper = routeUnit({
      file: LEGACY_FILE,
      symbol: "renderLegacyExport",
      label: "renderLegacyExport",
      line: await lineOf(LEGACY_FILE, "export function renderLegacyExport"),
    });
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);
    const third = await realBatch("appsec-routes-3", [helper]);
    const ownershipLine = await lineOf(ORDERS_FILE, "ownerId: session.userId");

    const { runtime } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ reply: replyOf({ verdicts: [cleanVerdict(clean.id, ownershipLine)] }) }],
        },
        {
          batchId: "appsec-routes-2",
          turns: [{ failure: { kind: "timeout", detail: "no reply within 240000ms" } }],
        },
        // A reply with nothing in it: the unit has no verdict, so the batch is
        // partial rather than failed, and the two must not read the same.
        { batchId: "appsec-routes-3", turns: [{ reply: replyOf({ verdicts: [] }) }] },
      ],
      { concurrency: 1, maxAttempts: 1 },
    );

    const seen: BatchProgress[] = [];
    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second, third],
      prompt: fixturePrompt,
      units: [clean, broken, helper],
      progress: (progress) => void seen.push(progress),
    });

    // One event per dispatched batch, in completion order, and never twice.
    expect(seen.map((event) => event.batchId)).toEqual([
      "appsec-routes-1",
      "appsec-routes-2",
      "appsec-routes-3",
    ]);
    expect(seen.map((event) => event.batchesDone)).toEqual([1, 2, 3]);
    expect(seen.every((event) => event.batchesTotal === 3)).toBe(true);
    // The totals are the planned batches' own, so both ratios finish together.
    expect(seen.map((event) => event.unitsTotal)).toEqual([3, 3, 3]);

    // The loss is classified as it happens, not summed at the end.
    expect(seen[1]).toMatchObject({ status: "failed", failure: "timeout", batchesFailed: 1 });
    expect(seen[1]?.reason).toBe("no reply within 240000ms");
    expect(seen[2]).toMatchObject({ status: "partial", batchesPartial: 1, verdicts: 0 });
    // A failed batch moves no verdict counter, which is what makes a run that is
    // quietly losing batches look different from one that is not.
    expect(seen.map((event) => event.unitsAudited)).toEqual([1, 1, 1]);
    expect(seen.map((event) => event.unitsDispatched)).toEqual([1, 2, 3]);
    expect(seen.map((event) => event.findings)).toEqual([0, 0, 0]);

    // What the progress said and what the report says are the same numbers.
    expect(result.batches.map((batch) => batch.status)).toEqual(["audited", "failed", "partial"]);
    expect(result.units.audited).toBe(1);
  });

  test("a batch the wall clock held back is never reported as finished", async () => {
    const clean = await cleanUnit();
    const broken = await brokenUnit();
    const first = await realBatch("appsec-routes-1", [clean]);
    const second = await realBatch("appsec-routes-2", [broken]);
    const { runtime } = fixtureRuntime(
      [
        {
          batchId: "appsec-routes-1",
          turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
        },
      ],
      { concurrency: 1 },
    );

    const seen: BatchProgress[] = [];
    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [first, second],
      prompt: fixturePrompt,
      units: [clean, broken],
      progress: (progress) => void seen.push(progress),
      now: (() => {
        let value = 0;
        return () => {
          const current = value;
          value += 60_000;
          return current;
        };
      })(),
      maxWallClockMs: 3 * 60_000,
    });

    // Two batches were planned and one was sent: progress reports the one that
    // finished, and the deferral is the bound's sentence to make, not a line
    // claiming a batch completed.
    expect(seen.map((event) => event.batchId)).toEqual(["appsec-routes-1"]);
    expect(seen[0]?.batchesTotal).toBe(2);
    expect(result.bound.stop).toBe("wall-clock");
  });

  test("no progress writer means no accounting, which is what --quiet buys", async () => {
    const clean = await cleanUnit();
    const batch = await realBatch("appsec-routes-1", [clean]);
    const { runtime } = fixtureRuntime([
      {
        batchId: "appsec-routes-1",
        turns: [{ reply: replyOf({ verdicts: [{ unitId: clean.id, status: "clean" }] }) }],
      },
    ]);
    // The assertion is that omitting `progress` is a supported call, not a crash:
    // every other test in this file omits it, and they are the regression guard.
    const result = await runAudit(auditContext(), {
      runtime,
      verdicts: verdictSource,
      batches: () => [batch],
      prompt: fixturePrompt,
      units: [clean],
    });
    expect(result.units.audited).toBe(1);
  });
});
