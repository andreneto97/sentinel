import { describe, expect, test } from "bun:test";
import type { Domain } from "../contracts/findings.ts";
import { AgentVerdictReportSchema } from "../contracts/verdict.ts";
import type { AgentVerdictReport } from "../contracts/verdict.ts";
import { fs, FILES, PROFILE, TARGET, lineOf, routeUnits } from "./__fixtures__/batch-fixtures.ts";
import { type AuditBatch, planBatches } from "./batch.ts";
import { checkIdsFor } from "./prompts/index.ts";
import {
  type VerdictIssueKind,
  assertedChecksOf,
  decodeVerdicts,
  passedChecks,
  readBatchVerdicts,
  verdictSource,
} from "./verdict.ts";

/** One batch of the fixture's three route handlers, prompt and slices included. */
async function routeBatch(domain: Domain = "appsec"): Promise<AuditBatch> {
  const plan = await planBatches({
    units: await routeUnits(),
    slices: { fs, targetDir: TARGET },
    profile: PROFILE,
    budget: { promptChars: 200_000 },
  });
  const batch = plan.batches.find((candidate) => candidate.domain === domain);
  if (batch === undefined) throw new Error(`the fixture produced no ${domain} batch`);
  return batch;
}

/** Every check of the route prompt answered `pass`, which is the clean verdict. */
function allPass(): Record<string, "pass"> {
  const checks: Record<string, "pass"> = {};
  for (const id of checkIdsFor("route")) checks[id] = "pass";
  return checks;
}

/** A reply that answers every unit of the batch cleanly. */
function cleanReport(batch: AuditBatch): AgentVerdictReport {
  return AgentVerdictReportSchema.parse({
    batchId: batch.id,
    verdicts: batch.units.map((unit) => ({ unitId: unit.id, checks: allPass() })),
  });
}

/** The issue kinds a decoding raised. */
function kinds(issues: readonly { kind: VerdictIssueKind }[]): VerdictIssueKind[] {
  return issues.map((issue) => issue.kind);
}

describe("decodeVerdicts", () => {
  test("a clean reply produces one complete verdict per unit and no issues", async () => {
    const batch = await routeBatch();
    const decoded = decodeVerdicts(cleanReport(batch), batch);

    expect(decoded.verdicts).toHaveLength(batch.units.length);
    expect(decoded.missing).toEqual([]);
    expect(decoded.issues).toEqual([]);
    expect(decoded.verdicts.every((verdict) => verdict.complete)).toBe(true);
    expect(decoded.verdicts[0]?.checks).toHaveLength(checkIdsFor("route").length);
    // The batch's order, not the reply's.
    expect(decoded.verdicts.map((verdict) => verdict.unitId)).toEqual(
      batch.units.map((unit) => unit.id),
    );
  });

  test("a verdict for a unit that was not in the batch is rejected, the rest survive", async () => {
    const batch = await routeBatch();
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        { unitId: "invented-unit", checks: allPass() },
        ...batch.units.map((unit) => ({ unitId: unit.id, checks: allPass() })),
      ],
    });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.verdicts.map((verdict) => verdict.unitId)).not.toContain("invented-unit");
    expect(decoded.verdicts).toHaveLength(batch.units.length);
    expect(kinds(decoded.issues)).toContain("unknown-unit");
    expect(decoded.issues[0]?.detail).toContain("not a unit of this batch");
  });

  test("a second verdict for the same unit is discarded", async () => {
    const batch = await routeBatch();
    const first = batch.units[0];
    if (first === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        { unitId: first.id, checks: allPass() },
        { unitId: first.id, checks: allPass(), notes: "again" },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.verdicts).toHaveLength(1);
    expect(kinds(decoded.issues)).toContain("duplicate-unit");
  });

  test("a unit with no verdict is reported as missing, in the shape coverage takes", async () => {
    const batch = await routeBatch();
    const first = batch.units[0];
    if (first === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: first.id, checks: allPass() }],
    });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.missing).toHaveLength(batch.units.length - 1);
    expect(decoded.missing[0]?.kind).toBe("route");
    expect(decoded.missing[0]?.reason).toContain("no verdict");
  });

  test("an unanswered check is a named hole, and the verdict is not complete", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    // The key is absent, not set to something: an omission is the failure mode.
    const checks = Object.fromEntries(
      checkIdsFor("route")
        .filter((id) => id !== "appsec.idor")
        .map((id) => [id, "pass"]),
    );
    const report = AgentVerdictReportSchema.parse({ verdicts: [{ unitId: unit.id, checks }] });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.verdicts[0]?.complete).toBe(false);
    expect(decoded.verdicts[0]?.missingChecks).toEqual(["appsec.idor"]);
    expect(kinds(decoded.issues)).toContain("missing-check");
  });

  test("a secondary domain's reply owes its own five checks, not the kind's twenty-three", async () => {
    // The seam between the registry's domain column and this decoder. The `api`
    // batch prints five questions; the union of every question a route is ever
    // asked is far larger, and judging the reply against the union made a
    // complete answer read as eighteen unanswered checks.
    const batch = await routeBatch("api");
    const unit = batch.units[0];
    if (unit === undefined) throw new Error("the api batch has no units");
    const obliged = checkIdsFor("route", "api");
    expect(obliged.length).toBeLessThan(checkIdsFor("route").length);

    const report = AgentVerdictReportSchema.parse({
      batchId: batch.id,
      verdicts: batch.units.map((each) => ({
        unitId: each.id,
        checks: Object.fromEntries(obliged.map((id) => [id, "pass"])),
      })),
    });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.verdicts.every((verdict) => verdict.complete)).toBe(true);
    expect(decoded.verdicts[0]?.missingChecks).toEqual([]);
    expect(kinds(decoded.issues)).toEqual([]);
    expect(decoded.verdicts[0]?.checks.map((check) => check.checkId)).toEqual([...obliged]);
  });

  test("a check another domain's prompt asks is permitted, and never demanded here", async () => {
    // Permission is the union, obligation is the batch's own list: an extra
    // answer is data, and it is not what makes the verdict complete.
    const batch = await routeBatch("api");
    const unit = batch.units[0];
    if (unit === undefined) throw new Error("the api batch has no units");
    const extra = checkIdsFor("route", "appsec")[0];
    if (extra === undefined) throw new Error("the appsec route prompt asks nothing");

    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: {
            ...Object.fromEntries(checkIdsFor("route", "api").map((id) => [id, "pass"])),
            [extra]: "pass",
          },
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);

    expect(kinds(decoded.issues)).not.toContain("unknown-check");
    expect(decoded.verdicts[0]?.complete).toBe(true);
    expect(decoded.verdicts[0]?.checks.map((check) => check.checkId)).toContain(extra);
  });

  test("a unit a secondary batch said nothing about is missing from that domain", async () => {
    const batch = await routeBatch("reliability");
    const report = AgentVerdictReportSchema.parse({ batchId: batch.id, verdicts: [] });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.missing).toHaveLength(batch.units.length);
    expect(decoded.missing.every((skip) => skip.domain === "reliability")).toBe(true);
  });

  test("a check the prompt never asked for is dropped and named", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: unit.id, checks: { ...allPass(), "appsec.vibes": "fail" } }],
    });
    const decoded = decodeVerdicts(report, batch);

    expect(decoded.verdicts[0]?.checks.map((check) => check.checkId)).not.toContain("appsec.vibes");
    expect(kinds(decoded.issues)).toContain("unknown-check");
  });

  test("a not-applicable with no reason is flagged, because it reads as neither answer", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: unit.id, checks: { ...allPass(), "appsec.idor": "not-applicable" } }],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(kinds(decoded.issues)).toContain("unexplained-not-applicable");
  });

  test("a finding under a rule the prompt never offered is not data", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const line = await lineOf(FILES.invoices, "export async function GET");
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: allPass(),
          findings: [
            {
              rule: "data.made-this-up",
              title: "t",
              description: "d",
              severity: "high",
              location: { file: FILES.invoices, line },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.findings).toEqual([]);
    expect(kinds(decoded.issues)).toContain("unknown-rule");
  });

  test("a citation outside the slices the batch showed is dropped", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: allPass(),
          findings: [
            {
              rule: "appsec.idor",
              title: "t",
              description: "d",
              severity: "high",
              location: { file: FILES.orders, line: 9_999 },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.findings).toEqual([]);
    expect(kinds(decoded.issues)).toContain("citation-not-shown");
    expect(decoded.issues[0]?.detail).toContain("not in the slices provided");
  });

  test("an evidence pointer outside the slices is dropped, the finding is kept", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const line = await lineOf(FILES.invoices, "const rows = await allInvoices(db)");
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: allPass(),
          findings: [
            {
              rule: "appsec.missing-tenant-scope",
              title: "every invoice is returned",
              description: "d",
              severity: "high",
              location: { file: FILES.invoices, line },
              evidence: [{ file: "src/nowhere.ts", line: 1 }],
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.findings).toHaveLength(1);
    expect(decoded.findings[0]?.evidence).toEqual([]);
    expect(kinds(decoded.issues)).toContain("evidence-not-shown");
  });

  test("a severity above the rule's ceiling is lowered to it", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const line = await lineOf(FILES.invoices, "export async function GET");
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: allPass(),
          findings: [
            {
              rule: "api.error-leaks-internals",
              title: "t",
              description: "d",
              severity: "critical",
              location: { file: FILES.invoices, line },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.findings[0]?.severity).toBe("medium");
    expect(kinds(decoded.issues)).toContain("severity-clamped");
  });

  test("a failed check with no finding behind it is reported", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const report = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: unit.id, checks: { ...allPass(), "appsec.idor": "fail" } }],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(kinds(decoded.issues)).toContain("fail-without-finding");
  });

  test("a reply echoing another batch's id is recorded, not silently filed", async () => {
    const batch = await routeBatch();
    const report = AgentVerdictReportSchema.parse({
      batchId: "route-000000000000",
      verdicts: batch.units.map((unit) => ({ unitId: unit.id, checks: allPass() })),
    });
    const decoded = decodeVerdicts(report, batch);
    expect(kinds(decoded.issues)).toEqual(["batch-id-mismatch"]);
    expect(decoded.verdicts).toHaveLength(batch.units.length);
  });

  test("an over-long field is truncated rather than carried into the report", async () => {
    const batch = await routeBatch();
    const unit = batch.units[0];
    if (unit === undefined) return;
    const line = await lineOf(FILES.invoices, "export async function GET");
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: allPass(),
          findings: [
            {
              rule: "appsec.idor",
              title: "x".repeat(500),
              description: "d",
              severity: "high",
              location: { file: FILES.invoices, line },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    expect(decoded.findings[0]?.title.length).toBe(160);
    expect(kinds(decoded.issues)).toContain("text-clamped");
  });

  test("a passing check keeps the pointer that proves it", async () => {
    const batch = await routeBatch();
    const unit = batch.units.find((candidate) => candidate.id === "route-orders-get");
    if (unit === undefined) return;
    const line = await lineOf(FILES.orders, "listOrders(db, session.orgId)");
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: unit.id,
          checks: {
            ...allPass(),
            "appsec.tenant-isolation": {
              result: "pass",
              evidence: { file: FILES.orders, line, note: "scoped by session.orgId" },
            },
          },
        },
      ],
    });
    const decoded = decodeVerdicts(report, batch);
    const passed = passedChecks(decoded);
    const scoped = passed.find((row) => row.check === "appsec.tenant-isolation");
    expect(scoped?.evidence?.line).toBe(line);

    const asserted = assertedChecksOf(decoded).find(
      (row) => row.checkId === "appsec.tenant-isolation",
    );
    expect(asserted?.domain).toBe("appsec");
    expect(asserted?.statement).toBe("every read is constrained by the authenticated principal");
    expect(asserted?.evidence).toHaveLength(1);
  });
});

describe("readBatchVerdicts", () => {
  test("clean, flagged and inconclusive are decided by what came back", () => {
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        { unitId: "clean", checks: { "appsec.idor": "pass" } },
        {
          unitId: "flagged",
          checks: { "appsec.idor": "fail" },
          findings: [
            {
              rule: "appsec.idor",
              title: "t",
              description: "d",
              severity: "critical",
              location: { file: "a.ts", line: 1 },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
        {
          unitId: "unsure",
          checks: { "appsec.idor": { result: "not-applicable", note: "no code" } },
          notes: "the handler was not provided",
        },
        { unitId: "silent", checks: {} },
      ],
    });
    const read = readBatchVerdicts(report);
    expect(read.verdicts.map((verdict) => verdict.status)).toEqual([
      "clean",
      "flagged",
      "inconclusive",
      "inconclusive",
    ]);
    expect(read.verdicts[2]?.note).toBe("the handler was not provided");
  });

  test("a passing check arrives with the sentence the report will print", () => {
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: "u1",
          checks: {
            "appsec.tenant-isolation": { result: "pass", evidence: { file: "a.ts", line: 4 } },
            "api.mass-assignment": "pass",
            "appsec.idor": "fail",
            "appsec.not-a-check": "pass",
          },
        },
      ],
    });
    const checks = readBatchVerdicts(report).verdicts[0]?.checks ?? [];
    const ids = checks.map((check) => check.id);
    expect(ids).toEqual(["appsec.tenant-isolation", "api.mass-assignment"]);
    expect(checks[0]?.statement).toBe("every read is constrained by the authenticated principal");
    expect(checks[1]?.subject).toBe("mutation handlers");
    expect(checks[0]?.evidence?.[0]?.line).toBe(4);
  });

  test("a finding's domain is its rule's prefix, and its severity respects the rubric", () => {
    const report = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: "u1",
          checks: {},
          findings: [
            {
              rule: "data.select-star",
              title: "t",
              description: "d",
              severity: "critical",
              location: { file: "a.ts", line: 1 },
              impact: "i",
              recommendation: "r",
            },
          ],
        },
      ],
    });
    const finding = readBatchVerdicts(report).verdicts[0]?.findings?.[0];
    expect(finding?.domain).toBe("data");
    expect(finding?.severity).toBe("medium");
  });

  test("the verdict source pairs the schema with its adapter", () => {
    const source = verdictSource();
    expect(source.schema).toBe(AgentVerdictReportSchema);
    expect(source.read({ verdicts: [] }).verdicts).toEqual([]);
  });
});
