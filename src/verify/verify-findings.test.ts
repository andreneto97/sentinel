import { describe, expect, test } from "bun:test";
import type { CodeRef, Finding } from "../contracts/findings.ts";
import { MemoryFileSystem } from "./_memory-file-system.ts";
import type { VerifyContext } from "./context.ts";
import { verifyFinding, verifyFindings } from "./verify-findings.ts";

const ORDERS = [
  'import { db } from "../db.ts";',
  "",
  "export async function listOrders(req, res) {",
  "  const rows = await db.order.findMany();",
  "  res.json(rows);",
  "}",
];

function context(): VerifyContext {
  return {
    fs: new MemoryFileSystem({
      files: {
        "/repo/src/api/orders.ts": `${ORDERS.join("\n")}\n`,
        "/repo/src/db.ts": "export const db = createClient();\n",
        "/etc/passwd": "root:x:0:0\n",
      },
    }),
    targetDir: "/repo",
    contextLines: 0,
  };
}

function finding(overrides: Partial<Finding> & { readonly location: CodeRef }): Finding {
  return {
    id: "appsec.idor:src/api/orders.ts",
    domain: "appsec",
    rule: "appsec.tenant-isolation",
    severity: "high",
    confidence: "medium",
    title: "Orders are listed without a tenant predicate",
    description: "findMany runs with no ownership filter.",
    evidence: [],
    impact: "Any authenticated user reads every tenant's orders.",
    recommendation: "Filter by the authenticated principal.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

describe("verifyFinding", () => {
  test("replaces the model's snippet with the one on disk", async () => {
    const result = await verifyFinding(
      finding({
        location: { file: "src/api/orders.ts", line: 4, snippet: "// trust me, this is the code" },
      }),
      context(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.finding.location.snippet).toBe("> 4 | const rows = await db.order.findMany();");
    expect(result.finding.title).toBe("Orders are listed without a tenant predicate");
  });

  test("drops evidence that does not resolve and keeps the rest", async () => {
    const result = await verifyFinding(
      finding({
        location: { file: "src/api/orders.ts", line: 4 },
        evidence: [
          { file: "src/db.ts", line: 1 },
          { file: "../../etc/passwd", line: 1 },
          { file: "src/api/orders.ts", line: 4000 },
        ],
      }),
      context(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.droppedEvidence).toBe(2);
    expect(result.finding.evidence).toHaveLength(1);
    expect(result.finding.evidence[0]?.snippet).toBe("> 1 | export const db = createClient();");
  });

  test("rejects the whole finding when the primary location does not resolve", async () => {
    const result = await verifyFinding(
      finding({ location: { file: "../../etc/passwd", line: 1 } }),
      context(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("path-escape");
  });

  test("reports relocation of either the location or its evidence", async () => {
    const result = await verifyFinding(
      finding({
        location: { file: "src/api/orders.ts", line: 4 },
        evidence: [{ file: "src/api/orders.ts", line: 1, snippet: "res.json(rows);" }],
      }),
      context(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.relocated).toBe(true);
    expect(result.finding.evidence[0]?.line).toBe(5);
  });
});

describe("verifyFindings", () => {
  test("splits a batch into kept and dropped with counts per reason", async () => {
    const result = await verifyFindings(
      [
        finding({ id: "keep-1", location: { file: "src/api/orders.ts", line: 4 } }),
        finding({ id: "escape", location: { file: "../../etc/passwd", line: 1 } }),
        finding({ id: "missing", location: { file: "src/api/ghost.ts", line: 1 } }),
        finding({ id: "past-eof", location: { file: "src/db.ts", line: 99 } }),
        finding({
          id: "keep-2",
          location: { file: "src/db.ts", line: 1 },
          evidence: [{ file: "src/api/ghost.ts", line: 1 }],
        }),
      ],
      context(),
    );

    expect(result.kept.map((item) => item.id)).toEqual(["keep-1", "keep-2"]);
    expect(result.dropped.map((item) => [item.finding.id, item.reason])).toEqual([
      ["escape", "path-escape"],
      ["missing", "file-not-found"],
      ["past-eof", "line-out-of-range"],
    ]);
    expect(result.droppedFindings).toBe(3);
    expect(result.droppedEvidence).toBe(1);
    expect(result.relocated).toBe(0);
    expect(result.reasons).toEqual({
      "path-escape": 1,
      "file-not-found": 1,
      "line-out-of-range": 1,
      "binary-file": 0,
    });
  });

  test("feeds relocation with a per-finding symbol hint", async () => {
    const result = await verifyFindings(
      [finding({ id: "drifted", location: { file: "src/api/orders.ts", line: 900 } })],
      context(),
      (item) => (item.id === "drifted" ? { symbol: "listOrders" } : undefined),
    );
    expect(result.kept).toHaveLength(1);
    expect(result.relocated).toBe(1);
    expect(result.kept[0]?.location.line).toBe(3);
    expect(result.kept[0]?.location.note).toBe("relocated from line 900");
  });

  test("returns zeroed counters for an empty batch", async () => {
    const result = await verifyFindings([], context());
    expect(result).toEqual({
      kept: [],
      dropped: [],
      droppedFindings: 0,
      droppedEvidence: 0,
      relocated: 0,
      reasons: {
        "file-not-found": 0,
        "line-out-of-range": 0,
        "path-escape": 0,
        "binary-file": 0,
      },
    });
  });
});
