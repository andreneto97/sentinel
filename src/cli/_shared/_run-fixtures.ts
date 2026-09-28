/**
 * An in-memory run directory, for the three verbs that read one.
 *
 * `resume`, `status` and `report` are all functions of what a run directory
 * contains, so their tests are functions of what this file can build: a
 * findings document, a scan report, an inventory, an audit report — each valid
 * against its own schema, each independently omittable, so a test can express
 * "a run that got as far as the inventory" as an argument rather than a fixture
 * on disk.
 */

import { dirname, join } from "node:path";
import type { AuditReport } from "../../audit/artifacts.ts";
import { ASSURANCES_FILE, AUDIT_FILE } from "../../audit/artifacts.ts";
import { unboundedBound } from "../../audit/budget.ts";
import type {
  Assurance,
  Coverage,
  Domain,
  Finding,
  FindingsDocument,
  Severity,
} from "../../contracts/findings.ts";
import { SCHEMA_VERSION } from "../../contracts/findings.ts";
import type { InventoryDocument } from "../../contracts/inventory.ts";
import { INVENTORY_FILE, zeroCounts } from "../../contracts/inventory.ts";
import type { AnalysisScope } from "../../contracts/scope.ts";
import { ANALYSIS_SCOPE_FILE, UNSCOPED_PHASES, buildAnalysisScope } from "../../contracts/scope.ts";
import type { ScanReport } from "../../scan/artifacts.ts";
import { FINDINGS_FILE, SCAN_REPORT_FILE } from "../../scan/artifacts.ts";
import {
  ISSUES_MD_FILE,
  REPORT_MD_FILE,
  REPORT_PDF_FILE,
  SCOPE_PROPOSAL_FILE,
  STACK_PROFILE_FILE,
} from "./run-artifacts.ts";

/** A filesystem that lives in a `Map`; satisfies every port slice the verbs use. */
export class MemoryRunFs {
  readonly files = new Map<string, string | Uint8Array>();
  private readonly dirs = new Set<string>(["/"]);

  async readFile(path: string): Promise<string> {
    const value = this.files.get(path);
    if (value === undefined) throw new Error(`ENOENT: ${path}`);
    return typeof value === "string" ? value : new TextDecoder().decode(value);
  }

  async writeFile(path: string, data: string | Uint8Array): Promise<void> {
    this.files.set(path, data);
    await this.mkdirp(dirname(path));
  }

  async mkdirp(path: string): Promise<void> {
    let current = path;
    while (current !== "/" && current !== "." && current !== "") {
      this.dirs.add(current);
      current = dirname(current);
    }
  }

  async exists(path: string): Promise<boolean> {
    if (this.files.has(path) || this.dirs.has(path)) return true;
    const prefix = `${path}/`;
    for (const known of this.files.keys()) if (known.startsWith(prefix)) return true;
    return false;
  }

  /** Every path written under `dir`, sorted; what a test asserts a verb produced. */
  written(dir: string): string[] {
    return [...this.files.keys()].filter((path) => path.startsWith(`${dir}/`)).sort();
  }
}

/** A findings document with the fields a test cares about and defaults for the rest. */
export function findingsDocument(
  overrides: Partial<FindingsDocument> & { readonly runId?: string } = {},
): FindingsDocument {
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: overrides.runId ?? "20260923T004014-d60d94c9",
    target: overrides.target ?? "/repo",
    findings: overrides.findings ?? [],
    assurances: overrides.assurances ?? [],
    coverage: overrides.coverage ?? [coverageRow("appsec", 4, 4)],
    droppedFindings: overrides.droppedFindings ?? 0,
  };
}

/** One finding; only what the assertion needs has to be passed. */
export function finding(overrides: Partial<Finding> & { readonly id: string }): Finding {
  return {
    id: overrides.id,
    domain: overrides.domain ?? "appsec",
    rule: overrides.rule ?? "appsec.missing-authorization",
    severity: overrides.severity ?? "high",
    confidence: overrides.confidence ?? "high",
    title: overrides.title ?? `Finding ${overrides.id}`,
    description: overrides.description ?? "A handler writes without checking ownership.",
    location: overrides.location ?? { file: "src/api/orders.ts", line: 12, snippet: "  12 | code" },
    evidence: overrides.evidence ?? [],
    impact: overrides.impact ?? "Another tenant's order can be modified.",
    recommendation: overrides.recommendation ?? "Assert ownership before the update.",
    acceptanceCriteria: overrides.acceptanceCriteria ?? ["The handler rejects a foreign id."],
    cwe: overrides.cwe ?? [],
    owasp: overrides.owasp ?? [],
    source: overrides.source ?? { kind: "agent", name: "audit" },
    ...(overrides.exploitability === undefined ? {} : { exploitability: overrides.exploitability }),
  };
}

/** One assurance: a check that ran and passed. */
export function assurance(overrides: Partial<Assurance> & { readonly id: string }): Assurance {
  return {
    id: overrides.id,
    domain: overrides.domain ?? "appsec",
    check: overrides.check ?? "authorization is enforced by the handler itself",
    scope: overrides.scope ?? "4/4 route handlers",
    unitsChecked: overrides.unitsChecked ?? 4,
    evidence: overrides.evidence ?? [],
  };
}

/** One coverage row, with the invariant `audited + skipped === total` preserved. */
export function coverageRow(
  domain: Domain,
  total: number,
  audited: number,
  skipped: readonly { unitId: string; reason: string }[] = [],
): Coverage {
  const missing =
    skipped.length > 0
      ? [...skipped]
      : Array.from({ length: total - audited }, (_, index) => ({
          unitId: `${domain}-skipped-${index}`,
          reason: "inconclusive: the agent declined to decide",
        }));
  return { domain, unitsTotal: total, unitsAudited: total - missing.length, skipped: missing };
}

/** Every failure kind at zero, which is what a clean audit report carries. */
function noFailures(): Record<string, number> {
  return {
    "malformed-output": 0,
    "truncated-output": 0,
    timeout: 0,
    quota: 0,
    transient: 0,
    refusal: 0,
  };
}

/** One batch line of `audit.json`. */
export function batchReport(
  overrides: Partial<AuditReport["batches"][number]> & { readonly batchId: string },
): AuditReport["batches"][number] {
  return {
    batchId: overrides.batchId,
    domain: overrides.domain ?? "appsec",
    kinds: overrides.kinds ?? ["route"],
    units: overrides.units ?? 4,
    status: overrides.status ?? "audited",
    attempts: overrides.attempts ?? 1,
    verdicts: overrides.verdicts ?? 4,
    findings: overrides.findings ?? 1,
    durationMs: overrides.durationMs ?? 1000,
    transcripts: overrides.transcripts ?? [],
    ...(overrides.failure === undefined ? {} : { failure: overrides.failure }),
    ...(overrides.reason === undefined ? {} : { reason: overrides.reason }),
  };
}

/** An audit report; everything not passed is a clean, complete phase 4. */
export function auditReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: overrides.runId ?? "20260923T004014-d60d94c9",
    target: overrides.target ?? "/repo",
    aborted: overrides.aborted ?? false,
    durationMs: overrides.durationMs ?? 1234,
    runtime: overrides.runtime ?? {
      kind: "claude-agent-sdk",
      concurrency: 2,
      maxAttempts: 3,
      timeoutMs: 240000,
      synthetic: false,
    },
    dispatches: overrides.dispatches ?? 1,
    retries: overrides.retries ?? 0,
    failures: overrides.failures ?? noFailures(),
    quotaExhausted: overrides.quotaExhausted ?? false,
    usage: overrides.usage ?? {
      inputTokens: 10,
      outputTokens: 20,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      costUsd: 0.5,
    },
    batches: overrides.batches ?? [batchReport({ batchId: "route-aaaa" })],
    bound: overrides.bound ?? unboundedBound(4, 4),
    units: overrides.units ?? {
      total: 4,
      audited: 4,
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
    coverage: overrides.coverage ?? [coverageRow("appsec", 4, 4)],
    kinds: overrides.kinds ?? [{ kind: "route", unitsTotal: 4, unitsAudited: 4, skipped: [] }],
    findingsKept: overrides.findingsKept ?? 1,
    assurances: overrides.assurances ?? 1,
    dropped: overrides.dropped ?? {
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
  };
}

/** A scan report where every planned step ran. */
export function scanReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: overrides.runId ?? "20260923T004014-d60d94c9",
    target: overrides.target ?? "/repo",
    aborted: overrides.aborted ?? false,
    durationMs: overrides.durationMs ?? 900,
    steps: overrides.steps ?? [
      { step: "trivy", status: "ok", findings: 2, artifacts: [], durationMs: 400 },
    ],
    dropped: overrides.dropped ?? { findings: 0, evidence: 0, byReason: {} },
    relocated: overrides.relocated ?? 0,
    merged: overrides.merged ?? [],
    escalations: overrides.escalations ?? [],
  };
}

/** An inventory with `units` route units and one enumerator that produced them. */
export function inventoryDocument(
  units = 4,
  overrides: Partial<InventoryDocument> = {},
): InventoryDocument {
  const counts = zeroCounts();
  counts.route = units;
  return {
    schemaVersion: SCHEMA_VERSION,
    runId: overrides.runId ?? "20260923T004014-d60d94c9",
    target: overrides.target ?? "/repo",
    units:
      overrides.units ??
      Array.from({ length: units }, (_, index) => ({
        id: `unit-${index}`,
        kind: "route" as const,
        label: `GET /thing/${index}`,
        location: { file: `src/api/thing-${index}.ts`, line: 1 },
        attributes: { method: "GET", path: `/thing/${index}`, authenticated: "yes" },
      })),
    counts: overrides.counts ?? counts,
    enumerators: overrides.enumerators ?? [
      { name: "routes", status: "ok", kinds: ["route"], units },
    ],
    dropped: overrides.dropped ?? [],
  };
}

/** A stack profile with one fact, enough for the phase to read as complete. */
export function stackProfile(target = "/repo"): unknown {
  return {
    schemaVersion: SCHEMA_VERSION,
    target,
    facts: [
      {
        kind: "backend-framework",
        value: "next",
        confidence: "high",
        evidence: [{ file: "package.json", line: 1 }],
      },
    ],
    absences: [],
    warnings: [],
    scan: { filesSeen: 10, filesRead: 8, truncated: false },
  };
}

/** A scope proposal document whose decision enables `domains`. */
export function scopeProposal(
  runId: string,
  target: string,
  domains: readonly Domain[] = ["appsec"],
): unknown {
  return {
    schemaVersion: SCHEMA_VERSION,
    runId,
    target,
    decision: {
      enabledDomains: [...domains],
      accepted: [],
      declined: [],
      untouched: [],
      notApplicable: [],
      unknownSelectors: [],
      blockedOnMissingTool: [],
      estimatedExtraSeconds: 0,
      usesAi: false,
    },
  };
}

/**
 * The `--path` artifact a run left behind, for the verbs that read one.
 *
 * Defaults to the shape a `--path` run has: one deployable analysed, the rest of
 * the workspace counted and left alone, because that is the run whose output must
 * not read like a whole-repository run. The counts are round on purpose — nothing
 * here asserts a particular total, only that in-scope and out-of-scope are told
 * apart.
 */
export function analysisScope(
  overrides: {
    readonly runId?: string;
    readonly target?: string;
    readonly paths?: readonly string[];
    readonly inScope?: number;
    readonly total?: number;
  } = {},
): AnalysisScope {
  const paths = overrides.paths ?? ["apps/api"];
  const total = overrides.total ?? 1000;
  const inScope = overrides.inScope ?? 300;
  return buildAnalysisScope({
    runId: overrides.runId ?? "20260923T004014-d60d94c9",
    target: overrides.target ?? "/repo",
    paths,
    selectors: paths.map((path) => ({ selector: path, kind: "directory" as const, paths: [path] })),
    unmatched: [],
    units: {
      total,
      inScope,
      outOfScope: total - inScope,
      byKind: [
        { kind: "route", inScope, outOfScope: 0 },
        { kind: "migration", inScope: 0, outOfScope: total - inScope },
      ],
    },
    unscopedPhases: paths.length === 0 ? [] : UNSCOPED_PHASES,
    findingsOutside: 0,
  });
}

/** What a run directory should contain; anything omitted is a phase that did not run. */
export interface RunFixture {
  readonly runDir: string;
  readonly findings?: FindingsDocument | undefined;
  readonly audit?: AuditReport | undefined;
  readonly assurances?: readonly Assurance[] | undefined;
  readonly scan?: ScanReport | undefined;
  readonly inventory?: InventoryDocument | undefined;
  readonly profile?: boolean | undefined;
  readonly scope?: readonly Domain[] | undefined;
  /** `--path`: the subtree the run analysed. Omitted means the artifact is absent. */
  readonly analysisScope?: AnalysisScope | undefined;
  /** Rendered report files that already exist. */
  readonly rendered?: readonly string[] | undefined;
  /** Files to write verbatim, for the corrupt-artifact cases. */
  readonly raw?: Readonly<Record<string, string>> | undefined;
}

/** Writes a run directory into a {@link MemoryRunFs}; returns the directory. */
export async function writeRunFixture(fs: MemoryRunFs, fixture: RunFixture): Promise<string> {
  const { runDir } = fixture;
  await fs.mkdirp(runDir);
  const write = async (file: string, value: unknown): Promise<void> => {
    await fs.writeFile(join(runDir, file), `${JSON.stringify(value, null, 2)}\n`);
  };
  const runId = fixture.findings?.runId ?? fixture.audit?.runId ?? "20260923T004014-d60d94c9";
  const target = fixture.findings?.target ?? fixture.audit?.target ?? "/repo";

  if (fixture.findings !== undefined) await write(FINDINGS_FILE, fixture.findings);
  if (fixture.audit !== undefined) await write(AUDIT_FILE, fixture.audit);
  if (fixture.assurances !== undefined) {
    await write(ASSURANCES_FILE, {
      schemaVersion: SCHEMA_VERSION,
      runId,
      target,
      assurances: fixture.assurances,
      coverage: fixture.findings?.coverage ?? [],
    });
  }
  if (fixture.scan !== undefined) await write(SCAN_REPORT_FILE, fixture.scan);
  if (fixture.inventory !== undefined) await write(INVENTORY_FILE, fixture.inventory);
  if (fixture.profile === true) await write(STACK_PROFILE_FILE, stackProfile(target));
  if (fixture.scope !== undefined) {
    await write(SCOPE_PROPOSAL_FILE, scopeProposal(runId, target, fixture.scope));
  }
  if (fixture.analysisScope !== undefined) {
    await write(ANALYSIS_SCOPE_FILE, fixture.analysisScope);
  }
  for (const file of fixture.rendered ?? []) {
    await fs.writeFile(join(runDir, file), "rendered earlier");
  }
  for (const [file, body] of Object.entries(fixture.raw ?? {})) {
    await fs.writeFile(join(runDir, file), body);
  }
  return runDir;
}

/** Every rendered file, for a fixture that stands for a finished run. */
export const RENDERED_ALL: readonly string[] = [REPORT_PDF_FILE, REPORT_MD_FILE, ISSUES_MD_FILE];

/** A run directory with every phase complete; the baseline the tests vary from. */
export async function completeRun(fs: MemoryRunFs, runDir: string): Promise<string> {
  return await writeRunFixture(fs, {
    runDir,
    findings: findingsDocument({
      findings: [finding({ id: "f1" })],
      assurances: [assurance({ id: "a1" })],
    }),
    audit: auditReport(),
    assurances: [assurance({ id: "a1" })],
    scan: scanReport(),
    inventory: inventoryDocument(),
    profile: true,
    scope: ["appsec"],
    rendered: RENDERED_ALL,
  });
}

/** Severity helper for tests that build a findings mix. */
export function findingWith(id: string, severity: Severity, domain: Domain): Finding {
  return finding({ id, severity, domain });
}
