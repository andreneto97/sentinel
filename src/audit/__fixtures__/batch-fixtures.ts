/**
 * The fixture repository the batching and verdict tests run against, and the
 * helpers that describe it.
 *
 * `batch-target/` is real TypeScript on disk, read through the real filesystem
 * port: the point of these tests is that the prompt contains code that was
 * extracted from a file, so a mocked filesystem would test the wrong thing.
 * Line numbers are resolved by searching for a needle rather than written down,
 * so editing the fixture cannot silently make an assertion meaningless.
 */

import { join } from "node:path";
import type { AuditUnit, CodeRef } from "../../contracts/findings.ts";
import { SCHEMA_VERSION } from "../../contracts/findings.ts";
import type { AuditUnitKind } from "../../contracts/inventory.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import type { SchemaSource } from "../batch.ts";

/** Absolute path of the fixture repository. */
export const TARGET = join(import.meta.dir, "batch-target");

/** The files the fixtures cite, by the repo-relative path a slice header prints. */
export const FILES = {
  orders: "src/api/orders.ts",
  invoices: "src/api/invoices.ts",
  auth: "src/lib/auth.ts",
  validate: "src/lib/validate.ts",
  queries: "src/db/queries.ts",
  panel: "src/ui/admin-panel.ts",
  migration: "migrations/0001_init.sql",
  workflow: ".github/workflows/qa-pipeline.yaml",
} as const;

/** The real filesystem port, which is what the slicer is given in production. */
export const fs = createFileSystem();

/** The 1-based line a needle first appears on, so a fixture edit cannot rot a test. */
export async function lineOf(file: string, needle: string): Promise<number> {
  const text = await fs.readFile(join(TARGET, file));
  const lines = text.split("\n");
  const index = lines.findIndex((line) => line.includes(needle));
  if (index === -1) throw new Error(`${needle} is not in ${file}`);
  return index + 1;
}

/** Builds a unit with the attributes its kind's prompt reads. */
export function unit(input: {
  readonly id: string;
  readonly kind: AuditUnitKind;
  readonly label: string;
  readonly file: string;
  readonly line: number;
  readonly endLine?: number;
  readonly attributes?: Readonly<Record<string, string>>;
}): AuditUnit {
  const location: CodeRef = {
    file: input.file,
    line: input.line,
    ...(input.endLine === undefined ? {} : { endLine: input.endLine }),
  };
  return {
    id: input.id,
    kind: input.kind,
    label: input.label,
    location,
    attributes: input.attributes ?? {},
  };
}

/** The three route units of the fixture, in inventory order. */
export async function routeUnits(): Promise<AuditUnit[]> {
  return [
    unit({
      id: "route-invoices-get",
      kind: "route",
      label: "GET /api/invoices",
      file: FILES.invoices,
      line: await lineOf(FILES.invoices, "export async function GET"),
      attributes: {
        method: "GET",
        path: "/api/invoices",
        framework: "next-app-router",
        authenticated: "no",
        authCheck: "none",
        validation: "none",
        mutates: "false",
      },
    }),
    unit({
      id: "route-orders-delete",
      kind: "route",
      label: "DELETE /api/orders/[id]",
      file: FILES.orders,
      line: await lineOf(FILES.orders, "export async function DELETE"),
      attributes: {
        method: "DELETE",
        path: "/api/orders/[id]",
        framework: "next-app-router",
        authenticated: "yes",
        authCheck: "requireSession(request.headers)",
        idParams: "id",
        validation: "none",
        mutates: "true",
      },
    }),
    unit({
      id: "route-orders-get",
      kind: "route",
      label: "GET /api/orders",
      file: FILES.orders,
      line: await lineOf(FILES.orders, "export async function GET"),
      attributes: {
        method: "GET",
        path: "/api/orders",
        framework: "next-app-router",
        authenticated: "yes",
        authCheck: "requireSession(request.headers)",
        validation: "none",
        mutates: "false",
      },
    }),
  ];
}

/** Two data-access units, one scoped and one not, with the tables they touch. */
export async function dataAccessUnits(): Promise<AuditUnit[]> {
  return [
    unit({
      id: "data-list-orders",
      kind: "data-access",
      label: "select orders",
      file: FILES.queries,
      line: await lineOf(FILES.queries, "select id, org_id, total from orders"),
      attributes: {
        orm: "pg",
        operation: "read",
        table: "orders",
        hasWhere: "true",
        whereColumns: "org_id",
        filtersByPrincipal: "true",
        hasLimit: "true",
      },
    }),
    unit({
      id: "data-all-invoices",
      kind: "data-access",
      label: "select invoices",
      file: FILES.queries,
      line: await lineOf(FILES.queries, "select * from invoices"),
      attributes: {
        orm: "pg",
        operation: "read",
        table: "invoices",
        hasWhere: "false",
        filtersByPrincipal: "false",
        hasLimit: "false",
        hasProjection: "false",
      },
    }),
  ];
}

/** A role gate whose endpoint is one of the route units, so the join has something to find. */
export async function roleGateUnit(): Promise<AuditUnit> {
  return unit({
    id: "gate-admin-delete",
    kind: "role-gate",
    label: "role === admin in adminPanel",
    file: FILES.panel,
    line: await lineOf(FILES.panel, 'user.role === "admin"'),
    attributes: {
      expression: 'user.role === "admin"',
      check: "role-compare",
      subject: "user.role",
      path: "/api/orders",
      endpoint: "/api/orders",
      symbol: "adminPanel",
    },
  });
}

/**
 * The two CI jobs of the fixture workflow, with the facts phase 2 records.
 *
 * The attribute names and values are the workflow-job enumerator's own — a job's
 * `permissions` falls back to the workflow-wide block, `triggers` lists the
 * events with their filters stripped — so a prompt that reads them here reads
 * what it will be given on a real repository.
 */
export async function workflowJobUnits(): Promise<AuditUnit[]> {
  const workflow = FILES.workflow;
  const start = await lineOf(workflow, "  slack-status-start:");
  const list = await lineOf(workflow, "  list-changed-files:");
  const end = (await fs.readFile(join(TARGET, workflow))).split("\n").length;
  return [
    unit({
      id: "job-slack-status-start",
      kind: "workflow-job",
      label: "qa-pipeline.yaml#slack-status-start",
      file: workflow,
      line: start,
      endLine: list - 1,
      attributes: {
        job: "slack-status-start",
        workflow: "QA Pipeline",
        triggers: "workflow_dispatch,workflow_run",
        permissions: "contents:read,id-token:write",
        usesSecrets: "SLACK_URL",
        runsOn: "ubuntu-latest",
        selfHosted: "no",
        concurrency: "yes",
        symbol: "job:slack-status-start",
      },
    }),
    unit({
      id: "job-list-changed-files",
      kind: "workflow-job",
      label: "qa-pipeline.yaml#list-changed-files",
      file: workflow,
      line: list,
      endLine: end,
      attributes: {
        job: "list-changed-files",
        workflow: "QA Pipeline",
        triggers: "workflow_dispatch,workflow_run",
        permissions: "contents:read,id-token:write",
        usesSecrets: "none",
        runsOn: "ubuntu-latest",
        selfHosted: "no",
        concurrency: "yes",
        condition:
          "${{ github.event.workflow_run.conclusion == 'success' || github.event_name == 'workflow_dispatch' }}",
        symbol: "job:list-changed-files",
      },
    }),
  ];
}

/** A container unit, which no phase 4 prompt covers. */
export async function containerUnit(): Promise<AuditUnit> {
  return unit({
    id: "container-migration-sql",
    kind: "container",
    label: "Dockerfile stage",
    file: FILES.migration,
    line: await lineOf(FILES.migration, "CREATE TABLE orders"),
  });
}

/** A unit whose citation does not resolve, which must be skipped and reported. */
export function unresolvableUnit(): AuditUnit {
  return unit({
    id: "route-ghost",
    kind: "route",
    label: "GET /api/ghost",
    file: "src/api/ghost.ts",
    line: 12,
    attributes: { method: "GET", path: "/api/ghost" },
  });
}

/** One proven fact, with the single piece of evidence the contract requires. */
function fact(
  kind: StackProfile["facts"][number]["kind"],
  value: string,
  file: string,
): StackProfile["facts"][number] {
  return { kind, value, confidence: "high", evidence: [{ file, line: 1 }] };
}

/** A profile stating what the fixture repository is, as phase 0 would prove it. */
export const PROFILE: StackProfile = {
  schemaVersion: SCHEMA_VERSION,
  target: TARGET,
  facts: [
    fact("backend-framework", "next", "src/api/orders.ts"),
    fact("next-router", "app", "src/api/orders.ts"),
    fact("data-layer", "pg", "src/db/queries.ts"),
    fact("database-engine", "postgresql", "src/db/queries.ts"),
    fact("auth-provider", "custom-session", FILES.auth),
    fact("auth-helper", FILES.auth, FILES.auth),
    fact("frontend", "react", FILES.panel),
    fact("config-validation", "readEnv", FILES.validate),
    fact("db-schema-file", "migrations", FILES.migration),
  ],
  absences: [],
  warnings: [],
  scan: { filesSeen: 7, filesRead: 7, truncated: false },
};

/** The reconstructed schema of the fixture, as phase 2 would leave it. */
export const SCHEMA: SchemaSource = {
  dialect: "postgresql",
  tables: [
    {
      name: "orders",
      columns: [
        { name: "id", type: "uuid", nullable: false, isPrimaryKey: true, isUnique: true },
        { name: "org_id", type: "uuid", nullable: false, isPrimaryKey: false, isUnique: false },
        {
          name: "customer_id",
          type: "uuid",
          nullable: false,
          isPrimaryKey: false,
          isUnique: false,
          references: { table: "customers", column: "id" },
        },
      ],
      indexes: [{ name: "orders_org_id_idx", columns: ["org_id"], unique: false }],
      foreignKeys: [
        { columns: ["customer_id"], referencesTable: "customers", referencesColumns: ["id"] },
      ],
      uniqueConstraints: [],
      rlsEnabled: false,
      policies: [],
      evidence: [{ file: FILES.migration, line: 2 }],
    },
    {
      name: "invoices",
      columns: [
        { name: "id", type: "uuid", nullable: false, isPrimaryKey: true, isUnique: true },
        { name: "number", type: "text", nullable: false, isPrimaryKey: false, isUnique: false },
      ],
      indexes: [],
      foreignKeys: [],
      uniqueConstraints: [],
      rlsEnabled: true,
      policies: [],
      evidence: [{ file: FILES.migration, line: 9 }],
    },
    {
      name: "customers",
      columns: [],
      indexes: [],
      foreignKeys: [],
      uniqueConstraints: [],
      rlsEnabled: false,
      policies: [],
      evidence: [],
    },
  ],
};
