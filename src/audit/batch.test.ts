import { describe, expect, test } from "bun:test";
import type { AuditUnitKind } from "../contracts/inventory.ts";
import {
  fs,
  FILES,
  PROFILE,
  SCHEMA,
  TARGET,
  containerUnit,
  dataAccessUnits,
  lineOf,
  roleGateUnit,
  routeUnits,
  unresolvableUnit,
  workflowJobUnits,
} from "./__fixtures__/batch-fixtures.ts";
import {
  type AuditBatch,
  type PlanBatchesInput,
  batchId,
  buildPrompt,
  citedRanges,
  createBatchPlanner,
  planBatches,
  renderSchemaExcerpt,
  sharedFilesFor,
  shownLines,
  stackFactsOf,
  wasShown,
} from "./batch.ts";
import { UNBOUNDED_BUDGET } from "./budget.ts";
import { type PromptPlanEntry, checkIdsFor, primaryDomainOf, promptsFor } from "./prompts/index.ts";

/**
 * The primary lens only: one batch series per kind, as every test below the
 * multi-domain block describes.
 *
 * Those tests are about packing, risk order and the budget, and a kind audited
 * by three prompts produces three series of each. Restricting them to the
 * primary domain keeps each one about the property it names; the series
 * themselves are the subject of `more than one domain over the same units`,
 * which uses the real registry.
 */
function primaryOnly(kind: AuditUnitKind): readonly PromptPlanEntry[] {
  return promptsFor(kind).filter((entry) => entry.domain === primaryDomainOf(kind));
}

/** A plan over the fixture repository, read through the real filesystem port. */
function input(
  units: PlanBatchesInput["units"],
  overrides: Partial<PlanBatchesInput> = {},
): PlanBatchesInput {
  return {
    units,
    slices: { fs, targetDir: TARGET },
    profile: PROFILE,
    prompts: primaryOnly,
    ...overrides,
  };
}

/** Every line number a batch's prompt printed in its gutter. */
function gutterLines(batch: AuditBatch): number[] {
  const numbers: number[] = [];
  for (const line of batch.prompt.split("\n")) {
    const match = /^\s*(\d+) \|/.exec(line);
    if (match?.[1] !== undefined) numbers.push(Number(match[1]));
  }
  return numbers;
}

describe("planBatches", () => {
  test("batches are homogeneous by kind", async () => {
    const units = [...(await routeUnits()), ...(await dataAccessUnits()), await roleGateUnit()];
    const plan = await planBatches(input(units));

    expect(plan.batches.length).toBeGreaterThanOrEqual(3);
    for (const batch of plan.batches) {
      const kinds = new Set(batch.units.map((unit) => unit.kind));
      expect([...kinds]).toEqual([batch.kind]);
    }
    expect(plan.batches.map((batch) => batch.kind).sort()).toEqual([
      "data-access",
      "role-gate",
      "route",
    ]);
  });

  test("the accounted size is the assembled prompt, measured not estimated", async () => {
    const plan = await planBatches(input(await routeUnits()));
    for (const batch of plan.batches) {
      expect(batch.chars).toBe(batch.systemPrompt.length + batch.prompt.length);
      expect(batch.chars).toBeLessThanOrEqual(60_000);
      expect(batch.overBudget).toBe(false);
    }
  });

  test("the character budget splits a kind, not a unit count", async () => {
    const units = await routeUnits();
    const wide = await planBatches(input(units, { budget: { promptChars: 200_000 } }));
    expect(wide.batches).toHaveLength(1);
    expect(wide.batches[0]?.units).toHaveLength(3);

    // A budget that fits the scaffolding and one or two units, count cap left high:
    // what splits this kind is the measured size, not the number of units.
    const narrow = await planBatches(
      input(units, { budget: { promptChars: 14_000, maxUnits: 100, sharedShare: 0 } }),
    );
    expect(narrow.batches.length).toBeGreaterThan(1);
    for (const batch of narrow.batches) {
      expect(batch.chars).toBeLessThanOrEqual(14_000);
      expect(batch.overBudget).toBe(false);
    }
    const planned = narrow.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    expect(planned.sort()).toEqual(units.map((unit) => unit.id).sort());
  });

  test("every unit is in exactly one batch, and none is silently dropped", async () => {
    const units = [...(await routeUnits()), ...(await dataAccessUnits())];
    const plan = await planBatches(
      input(units, { budget: { promptChars: 14_000, sharedShare: 0 } }),
    );
    const planned = plan.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    expect(new Set(planned).size).toBe(planned.length);
    expect(planned.sort()).toEqual(units.map((unit) => unit.id).sort());
    expect(plan.skipped).toEqual([]);
  });

  test("a unit that cannot be made to fit gets its own batch and is disclosed", async () => {
    const units = await routeUnits();
    // Below the scaffolding itself: nothing can fit, and nothing may be dropped.
    const plan = await planBatches(input(units, { budget: { promptChars: 2_000 } }));

    expect(plan.batches).toHaveLength(units.length);
    for (const batch of plan.batches) {
      expect(batch.units).toHaveLength(1);
      expect(batch.overBudget).toBe(true);
      expect(batch.shared).toEqual([]);
      expect(batch.chars).toBe(batch.systemPrompt.length + batch.prompt.length);
    }
    expect(plan.skipped).toEqual([]);
    expect(plan.notes.filter((note) => note.includes("above the")).length).toBe(units.length);
  });

  test("the same inventory produces the same batches with the same ids", async () => {
    const units = await routeUnits();
    const budget = { promptChars: 14_000, sharedShare: 0 };
    const first = await planBatches(input(units, { budget }));
    const second = await planBatches(input([...units].reverse(), { budget }));
    const shape = (plan: { batches: readonly AuditBatch[] }): string[] =>
      plan.batches.map((batch) => `${batch.id}:${batch.units.map((unit) => unit.id).join(",")}`);
    expect(shape(second)).toEqual(shape(first));
    for (const batch of first.batches) expect(batch.prompt.length).toBeGreaterThan(0);
  });

  test("a batch id changes when its units change, and not otherwise", () => {
    expect(batchId("route", ["a", "b"])).toBe(batchId("route", ["a", "b"]));
    expect(batchId("route", ["a", "b"])).not.toBe(batchId("route", ["a", "c"]));
    expect(batchId("route", ["a", "b"])).not.toBe(batchId("data-access", ["a", "b"]));
    expect(batchId("route", ["a"])).toMatch(/^route-[0-9a-f]{12}$/);
  });

  test("the prompt carries source read from disk, with its real line numbers", async () => {
    const plan = await planBatches(input(await routeUnits()));
    const batch = plan.batches.find((candidate) => candidate.kind === "route");
    const deleteLine = await lineOf(FILES.orders, "export async function DELETE");

    expect(batch?.prompt).toContain(`// ${FILES.orders}:`);
    expect(batch?.prompt).toContain("delete from orders where id = $1");
    expect(gutterLines(batch as AuditBatch)).toContain(deleteLine);
    // The unit ids the verdict must answer for are listed verbatim.
    for (const unit of batch?.units ?? []) expect(batch?.prompt).toContain(unit.id);
  });

  test("a unit whose citation does not resolve is skipped with a reason, never dropped", async () => {
    const units = [...(await routeUnits()), unresolvableUnit()];
    const plan = await planBatches(input(units));
    const planned = plan.batches.flatMap((batch) => batch.units.map((unit) => unit.id));

    expect(planned).not.toContain("route-ghost");
    expect(plan.skipped).toHaveLength(1);
    expect(plan.skipped[0]?.unitId).toBe("route-ghost");
    expect(plan.skipped[0]?.reason).toContain("source could not be read");
  });

  test("a kind no model audits is reported with the reason it is not audited", async () => {
    const plan = await planBatches(input([await containerUnit()]));
    expect(plan.batches).toEqual([]);
    expect(plan.skipped).toHaveLength(1);
    expect(plan.skipped[0]?.reason).toContain("hadolint");
  });

  test("a kind left out of the run is skipped as excluded, not as unaudited", async () => {
    const units = [...(await routeUnits()), ...(await dataAccessUnits())];
    const plan = await planBatches(input(units, { kinds: ["route"] }));
    expect(plan.batches.every((batch) => batch.kind === "route")).toBe(true);
    expect(plan.skipped.map((skip) => skip.kind)).toEqual(["data-access", "data-access"]);
    expect(plan.skipped[0]?.reason).toContain("excluded");
  });

  test("the shared context quotes the auth helper once for a route batch", async () => {
    const plan = await planBatches(input(await routeUnits()));
    const batch = plan.batches[0];
    const labels = batch?.shared.map((block) => block.label) ?? [];

    expect(labels.some((label) => label.includes("auth helper"))).toBe(true);
    expect(labels.some((label) => label.includes("validation helper"))).toBe(true);
    expect(batch?.prompt).toContain("export function requireSession");
    // Once, not once per unit.
    const occurrences = batch?.prompt.split("export function requireSession").length ?? 0;
    expect(occurrences).toBe(2);
  });

  test("the schema excerpt names the tables the batch touches and nothing else", async () => {
    const plan = await planBatches(input(await dataAccessUnits(), { schema: SCHEMA }));
    const batch = plan.batches[0];
    expect(batch?.prompt).toContain("table orders");
    expect(batch?.prompt).toContain("table invoices");
    expect(batch?.prompt).not.toContain("table customers");
    expect(batch?.prompt).toContain("row level security: ENABLED with 0 policies");
  });

  test("the schema excerpt is skipped when no unit names a table in it", () => {
    expect(renderSchemaExcerpt(SCHEMA, [])).toBeUndefined();
    const excerpt = renderSchemaExcerpt(SCHEMA, [
      {
        id: "x",
        kind: "data-access",
        label: "x",
        location: { file: "a.ts", line: 1 },
        attributes: { table: "nope" },
      },
    ]);
    expect(excerpt).toBeUndefined();
  });

  test("the excerpt's declaration line is citable, so a schema claim can point at the table", async () => {
    // Without this, a finding derived from the excerpt has to anchor itself on
    // whatever line of the migration survived the unit's slice budget, and the
    // report sends the reader to an unrelated statement.
    const excerpt = renderSchemaExcerpt(SCHEMA, [
      {
        id: "x",
        kind: "data-access",
        label: "x",
        location: { file: "a.ts", line: 1 },
        attributes: { table: "orders" },
      },
    ]);
    expect(excerpt?.text).toContain(`declared at: ${FILES.migration}:2`);
    // Exactly the declaration lines of the tables the excerpt describes, and
    // nothing else: this opens one line per table, not the file.
    expect(excerpt?.citable).toEqual([{ file: FILES.migration, line: 2 }]);

    const plan = await planBatches(input(await dataAccessUnits(), { schema: SCHEMA }));
    const batch = plan.batches[0];
    expect(batch).toBeDefined();
    if (batch === undefined) return;
    const declarations =
      batch.shared.find((block) => block.label === "schema excerpt")?.citable ?? [];
    // Sorted by table name, so `invoices` (line 9) comes before `orders` (line 2).
    expect(declarations).toEqual([
      { file: FILES.migration, line: 9 },
      { file: FILES.migration, line: 2 },
    ]);
    // Both gates accept each of them: the coarse extent list the audit phase
    // builds from `slices`, and the exact per-line index the CLI passes as `shown`.
    for (const declaration of declarations) {
      expect(batch.slices).toContainEqual({
        file: declaration.file,
        startLine: declaration.line,
        endLine: declaration.line,
      });
      expect(wasShown(citedRanges(batch), declaration.file, declaration.line)).toBe(true);
    }
  });

  test("shared context is trimmed, never the units, when the budget is tight", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: { promptChars: 9_000, maxUnits: 100 } }),
    );
    const planned = plan.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    expect(planned).toHaveLength(3);
    const trimmed = plan.batches.some((batch) => batch.shared.length === 0);
    expect(trimmed).toBe(true);
    expect(plan.notes.some((note) => note.includes("dropped"))).toBe(true);
  });

  test("a role gate carries the handler behind the endpoint it gates", async () => {
    const units = [...(await routeUnits()), await roleGateUnit()];
    const plan = await planBatches(input(units));
    const gate = plan.batches.find((batch) => batch.kind === "role-gate");
    const related = gate?.entries[0]?.related ?? [];

    expect(related).toHaveLength(1);
    expect(related[0]?.unitId).toBe("route-orders-get");
    expect(related[0]?.label).toContain("handler behind the gated action");
    expect(gate?.prompt).toContain("listOrders(db, session.orgId)");
  });

  test("slices list every range the prompt pasted, shared context included", async () => {
    const plan = await planBatches(input(await routeUnits()));
    const batch = plan.batches[0] as AuditBatch;
    const files = new Set(batch.slices.map((extent) => extent.file));
    expect(files.has(FILES.orders)).toBe(true);
    expect(files.has(FILES.auth)).toBe(true);
    for (const extent of batch.slices) {
      expect(extent.endLine).toBeGreaterThanOrEqual(extent.startLine);
    }
  });
});

describe("more than one domain over the same units", () => {
  test("a route is batched once per registered domain, and the ids differ", async () => {
    // The registry audits a route for access control, for its contract and for
    // its reliability. Three series over the same three units, each carrying the
    // domain its verdicts are counted under — which is what gives D6 and D7 a
    // coverage row at all.
    const plan = await planBatches({
      units: await routeUnits(),
      slices: { fs, targetDir: TARGET },
      profile: PROFILE,
      spend: UNBOUNDED_BUDGET,
    });
    const domains = plan.batches.map((batch) => batch.domain);
    expect([...new Set(domains)].sort()).toEqual(["api", "appsec", "reliability"]);
    expect(plan.gaps).toEqual([]);

    for (const domain of ["appsec", "api", "reliability"] as const) {
      const ofDomain = plan.batches.filter((batch) => batch.domain === domain);
      const ids = ofDomain.flatMap((batch) => batch.units.map((unit) => unit.id));
      // Per domain, every unit exactly once: `audited + skipped === total` is
      // only true per domain if each domain sees the whole population once.
      expect(ids.sort()).toEqual(["route-invoices-get", "route-orders-delete", "route-orders-get"]);
      expect(ofDomain.every((batch) => batch.kind === "route")).toBe(true);
    }

    // Two batches over the same units are two dispatches and two transcripts,
    // so they may not share an id.
    const ids = plan.batches.map((batch) => batch.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.filter((id) => id.startsWith("route-api-")).length).toBeGreaterThan(0);
    expect(ids.filter((id) => id.startsWith("route-reliability-")).length).toBeGreaterThan(0);
    // The primary series keeps the id it had before the domain column existed,
    // so a resumed run still recognises what it already paid for.
    const appsec = plan.batches.filter((batch) => batch.domain === "appsec");
    for (const batch of appsec) {
      expect(batch.id).toBe(
        batchId(
          "route",
          batch.units.map((unit) => unit.id),
        ),
      );
    }
  });

  test("each series asks only its own domain's questions about the same slices", async () => {
    const plan = await planBatches({
      units: await routeUnits(),
      slices: { fs, targetDir: TARGET },
      profile: PROFILE,
      spend: UNBOUNDED_BUDGET,
      budget: { promptChars: 200_000 },
    });
    const of = (domain: string): AuditBatch | undefined =>
      plan.batches.find((batch) => batch.domain === domain);
    const appsec = of("appsec");
    const api = of("api");
    expect(appsec).toBeDefined();
    expect(api).toBeDefined();
    if (appsec === undefined || api === undefined) return;

    for (const id of checkIdsFor("route", "appsec")) expect(appsec.prompt).toContain(`"${id}"`);
    for (const id of checkIdsFor("route", "api")) {
      expect(api.prompt).toContain(`"${id}"`);
      expect(appsec.prompt).not.toContain(`"${id}"`);
    }
    // The question the two prompts share is asked once, by the first row.
    expect(api.prompt).not.toContain('"api.input-validation"');
    // The same lines of the same files, read once from disk and pasted twice.
    expect(api.slices).toEqual(appsec.slices);
  });

  test("a budget defers whole series in risk order, and says so for each", async () => {
    const plan = await planBatches({
      units: await routeUnits(),
      slices: { fs, targetDir: TARGET },
      profile: PROFILE,
      budget: { promptChars: 14_000, maxUnits: 1, sharedShare: 0 },
      spend: { maxBatches: 4 },
    });
    // Nine batches planned (three units × three domains), four dispatched: the
    // units behind the line are named with the cause `budget`, once per domain
    // that has not audited them, and nothing is silently absent.
    expect(plan.bound.batchesPlanned).toBe(9);
    expect(plan.batches).toHaveLength(4);
    expect(plan.skipped.every((skip) => skip.cause === "budget")).toBe(true);
    const batched = plan.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    expect([...batched, ...plan.skipped.map((skip) => skip.unitId)]).toHaveLength(9);

    // The run-level sentence counts units of this repository, not dispatch slots:
    // three routes audited under three lenses are three units, and a bound that
    // said `of 9` would overstate the repository by a factor of three.
    expect(plan.bound.unitsTotal).toBe(3);
    expect(plan.bound.unitsDispatched + plan.bound.unitsDeferred).toBe(3);

    // Every deferred unit names the domain it was deferred for, which is what
    // phase 4 files the skip under — otherwise a domain that audited a third of
    // the routes would report that third as its whole population.
    for (const skip of plan.skipped) expect(skip.domain).toBeDefined();
    const domains = new Set(plan.skipped.map((skip) => skip.domain));
    expect([...domains].sort()).toEqual(["api", "appsec", "reliability"]);
    // A secondary domain's deferral says so in the reason as well, so the CLI's
    // grouped count cannot be read as units left unaudited altogether.
    const secondary = plan.skipped.filter((skip) => skip.domain === "api");
    expect(secondary.every((skip) => skip.reason.endsWith("deferred for the api domain"))).toBe(
      true,
    );
    // And the plan states the shortfall per domain in one line each.
    const perDomain = plan.notes.filter((note) => /^route\/(api|appsec|reliability): /.test(note));
    expect(perDomain).toHaveLength(3);
    expect(perDomain.some((note) => note.includes("route handlers were not dispatched"))).toBe(
      true,
    );
  });

  test("a domain the scope turned off is not planned, and says which it was", async () => {
    // Phase 4 filters by the enabled domains too, so this is not what makes an
    // out-of-scope domain safe — it is what stops a batch ceiling from being
    // spent on a series that will be thrown away.
    const plan = await planBatches({
      units: [...(await routeUnits()), ...(await workflowJobUnits())],
      slices: { fs, targetDir: TARGET },
      profile: PROFILE,
      domains: ["appsec"],
      spend: UNBOUNDED_BUDGET,
    });
    expect(new Set(plan.batches.map((batch) => batch.domain))).toEqual(new Set(["appsec"]));
    // The CI jobs are only audited under `delivery`, which is off: they are
    // reported as out of scope, not as a kind nobody wrote a prompt for.
    const jobs = plan.skipped.filter((skip) => skip.kind === "workflow-job");
    expect(jobs).toHaveLength(2);
    expect(jobs[0]?.reason).toBe(
      "every domain that audits this kind is outside this run's scope: delivery",
    );
  });

  test("a unit that reached no batch is missing from every domain that owed it", async () => {
    // Its source cannot be read, so no lens can audit it. One skip entry per
    // domain, because a single entry would leave the contract and reliability
    // tables counting it out of their own totals — and the run-level sentence
    // still counts it once, because it is one unit.
    const plan = await planBatches({
      units: [...(await routeUnits()), unresolvableUnit()],
      slices: { fs, targetDir: TARGET },
      profile: PROFILE,
      spend: UNBOUNDED_BUDGET,
    });
    const ghost = plan.skipped.filter((skip) => skip.unitId === "route-ghost");
    expect(ghost.map((skip) => skip.domain)).toEqual(["appsec", "api", "reliability"]);
    for (const skip of ghost) {
      expect(skip.cause).toBe("no-batch");
      expect(skip.reason).toContain("source could not be read");
    }
    expect(plan.bound.unitsTotal).toBe(4);
    expect(plan.bound.unitsAudited).toBe(3);
  });
});

describe("CI workflow jobs", () => {
  test("every job is batched under delivery, which is what phase 1 could not audit", async () => {
    // Before this kind had a prompt these were enumerated and never batched, so the
    // delivery domain counted only its analyzer steps as checks that ran.
    const plan = await planBatches(input(await workflowJobUnits()));
    expect(plan.batches).toHaveLength(1);
    const batch = plan.batches[0] as AuditBatch;
    expect(batch.kind).toBe("workflow-job");
    expect(batch.domain).toBe("delivery");
    // Both jobs score the same base risk, so the order between them is the
    // ranker's tie-break; what this asserts is that neither is left out.
    expect([...batch.units.map((unit) => unit.id)].sort()).toEqual([
      "job-list-changed-files",
      "job-slack-status-start",
    ]);
    expect(plan.skipped).toEqual([]);
  });

  test("the job's YAML is pasted with its real line numbers", async () => {
    const plan = await planBatches(input(await workflowJobUnits()));
    const batch = plan.batches[0] as AuditBatch;
    const checkout = await lineOf(FILES.workflow, "ref: ${{ github.event.workflow_run.head_sha");
    const localAction = await lineOf(FILES.workflow, "uses: ./.github/actions/list-changed-files");

    expect(batch.prompt).toContain(`// ${FILES.workflow}:`);
    expect(gutterLines(batch)).toContain(checkout);
    // The distinction the whole prompt exists for: the checkout of the
    // contributor's ref and the step that runs code out of it are both on the
    // page, and both are citable.
    expect(wasShown(citedRanges(batch), FILES.workflow, checkout)).toBe(true);
    expect(wasShown(citedRanges(batch), FILES.workflow, localAction)).toBe(true);
  });

  test("the workflow header is shared context, so the trigger can be read and cited", async () => {
    const plan = await planBatches(input(await workflowJobUnits()));
    const batch = plan.batches[0] as AuditBatch;
    const header = batch.shared.find((block) => block.label.startsWith("workflow header"));
    const trigger = await lineOf(FILES.workflow, "workflow_run:");
    const role = await lineOf(FILES.workflow, 'AWS_ROLE: "ExampleDeployRole"');

    expect(header).toBeDefined();
    expect(header?.label).toContain(FILES.workflow);
    // The filters and the blast radius: `branches` is what decides how hard the
    // trigger is to reach, and the workflow's `env` is where the role it can
    // assume is written down.
    expect(header?.text).toContain("branches: ['develop']");
    expect(header?.text).toContain("ExampleDeployRole");
    // Once for the batch, not once per job.
    expect(batch.prompt.split("workflow_run:").length).toBe(2);
    for (const line of [trigger, role]) {
      expect(wasShown(citedRanges(batch), FILES.workflow, line)).toBe(true);
    }
  });

  test("the prompt states the facts phase 2 proved about each job", async () => {
    const plan = await planBatches(input(await workflowJobUnits()));
    const batch = plan.batches[0] as AuditBatch;
    expect(batch.prompt).toContain("triggers: workflow_dispatch,workflow_run");
    expect(batch.prompt).toContain("permissions: contents:read,id-token:write");
    expect(batch.prompt).toContain("usesSecrets: SLACK_URL");
    expect(batch.prompt).toContain("selfHosted: no");
    // And how to read them, so `permissions` inherited from the workflow is not
    // read as the job's own declaration.
    expect(batch.prompt).toContain("or the workflow-wide block when the job declares none");
  });
});

describe("risk ordering", () => {
  /** A budget that gives each route unit a batch of its own, so order is visible. */
  const perUnit = { promptChars: 14_000, maxUnits: 1, sharedShare: 0 };

  test("packs a kind highest-risk first, not by file and line", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: UNBOUNDED_BUDGET }),
    );
    // `GET /api/invoices` is unauthenticated with no check and no validation;
    // `DELETE /api/orders/[id]` is guarded but mutates and takes an id;
    // `GET /api/orders` is a guarded read. Enumeration order would have put the
    // invoices file first only by accident of the alphabet — this is the order
    // the scores put them in, and the scores say why.
    expect(plan.batches.map((batch) => batch.units[0]?.id)).toEqual([
      "route-invoices-get",
      "route-orders-delete",
      "route-orders-get",
    ]);
    const first = plan.batches[0]?.entries[0];
    expect(first?.risk.reasons).toContain("reachable without authentication");
    expect(first?.risk.reasons).toContain("no schema validation at the request boundary");
  });

  test("a batch's risk is the mean of its units, and batches are dispatched by it", async () => {
    const plan = await planBatches(
      input([...(await routeUnits()), ...(await dataAccessUnits())], {
        spend: UNBOUNDED_BUDGET,
      }),
    );
    const risks = plan.batches.map((batch) => batch.risk);
    expect(risks).toEqual([...risks].sort((left, right) => right - left));
    for (const batch of plan.batches) {
      const mean =
        batch.entries.reduce((sum, entry) => sum + entry.risk.score, 0) / batch.entries.length;
      expect(batch.risk).toBeCloseTo(mean, 1);
    }
    // The route batch outranks the query batch: blast radius, not likelihood.
    expect(plan.batches[0]?.kind).toBe("route");
  });

  test("the order is total, so two runs queue the same batches in the same places", async () => {
    const units = [...(await routeUnits()), ...(await dataAccessUnits())];
    const shape = (plan: { batches: readonly AuditBatch[] }): string[] =>
      plan.batches.map((batch) => `${batch.id}@${batch.risk}`);
    const first = await planBatches(input(units, { spend: UNBOUNDED_BUDGET }));
    const second = await planBatches(input([...units].reverse(), { spend: UNBOUNDED_BUDGET }));
    expect(shape(second)).toEqual(shape(first));
  });
});

describe("the run budget", () => {
  const perUnit = { promptChars: 14_000, maxUnits: 1, sharedShare: 0 };

  test("an unbounded run plans every batch and says it reached no budget", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: UNBOUNDED_BUDGET }),
    );
    expect(plan.batches).toHaveLength(3);
    expect(plan.bound.stop).toBe("complete");
    expect(plan.bound.unitsDeferred).toBe(0);
    expect(plan.bound.statement).toBe("all 3 units were audited; the run reached no budget");
  });

  test("a batch budget dispatches the highest-risk batches and defers the rest", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: { maxBatches: 1 } }),
    );
    expect(plan.batches).toHaveLength(1);
    expect(plan.batches[0]?.units[0]?.id).toBe("route-invoices-get");
    expect(plan.bound.stop).toBe("batch-budget");
    expect(plan.bound.batchesPlanned).toBe(3);
    expect(plan.bound.batchesDispatched).toBe(1);
    expect(plan.bound.batchesDeferred).toBe(2);
  });

  test("nothing the budget held back is lost: every unit is batched or named", async () => {
    const units = [...(await routeUnits()), ...(await dataAccessUnits())];
    const plan = await planBatches(input(units, { budget: perUnit, spend: { maxBatches: 2 } }));
    const batched = plan.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    const named = plan.skipped.map((skip) => skip.unitId);
    expect([...batched, ...named].sort()).toEqual(units.map((unit) => unit.id).sort());
    expect(plan.bound.unitsTotal).toBe(units.length);
  });

  test("a deferred unit carries the cause `budget`, never `no-batch`", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: { maxBatches: 1 } }),
    );
    const deferred = plan.skipped.filter((skip) => skip.cause === "budget");
    expect(deferred).toHaveLength(2);
    // The reason each unit carries is the run's own disclosure sentence, so the
    // CLI's existing "N units were not batched" grouping prints it with a count.
    for (const skip of deferred) expect(skip.reason).toBe(plan.bound.statement);
    expect(plan.bound.statement).toStartWith("2 of 3 units were not audited: ");
    expect(plan.bound.statement).toContain("batch budget of 1 batch");
    expect(plan.notes).toContain(plan.bound.statement);
  });

  test("a unit ceiling is honoured at a batch boundary and named as such", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: { maxBatches: null, maxUnits: 2 } }),
    );
    expect(plan.batches).toHaveLength(2);
    expect(plan.bound.stop).toBe("unit-budget");
    expect(plan.bound.unitsDeferred).toBe(1);
  });

  test("a unit that no model audits is still `no-batch`, not a budget casualty", async () => {
    const plan = await planBatches(
      input([...(await routeUnits()), await containerUnit()], { spend: { maxBatches: 1 } }),
    );
    const container = plan.skipped.find((skip) => skip.unitId === "container-migration-sql");
    expect(container?.cause).toBe("no-batch");
    expect(container?.reason).toContain("hadolint");
  });

  test("the plan's reasons name what put the dispatched units at the front", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: perUnit, spend: { maxBatches: 1 } }),
    );
    expect(plan.bound.reasons).toContain("reachable without authentication");
    expect(plan.bound.ordering).toContain("ordered by exposure and blast radius");
  });
});

describe("resuming a budgeted plan", () => {
  test("excluded units are neither re-batched nor reported as deferred", async () => {
    const units = await routeUnits();
    const first = await planBatches(
      input(units, {
        budget: { promptChars: 14_000, maxUnits: 1, sharedShare: 0 },
        spend: { maxBatches: 1 },
      }),
    );
    const audited = first.batches.flatMap((batch) => batch.units.map((unit) => unit.id));
    expect(audited).toEqual(["route-invoices-get"]);

    const second = await planBatches(
      input(units, {
        budget: { promptChars: 14_000, maxUnits: 1, sharedShare: 0 },
        spend: { maxBatches: 1 },
        exclude: audited,
      }),
    );
    // The next-highest-risk unit, not the one already paid for.
    expect(second.batches.flatMap((batch) => batch.units.map((unit) => unit.id))).toEqual([
      "route-orders-delete",
    ]);
    expect(second.skipped.map((skip) => skip.unitId)).toEqual(["route-orders-get"]);
    // The carried-over unit counts as audited, and against the same total: the
    // sentence a reader checks is about the repository, not about one attempt.
    expect(second.bound.unitsCarriedOver).toBe(1);
    expect(second.bound.unitsTotal).toBe(3);
    expect(second.bound.unitsAudited).toBe(2);
    expect(second.bound.statement).toStartWith("1 of 3 units were not audited: ");
  });

  test("a related unit is still quoted after its own verdict was carried over", async () => {
    // The role gate's target route was audited by the first attempt, so it is
    // excluded — but the gate cannot be judged without the handler's source.
    const units = [...(await routeUnits()), await roleGateUnit()];
    const plan = await planBatches(
      input(units, { spend: UNBOUNDED_BUDGET, exclude: ["route-orders-get"] }),
    );
    const gate = plan.batches.find((batch) => batch.kind === "role-gate");
    expect(gate?.entries[0]?.related.map((slice) => slice.unitId)).toEqual(["route-orders-get"]);
  });

  test("an excluded id that no longer exists changes nothing", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { spend: UNBOUNDED_BUDGET, exclude: ["route-from-another-repo"] }),
    );
    expect(plan.bound.unitsCarriedOver).toBe(0);
    expect(plan.bound.unitsTotal).toBe(3);
  });
});

describe("a handler declared in another file", () => {
  /** A route unit whose registration line is not where its handler lives. */
  async function delegatingRoute(handlerSource: string): Promise<PlanBatchesInput["units"]> {
    const [first, ...rest] = await routeUnits();
    if (first === undefined) throw new Error("the fixture has no route units");
    return [
      { ...first, attributes: { ...first.attributes, handlerSymbol: "listOrders", handlerSource } },
      ...rest,
    ];
  }

  test("the handler's body is attached to the unit and its lines are citable", async () => {
    const start = await lineOf(FILES.queries, "export async function listOrders");
    const plan = await planBatches(
      input(await delegatingRoute(`${FILES.queries}:${start}-${start + 2}`)),
    );
    const batch = plan.batches.find((one) => one.kind === "route") as AuditBatch;
    const entry = batch.entries.find((one) => one.unit.attributes.handlerSource !== undefined);

    expect(entry?.related.map((one) => one.label)).toEqual([
      "the handler this route registers: listOrders",
    ]);
    expect(entry?.related[0]?.slice.file).toBe(FILES.queries);
    expect(batch.prompt).toContain("where org_id = $1");
    // A finding that cites the handler must survive the slice gate; before the
    // body was attached, the same citation was discarded as "not shown".
    expect(wasShown(citedRanges(batch), FILES.queries, start + 1)).toBe(true);
  });

  test("a handler already inside the unit's own slice is not pasted twice", async () => {
    // The first route unit is the invoices GET, so its own slice already holds it.
    const declaration = await lineOf(FILES.invoices, "export async function GET");
    const plan = await planBatches(
      await delegatingRoute(`${FILES.invoices}:${declaration}-${declaration + 1}`).then((units) =>
        input(units),
      ),
    );
    const batch = plan.batches.find((one) => one.kind === "route") as AuditBatch;
    const entry = batch.entries.find((one) => one.unit.attributes.handlerSource !== undefined);
    expect(entry?.related).toEqual([]);
  });

  test("a handlerSource that names no such file loses the attachment, not the unit", async () => {
    const plan = await planBatches(input(await delegatingRoute("src/api/ghost.ts:1-4")));
    const batch = plan.batches.find((one) => one.kind === "route") as AuditBatch;
    const entry = batch.entries.find((one) => one.unit.attributes.handlerSource !== undefined);
    expect(entry).toBeDefined();
    expect(entry?.related).toEqual([]);
  });
});

describe("citedRanges", () => {
  test("admits the lines the prompt printed and refuses the rest", async () => {
    const plan = await planBatches(input(await routeUnits()));
    const batch = plan.batches[0] as AuditBatch;
    const ranges = citedRanges(batch);
    const deleteLine = await lineOf(FILES.orders, "export async function DELETE");

    expect(wasShown(ranges, FILES.orders, deleteLine)).toBe(true);
    expect(wasShown(ranges, FILES.orders, 10_000)).toBe(false);
    expect(wasShown(ranges, "src/api/ghost.ts", 1)).toBe(false);
  });

  test("shown lines come from the gutter, so an elided line is not admitted", async () => {
    const plan = await planBatches(
      input(await routeUnits(), { budget: { slice: { maxLines: 5 } } }),
    );
    const batch = plan.batches[0] as AuditBatch;
    const truncated = batch.entries.find((entry) => entry.slice.truncated);
    expect(truncated).toBeDefined();
    if (truncated === undefined) return;

    const shown = new Set(shownLines(truncated.slice));
    const ranges = citedRanges(batch);
    let elided: number | undefined;
    for (let line = truncated.slice.startLine; line <= truncated.slice.endLine; line += 1) {
      if (!shown.has(line)) elided = line;
    }
    expect(elided).toBeDefined();
    expect(wasShown(ranges, truncated.slice.file, elided ?? 0)).toBe(false);
  });
});

describe("stackFactsOf", () => {
  test("states what phase 0 proved", () => {
    const stack = stackFactsOf(PROFILE);
    expect(stack.frameworks).toEqual(["next"]);
    expect(stack.dataLayers).toEqual(["pg"]);
    expect(stack.databases).toEqual(["postgresql"]);
    expect(stack.authHelpers).toEqual([FILES.auth]);
    expect(stack.hasFrontend).toBe(true);
    expect(stack.validatesConfig).toBe(true);
  });

  test("says so, out loud, when there is no profile", () => {
    const stack = stackFactsOf(undefined);
    expect(stack.frameworks).toEqual([]);
    expect(stack.notes.join(" ")).toContain("stack detection did not run");
  });
});

describe("sharedFilesFor", () => {
  test("gives each kind the context its questions need", () => {
    expect(sharedFilesFor("route", PROFILE).map((request) => request.file)).toEqual([
      FILES.auth,
      FILES.validate,
    ]);
    expect(sharedFilesFor("data-access", PROFILE).map((request) => request.file)).toEqual([
      FILES.migration,
    ]);
    expect(sharedFilesFor("route", undefined)).toEqual([]);
  });
});

describe("buildPrompt and the planner seam", () => {
  test("the planner returns batches and keeps the rest of the plan", async () => {
    const planner = createBatchPlanner({ schema: SCHEMA });
    const batches = await planner(await dataAccessUnits(), {
      fs,
      targetDir: TARGET,
      profile: PROFILE,
    });
    // Two series over the same two call sites, because the registry audits a
    // data-access unit for its data layer and for its reliability. The seam
    // carries both to phase 4, which counts each under its own domain.
    expect(batches.map((batch) => batch.domain)).toEqual(["data", "reliability"]);
    expect(planner.plan()?.skipped).toEqual([]);
    expect(planner.plan()?.gaps).toEqual([]);
    expect(planner.plan()?.stack.dataLayers).toEqual(["pg"]);
  });

  test("the planner carries the budget through and exposes the bound phase 4 reads", async () => {
    // This is the seam `runAudit` reads to classify a deferred unit as `budget`
    // rather than `no-batch`, and the one the CLI reads to print one sentence.
    const planner = createBatchPlanner({
      budget: { promptChars: 14_000, maxUnits: 1, sharedShare: 0 },
      spend: { maxBatches: 1 },
      prompts: primaryOnly,
    });
    const batches = await planner(await routeUnits(), {
      fs,
      targetDir: TARGET,
      profile: PROFILE,
    });
    expect(batches).toHaveLength(1);
    const plan = planner.plan();
    expect(plan?.bound.stop).toBe("batch-budget");
    expect(plan?.bound.batchesDeferred).toBe(2);
    expect(plan?.skipped.every((skip) => skip.cause === "budget")).toBe(true);
  });

  test("an excluded set reaches the planner, so a resume can be wired in one line", async () => {
    const planner = createBatchPlanner({
      spend: UNBOUNDED_BUDGET,
      exclude: ["route-invoices-get"],
      prompts: primaryOnly,
    });
    const batches = await planner(await routeUnits(), {
      fs,
      targetDir: TARGET,
      profile: PROFILE,
    });
    expect(batches.flatMap((batch) => batch.units.map((unit) => unit.id)).sort()).toEqual([
      "route-orders-delete",
      "route-orders-get",
    ]);
    expect(planner.plan()?.bound.unitsCarriedOver).toBe(1);
  });

  test("buildPrompt hands back the bytes that were budgeted", async () => {
    const plan = await planBatches(input(await routeUnits()));
    const batch = plan.batches[0] as AuditBatch;
    const prompt = buildPrompt(batch);
    expect(prompt.system).toBe(batch.systemPrompt);
    expect(prompt.user).toBe(batch.prompt);
    expect(prompt.system.length + prompt.user.length).toBe(batch.chars);
  });

  test("buildPrompt refuses a batch that did not come from the planner", () => {
    expect(() => buildPrompt({ id: "foreign" })).toThrow(/carries no assembled prompt/);
  });
});
