import { describe, expect, test } from "bun:test";
import { DomainSchema, SeveritySchema } from "../../contracts/findings.ts";
import type { AuditUnit, Domain } from "../../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../../contracts/inventory.ts";
import { DOMAIN_BY_UNIT_KIND } from "../coverage.ts";
import { API_DOMAIN, apiPromptBuilder } from "./api.ts";
import {
  AUDITED_KINDS,
  type AuditCheck,
  CHECK_INDEX,
  PROMPT_GAPS,
  PROMPT_REGISTRY,
  type PromptContext,
  type PromptRegistration,
  type PromptUnit,
  ROUTE_PROMPT,
  RULE_CEILINGS,
  UNKNOWN_STACK,
  assemblePrompt,
  ceilingFor,
  ceilingOfRule,
  checkById,
  checkIdOf,
  checkIdsFor,
  checksFor,
  createPromptBuilder,
  domainsFor,
  gapsFor,
  isAuditedKind,
  primaryDomainOf,
  promptChars,
  promptFor,
  renderChecks,
  renderStack,
  resolveRegistry,
  rulesFor,
  unauditedReason,
} from "./index.ts";
import {
  RELIABILITY_KINDS,
  RELIABILITY_OUT_OF_SCOPE,
  reliabilityPromptFor,
} from "./reliability.ts";
import { routePromptBuilder } from "./routes.ts";

/** Contract order for unit kinds, so a registration list can be compared to one. */
function byKindOrder(left: AuditUnitKind, right: AuditUnitKind): number {
  return AUDIT_UNIT_KINDS.indexOf(left) - AUDIT_UNIT_KINDS.indexOf(right);
}

/** The declared row for a pair, whose builder is the module's own, unprojected. */
function rowFor(kind: AuditUnitKind, domain: Domain): PromptRegistration | undefined {
  return PROMPT_REGISTRY.find((row) => row.kind === kind && row.domain === domain);
}

/** Every check of every audited kind, with the kind that asked it. */
function everyCheck(): { kind: AuditUnitKind; check: AuditCheck }[] {
  return AUDITED_KINDS.flatMap((kind) => checksFor(kind).map((check) => ({ kind, check })));
}

/** A unit that is only as real as a prompt-rendering test needs. */
function unit(id: string, kind: AuditUnitKind): PromptUnit {
  const value: AuditUnit = {
    id,
    kind,
    label: `${kind} ${id}`,
    location: { file: "src/api/orders.ts", line: 10, endLine: 20 },
    attributes: { method: "GET", path: "/api/orders" },
  };
  return { unit: value, sliceText: "// src/api/orders.ts:10-20\n10 | const x = 1;", related: [] };
}

describe("the registry", () => {
  test("every audited kind has a prompt, and every other kind says why it has none", () => {
    for (const kind of AUDIT_UNIT_KINDS) {
      if (AUDITED_KINDS.includes(kind)) {
        expect(promptFor(kind)?.kind).toBe(kind);
        expect(isAuditedKind(kind)).toBe(true);
        continue;
      }
      expect(promptFor(kind)).toBeUndefined();
      expect(unauditedReason(kind).length).toBeGreaterThan(20);
    }
  });

  test("the container is the only kind no model audits", () => {
    const unaudited = AUDIT_UNIT_KINDS.filter((kind) => !isAuditedKind(kind));
    expect(unaudited).toEqual(["container"]);
    expect(unauditedReason("container")).toContain("phase 1");
  });

  test("a CI workflow job is audited by a model, not only by actionlint", () => {
    // These used to be enumerated and never batched: the delivery domain counted
    // only its analyzer steps because the jobs were a unit kind no prompt claimed.
    // This is the assertion that says they are claimed now.
    expect(isAuditedKind("workflow-job")).toBe(true);
    expect(promptFor("workflow-job")?.kind).toBe("workflow-job");
    expect(promptFor("workflow-job", "delivery")?.spec.noun).toBe("CI workflow job");
    expect(rulesFor("workflow-job")).toContain("delivery.ci.untrusted-code-executed");
  });

  test("a kind's prompt carries at least three checks and a mission", () => {
    for (const kind of AUDITED_KINDS) {
      const spec = promptFor(kind)?.spec;
      expect(spec?.checks.length ?? 0).toBeGreaterThanOrEqual(3);
      expect(spec?.mission.length ?? 0).toBeGreaterThan(40);
      expect(spec?.noun.length ?? 0).toBeGreaterThan(3);
    }
  });
});

describe("the check vocabulary", () => {
  test("every rule and every check id names a real domain", () => {
    for (const { check } of everyCheck()) {
      const ruleDomain = check.rule.split(".")[0] ?? "";
      expect(DomainSchema.safeParse(ruleDomain).success).toBe(true);
      expect(checkIdOf(check)).toBe(`${ruleDomain}.${check.name}`);
      expect(SeveritySchema.safeParse(check.ceiling).success).toBe(true);
    }
  });

  test("check ids are unique inside a kind", () => {
    for (const kind of AUDITED_KINDS) {
      const ids = checkIdsFor(kind);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  test("a check id shared by two kinds means the same thing in both", () => {
    const byId = new Map<string, AuditCheck>();
    for (const { check } of everyCheck()) {
      const id = checkIdOf(check);
      const first = byId.get(id);
      if (first === undefined) {
        byId.set(id, check);
        continue;
      }
      expect(check.rule).toBe(first.rule);
      expect(check.statement).toBe(first.statement);
      expect(check.ceiling).toBe(first.ceiling);
    }
    expect(CHECK_INDEX.size).toBe(byId.size);
  });

  test("a rule carries the same ceiling everywhere it is offered", () => {
    for (const { kind, check } of everyCheck()) {
      expect(ceilingFor(kind, check.rule)).toBe(check.ceiling);
      expect(ceilingOfRule(check.rule)).toBe(check.ceiling);
    }
    expect(ceilingOfRule("data.invented")).toBeUndefined();
    expect(RULE_CEILINGS.get("appsec.idor")).toBe("critical");
  });

  test("every check has a question, a failure condition and a report-voice statement", () => {
    for (const { check } of everyCheck()) {
      expect(check.question.length).toBeGreaterThan(20);
      expect(check.fails.length).toBeGreaterThan(20);
      expect(check.statement.length).toBeGreaterThan(15);
      // The statement is what a passing check publishes, so it reads positively.
      expect(check.statement.startsWith("no ") || !check.statement.includes("missing")).toBe(true);
    }
  });

  test("checkById resolves a check without knowing which kind asked it", () => {
    expect(checkById("appsec.idor")?.rule).toBe("appsec.idor");
    expect(checkById("api.input-validation")?.rule).toBe("api.missing-input-validation");
    expect(checkById("nope.nope")).toBeUndefined();
  });

  test("every rule a kind offers belongs to one of its checks", () => {
    for (const kind of AUDITED_KINDS) {
      const rules = new Set(rulesFor(kind));
      for (const check of checksFor(kind)) expect(rules.has(check.rule)).toBe(true);
      for (const rule of rules) {
        expect(checksFor(kind).some((check) => check.rule === rule)).toBe(true);
      }
    }
  });
});

describe("the system prompt", () => {
  test("states the closed world, the obligation, the rubric and the output contract", () => {
    for (const kind of AUDITED_KINDS) {
      const system = promptFor(kind)?.systemPrompt() ?? "";
      expect(system).toContain("no filesystem");
      expect(system).toContain("elided");
      expect(system).toContain("Return one verdict for EVERY unit id listed");
      for (const severity of SeveritySchema.options) expect(system).toContain(severity);
      expect(system).toContain("Reply with ONE JSON document");
      expect(system).toContain('"unitId"');
      expect(system).toContain("not-applicable");
      expect(system).toContain("exploitability");
    }
  });

  test("offers only the rule ids its own checks use", () => {
    // Per registered prompt, not per kind: a route is audited by three prompts,
    // and each one may name only the rules its own checks file findings under —
    // otherwise a model asked the access-control questions could answer with a
    // contract rule nobody asked it about.
    for (const row of PROMPT_REGISTRY) {
      const own = new Set(rulesFor(row.kind, row.domain));
      const system = promptFor(row.kind, row.domain)?.systemPrompt() ?? "";
      for (const rule of own) expect(system).toContain(rule);
      // A rule the row's own checks do not file under is not offered, even when
      // the module declared it: the projection took the check away, so the
      // question belongs to the batch that kept it and an answer here would be
      // a second finding for one defect.
      const foreign = [...rulesFor(row.kind), ...rulesFor("migration")].filter(
        (rule) => !own.has(rule),
      );
      for (const rule of foreign) expect(system).not.toContain(rule);
    }
  });

  test("is identical for every batch of a kind, so the prompt cache can hold it", () => {
    const builder = promptFor("route");
    expect(builder?.systemPrompt()).toBe(builder?.systemPrompt());
  });
});

describe("the user prompt", () => {
  const context: PromptContext = { stack: UNKNOWN_STACK, shared: [] };

  test("the header states the stack as ground truth and lists every check", () => {
    const builder = promptFor("data-access");
    const header = builder?.header(context, [unit("u1", "data-access")]) ?? "";
    expect(header).toContain("STACK (detected by Sentinel, treat as ground truth)");
    expect(header).toContain("stack detection did not run");
    for (const id of checkIdsFor("data-access", "data")) expect(header).toContain(`"${id}"`);
    expect(header).toContain("SHARED CONTEXT: none was available");
  });

  test("the footer demands a verdict for every id, by id", () => {
    const builder = promptFor("route");
    const units = [unit("a1", "route"), unit("b2", "route")];
    const footer = builder?.footer(units) ?? "";
    expect(footer).toContain("A VERDICT IS REQUIRED FOR ALL 2 OF THESE UNIT IDS");
    expect(footer).toContain("a1");
    expect(footer).toContain("b2");
    expect(footer).toContain(`${checksFor("route", "appsec").length} checks`);
  });

  test("a unit section carries its id, its facts and its source", () => {
    const section = promptFor("route")?.section(unit("a1", "route")) ?? "";
    expect(section).toContain("UNIT a1");
    expect(section).toContain("at: src/api/orders.ts:10-20");
    expect(section).toContain("method: GET");
    expect(section).toContain("// src/api/orders.ts:10-20");
  });

  test("a related slice is labelled and attributed to the unit it came from", () => {
    const entry = unit("gate", "role-gate");
    const withRelated: PromptUnit = {
      ...entry,
      related: [{ label: "the handler", unitId: "route-1", text: "// src/api/orders.ts:1-2" }],
    };
    const section = promptFor("role-gate")?.section(withRelated) ?? "";
    expect(section).toContain("related — the handler (unit route-1)");
  });

  test("the assembled prompt is exactly its parts, so a measured size is the real one", () => {
    const builder = promptFor("route");
    if (builder === undefined) return;
    const units = [unit("a1", "route"), unit("b2", "route")];
    const parts = {
      systemPrompt: builder.systemPrompt(),
      header: builder.header(context, units),
      sections: units.map((entry) => builder.section(entry)),
      footer: builder.footer(units),
    };
    const assembled = assemblePrompt(parts);
    expect(assembled.startsWith(parts.header)).toBe(true);
    expect(assembled.endsWith(parts.footer)).toBe(true);
    for (const section of parts.sections) expect(assembled).toContain(section);
    expect(promptChars(parts)).toBe(parts.systemPrompt.length + assembled.length);
  });
});

describe("rendering", () => {
  test("the stack block never omits a field, so an absent fact is stated", () => {
    const rendered = renderStack({
      frameworks: ["fastify"],
      dataLayers: [],
      databases: ["postgresql"],
      authProviders: [],
      authHelpers: [],
      hasFrontend: false,
      validatesConfig: false,
      notes: [],
    });
    expect(rendered).toContain("framework: fastify");
    expect(rendered).toContain("data layer: not detected");
    expect(rendered).toContain("auth helpers: none found");
    expect(rendered).toContain("frontend in this repository: no");
  });

  test("the checks block names the rule, the ceiling and what a pass publishes", () => {
    const spec = promptFor("webhook")?.spec;
    expect(spec).toBeDefined();
    if (spec === undefined) return;
    const rendered = renderChecks(spec);
    expect(rendered).toContain("serverless.webhook-unverified");
    expect(rendered).toContain("max severity: critical");
    expect(rendered).toContain("a pass publishes:");
    for (const check of spec.checks) expect(rendered).toContain(check.statement);
  });
});

describe("the domain column", () => {
  /**
   * A stand-in for the D6 prompt module another agent is writing.
   *
   * It exists so the multi-domain path is proved now rather than when that file
   * lands: one check the route prompt already asks, one it does not. The real
   * module replaces it by taking the `pending` off its row in the registry.
   */
  const apiStandIn = createPromptBuilder({
    kind: "route",
    noun: "route contract",
    mission:
      "You decide whether each endpoint's request and response contract is what the caller is entitled to, and whether it matches the committed schema.",
    checks: [
      // Deliberately the same id the route prompt already asks, to prove the
      // registry does not buy the same answer twice.
      ROUTE_PROMPT.checks[3] as AuditCheck,
      {
        name: "pagination",
        statement: "a collection endpoint bounds the rows it returns",
        rule: "api.unbounded-collection",
        question: "does this endpoint bound the number of rows it returns, by limit or by cursor?",
        fails: "a list endpoint returns every row that matches, with no limit and no cursor",
        ceiling: "medium",
      },
    ],
    guidance: [],
  });

  test("a kind's primary domain is the one the coverage table falls back to", () => {
    // If these two disagree, a unit no batch reached lands in a different
    // domain's table than the same unit audited, and the per-domain arithmetic
    // stops describing one population.
    for (const kind of AUDITED_KINDS) {
      expect(primaryDomainOf(kind)).toBe(DOMAIN_BY_UNIT_KIND[kind]);
    }
  });

  test("every row's prompt is built for the kind the row files it under", () => {
    for (const row of PROMPT_REGISTRY) {
      expect(DomainSchema.safeParse(row.domain).success).toBe(true);
      if (row.builder === undefined) {
        expect(row.pending?.length ?? 0).toBeGreaterThan(40);
        continue;
      }
      expect(row.builder.kind).toBe(row.kind);
    }
  });

  test("every declared pair has a prompt, so this run states no gap", () => {
    // D6 and D7 were the gaps this table was built to hold. Their modules
    // landed, so both rows carry a builder and the list is empty — but the
    // mechanism stays tested below, because the next domain will need it.
    expect(PROMPT_GAPS).toEqual([]);
    expect(gapsFor("route")).toEqual([]);
    expect(domainsFor("route")).toEqual(["appsec", "api", "reliability"]);
    expect(domainsFor("workflow-job")).toEqual(["delivery"]);
  });

  test("a declared domain with no prompt is a stated gap, not silence", () => {
    // What a domain with no prompt must never be is absent: without this a
    // declared domain reads `0 of 0` with no sentence beside it, because nothing
    // in the pipeline knows the pair was intended.
    const declared = resolveRegistry([
      { kind: "route", domain: "appsec", builder: routePromptBuilder },
      { kind: "route", domain: "api", pending: "`./api.ts` has not been written yet" },
    ]);
    expect(declared.entries.map((entry) => entry.domain)).toEqual(["appsec"]);
    expect(declared.gaps).toEqual([
      { kind: "route", domain: "api", reason: "`./api.ts` has not been written yet" },
    ]);

    // A row with neither a builder nor a sentence still produces a sentence.
    const bare = resolveRegistry([{ kind: "container", domain: "delivery" }]);
    expect(bare.entries).toEqual([]);
    expect(bare.gaps[0]?.reason).toContain("no prompt module claims this domain");
    expect(unauditedReason("container")).toContain("phase 1");
  });

  test("the D7 lens registers every kind it says it audits, and no other", () => {
    // `reliability.ts` owns the list; this table owns the rows. The two are
    // asserted equal rather than derived from each other, so a kind added to
    // that lens and forgotten here fails a test instead of going unaudited.
    const registered = AUDIT_UNIT_KINDS.filter((kind) => domainsFor(kind).includes("reliability"));
    expect(registered).toEqual([...RELIABILITY_KINDS].sort(byKindOrder));
    for (const kind of RELIABILITY_KINDS) {
      expect(rowFor(kind, "reliability")?.builder).toBe(reliabilityPromptFor(kind));
    }
    for (const kind of AUDIT_UNIT_KINDS) {
      if (RELIABILITY_KINDS.includes(kind)) continue;
      expect(promptFor(kind, "reliability")).toBeUndefined();
      expect(RELIABILITY_OUT_OF_SCOPE[kind]?.length ?? 0).toBeGreaterThan(40);
    }
  });

  test("the D6 lens is registered for the route, which is the only kind it claims", () => {
    expect(rowFor("route", API_DOMAIN)?.builder).toBe(apiPromptBuilder);
    expect(AUDIT_UNIT_KINDS.filter((kind) => domainsFor(kind).includes("api"))).toEqual(["route"]);
    // Its five overlapping questions are the route prompt's; what is left is
    // what D6 adds, and that is all the second batch pays for.
    expect(checkIdsFor("route", "api")).toEqual([
      "api.auth-requirement",
      "api.pagination",
      "api.serializer-breadth",
      "api.status-codes",
      "api.contract-drift",
    ]);
  });

  test("a row asks its module's checks minus the ones an earlier row claims", () => {
    // The projection rule, over the whole table: each domain's batch asks what
    // its module declares and no question an earlier domain already asked, and
    // the union of the rows is exactly the concatenation of those halves. That
    // union is what a reply may draw from; each half is what one reply owes.
    for (const kind of AUDITED_KINDS) {
      const seen = new Set<string>();
      for (const domain of domainsFor(kind)) {
        const declared = rowFor(kind, domain)?.builder?.spec.checks ?? [];
        expect(declared.length).toBeGreaterThan(0);
        const expected = declared.map((check) => checkIdOf(check)).filter((id) => !seen.has(id));
        expect(checkIdsFor(kind, domain)).toEqual(expected);
        for (const id of expected) seen.add(id);
      }
      expect(checkIdsFor(kind)).toEqual([...seen]);
    }
  });

  test("a second domain is asked only the checks the first did not ask", () => {
    const resolved = resolveRegistry([
      { kind: "route", domain: "appsec", builder: routePromptBuilder },
      { kind: "route", domain: "api", builder: apiStandIn },
    ]);
    expect(resolved.gaps).toEqual([]);
    expect(resolved.entries.map((entry) => entry.domain)).toEqual(["appsec", "api"]);
    // The primary keeps its module's prompt exactly: same object, same bytes.
    expect(resolved.entries[0]?.builder).toBe(routePromptBuilder);
    // The second is projected onto what is left, so no unit is asked one
    // question twice and no check's population is counted twice.
    const second = resolved.entries[1]?.builder;
    expect(second?.spec.checks.map((check) => checkIdOf(check))).toEqual(["api.pagination"]);
    expect(second?.systemPrompt()).toContain("api.unbounded-collection");
    expect(second?.systemPrompt()).not.toContain("api.missing-input-validation");
  });

  test("a second prompt that repeats the first is reported, not billed twice", () => {
    const resolved = resolveRegistry([
      { kind: "route", domain: "appsec", builder: routePromptBuilder },
      { kind: "route", domain: "api", builder: routePromptBuilder },
    ]);
    expect(resolved.entries).toHaveLength(1);
    expect(resolved.gaps[0]?.domain).toBe("api");
    expect(resolved.gaps[0]?.reason).toContain("already asked by the appsec prompt");
  });

  test("the lookups answer per domain for an obligation and over the union for a permission", () => {
    const registry = [
      { kind: "route" as const, domain: "appsec" as const, builder: routePromptBuilder },
      { kind: "route" as const, domain: "api" as const, builder: apiStandIn },
    ];
    const resolved = resolveRegistry(registry);
    const ids = (domain?: "appsec" | "api"): string[] =>
      resolved.entries
        .filter((entry) => domain === undefined || entry.domain === domain)
        .flatMap((entry) => entry.builder.spec.checks.map((check) => checkIdOf(check)));
    // The union is what a reply may draw from; a domain's own list is what the
    // reply to that batch owes an answer for, and the two halves partition it.
    expect(ids()).toEqual([...ids("appsec"), ...ids("api")]);
    expect(new Set(ids()).size).toBe(ids().length);
  });
});
