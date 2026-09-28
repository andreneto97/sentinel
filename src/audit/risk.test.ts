/**
 * The risk ordering, tested against the attribute shapes phase 2 actually writes.
 *
 * Every `unit()` below carries the attribute *values* the enumerators emit —
 * `filtersByPrincipal: "no"`, `lockRisk: "add-not-null-with-default"`, `backoff:
 * "unset"` — rather than values invented for the test. A scorer that reads
 * `authenticated: "false"` where the enumerator writes `"no"` would pass a
 * hand-made fixture and then score every route in a repository identically, which
 * is the exact failure this ordering exists to prevent.
 */

import { describe, expect, test } from "bun:test";
import type { AuditUnit } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../contracts/inventory.ts";
import {
  EMPTY_RISK_CONTEXT,
  KIND_BASE,
  RISK_ORDERING,
  meanRisk,
  rankUnits,
  riskContextOf,
  scoreUnit,
  topReasons,
} from "./risk.ts";

/** A unit with the attributes a real enumerator would have written. */
function unit(
  kind: AuditUnitKind,
  attributes: Readonly<Record<string, string>>,
  id = `${kind}-${JSON.stringify(attributes).length}-${Math.random().toString(36).slice(2, 8)}`,
): AuditUnit {
  return {
    id,
    kind,
    label: `${kind} unit`,
    location: { file: `src/${kind}.ts`, line: 1 },
    attributes,
  };
}

// Attribute sets in the spellings the enumerators write them.

/** An unauthenticated delete taking two ids off the path: the worst shape a route has. */
const UNAUTHENTICATED_DELETE = unit("route", {
  method: "DELETE",
  path: "/:customerId/addresses/:id",
  framework: "express",
  authenticated: "no",
  authCheck: "none",
  mutates: "true",
  readsBody: "false",
  validation: "none",
  pagination: "none",
  trigger: "http",
  idParams: "customerId,id",
});

/** A guarded, paginated read: the shape a well-built route has. */
const GUARDED_READ = unit("route", {
  method: "GET",
  path: "/api/opportunities",
  framework: "next-app-router",
  authenticated: "yes",
  authCheck: "requireBusiness",
  mutates: "false",
  readsBody: "false",
  validation: "z.uuid()",
  pagination: "cursor",
  trigger: "http",
});

describe("scoreUnit", () => {
  test("an unauthenticated mutating handler that takes an id outranks a guarded read", () => {
    const dangerous = scoreUnit(UNAUTHENTICATED_DELETE);
    const safe = scoreUnit(GUARDED_READ);
    expect(dangerous.score).toBeGreaterThan(safe.score);
    expect(dangerous.reasons).toContain("reachable without authentication");
    expect(dangerous.reasons).toContain(
      "takes an object id from the request, which is the precondition for IDOR",
    );
    // The guarded read is not zero — it is still an entry point — but nothing
    // about it fires beyond the kind itself and the unpaginated-read rule.
    expect(safe.reasons[0]).toBe("an entry point reachable from outside the process");
  });

  test("a webhook without signature verification outranks one with", () => {
    const shape = {
      provider: "custom",
      replayProtection: "no",
      usesRawBody: "no",
    } as const;
    const unverified = scoreUnit(unit("webhook", { ...shape, signatureVerified: "no" }));
    const verified = scoreUnit(
      unit("webhook", { ...shape, signatureVerified: "yes", replayProtection: "yes" }),
    );
    expect(unverified.score).toBeGreaterThan(verified.score);
    expect(unverified.reasons).toContain("no inbound signature verification was found");
  });

  test("an unproved guard is treated as no guard, never as a pass", () => {
    // Phase 2 says it could not tell. A scorer that read that as "verified"
    // would bury exactly the receiver a human most needs to look at.
    const unknown = scoreUnit(unit("webhook", { signatureVerified: "unknown" }));
    const verified = scoreUnit(unit("webhook", { signatureVerified: "yes" }));
    expect(unknown.score).toBeGreaterThan(verified.score);
  });

  test("an unauthenticated cron endpoint outranks a migration from 2023", () => {
    const cron = scoreUnit(
      unit("cron", {
        authenticated: "no",
        authCheck: "none",
        library: "vercel",
        schedule: "0 12 * * *",
        path: "/api/cron/reminders",
      }),
    );
    const context = riskContextOf([
      unit("migration", { ordinal: "1", version: "20230101000000", tool: "typeorm" }, "old"),
      unit("migration", { ordinal: "480", version: "20260901000000", tool: "typeorm" }, "new"),
    ]);
    const old = scoreUnit(
      unit(
        "migration",
        {
          ordinal: "1",
          version: "20230101000000",
          tool: "typeorm",
          destructive: "false",
          hasDownMigration: "true",
          lockRisk: "none",
          mixesDataAndSchema: "false",
        },
        "old",
      ),
      context,
    );
    expect(cron.score).toBeGreaterThan(old.score);
    expect(cron.reasons).toContain("the scheduled endpoint is reachable without a shared secret");
  });

  test("recency is a nudge inside the kind, never enough to overtake a risky one", () => {
    const context = riskContextOf([
      unit("migration", { ordinal: "1" }, "a"),
      unit("migration", { ordinal: "480" }, "b"),
    ]);
    const base = {
      tool: "typeorm",
      hasDownMigration: "true",
      mixesDataAndSchema: "false",
    } as const;
    const recentAndHarmless = scoreUnit(
      unit("migration", { ...base, ordinal: "480", destructive: "false", lockRisk: "none" }, "b"),
      context,
    );
    const oldAndDestructive = scoreUnit(
      unit(
        "migration",
        { ...base, ordinal: "1", destructive: "true", lockRisk: "add-not-null-with-default" },
        "a",
      ),
      context,
    );
    expect(oldAndDestructive.score).toBeGreaterThan(recentAndHarmless.score);
    expect(recentAndHarmless.reasons).toContain(
      "one of the most recent migrations, so least likely reviewed",
    );
  });

  test("a query with no principal predicate outranks one scoped to the caller", () => {
    const shape = {
      orm: "typeorm",
      operation: "update",
      hasWhere: "true",
      hasLimit: "false",
      hasProjection: "n/a",
      insideLoop: "false",
      insideTransaction: "false",
      awaitedSequentially: "true",
      table: "invoices",
      tableSource: "identifier",
    } as const;
    const unscoped = scoreUnit(unit("data-access", { ...shape, filtersByPrincipal: "no" }));
    const scoped = scoreUnit(
      unit("data-access", { ...shape, filtersByPrincipal: "yes", scopeColumns: "businessId" }),
    );
    expect(unscoped.score).toBeGreaterThan(scoped.score);
    expect(unscoped.reasons).toContain(
      "no predicate constrains the query by the authenticated principal",
    );
  });

  test("both spellings of `filtersByPrincipal` are read the same way", () => {
    // The enumerator writes `no`/`yes`/`scoped`; the prompt documents
    // `false`/`true`. A scorer that matched only one would flatten every
    // data-access call site in a repository to the same number and no test would fail.
    const shape = { orm: "pg", operation: "select", hasWhere: "true" } as const;
    const enumeratorSpelling = scoreUnit(
      unit("data-access", { ...shape, filtersByPrincipal: "no" }),
    );
    const promptSpelling = scoreUnit(
      unit("data-access", { ...shape, filtersByPrincipal: "false" }),
    );
    expect(promptSpelling.score).toBe(enumeratorSpelling.score);
    // `scoped` is the enumerator saying it found the tenant predicate.
    expect(scoreUnit(unit("data-access", { ...shape, filtersByPrincipal: "scoped" })).score).toBe(
      scoreUnit(unit("data-access", { ...shape, filtersByPrincipal: "yes" })).score,
    );
  });

  test("an unfiltered write and an N+1 read are both named", () => {
    const wide = scoreUnit(
      unit("data-access", {
        orm: "typeorm",
        operation: "delete",
        hasWhere: "false",
        filtersByPrincipal: "no",
        insideLoop: "for",
        insideTransaction: "false",
        hasLimit: "false",
        awaitedSequentially: "true",
        table: "sessions",
        tableSource: "identifier",
      }),
    );
    expect(wide.reasons).toContain("a write with no WHERE clause, so it reaches every row");
    expect(wide.reasons).toContain("the call sits inside a loop, which is the N+1 shape");
  });

  test("a route outranks the data-access call site behind it, all else equal", () => {
    // Blast radius, not likelihood: the handler is what an attacker reaches.
    const route = scoreUnit(unit("route", { authenticated: "yes", authCheck: "requireSession" }));
    const query = scoreUnit(
      unit("data-access", { filtersByPrincipal: "yes", operation: "select" }),
    );
    expect(route.score).toBeGreaterThan(query.score);
  });

  test("every reason list leads with what the unit is, so a score is never bare", () => {
    for (const kind of AUDIT_UNIT_KINDS) {
      const score = scoreUnit(unit(kind, {}));
      expect(score.reasons.length).toBeGreaterThan(0);
      expect(score.score).toBeGreaterThanOrEqual(KIND_BASE[kind]);
    }
    // With nothing proved either way a route scores its base exactly: none of
    // its signals fire on an absent attribute, because "the enumerator did not
    // write `mutates`" is not evidence that the handler mutates.
    expect(scoreUnit(unit("route", {})).score).toBe(KIND_BASE.route);
    // A webhook is the documented exception: an absent `signatureVerified` is a
    // question, and a question outranks a proved answer.
    expect(scoreUnit(unit("webhook", {})).score).toBeGreaterThan(KIND_BASE.webhook);
  });

  test("the score is clamped to the 0-100 scale it is printed on", () => {
    expect(scoreUnit(UNAUTHENTICATED_DELETE).score).toBeLessThanOrEqual(100);
    expect(scoreUnit(UNAUTHENTICATED_DELETE).score).toBeGreaterThanOrEqual(0);
  });

  test("an unknown attribute value neither fires a signal nor throws", () => {
    const score = scoreUnit(
      unit("route", { authenticated: "unknown", mutates: "unknown", idParams: "unresolved" }),
    );
    expect(score.reasons).not.toContain("reachable without authentication");
    expect(score.reasons).not.toContain(
      "takes an object id from the request, which is the precondition for IDOR",
    );
  });

  test("scoring is independent of the rest of the inventory, except migration recency", () => {
    const route = unit("route", { authenticated: "no", mutates: "true" });
    expect(scoreUnit(route, EMPTY_RISK_CONTEXT)).toEqual(scoreUnit(route, riskContextOf([route])));
  });
});

describe("rankUnits", () => {
  test("orders by risk and is total, so two runs produce the same queue", () => {
    const units = [GUARDED_READ, UNAUTHENTICATED_DELETE, unit("data-access", { operation: "raw" })];
    const once = rankUnits(units).map((entry) => entry.unit.id);
    const again = rankUnits([...units].reverse()).map((entry) => entry.unit.id);
    expect(once).toEqual(again);
    expect(once[0]).toBe(UNAUTHENTICATED_DELETE.id);
  });

  test("ties break on kind, file and line, never on input order", () => {
    const a = unit("route", { authenticated: "no" }, "zzz");
    const b = unit("route", { authenticated: "no" }, "aaa");
    const ranked = rankUnits([a, b]);
    expect(ranked[0]?.risk.score).toBe(ranked[1]?.risk.score);
    expect(ranked.map((entry) => entry.unit.id)).toEqual(["aaa", "zzz"]);
  });

  test("every unit comes back exactly once", () => {
    const units = [UNAUTHENTICATED_DELETE, GUARDED_READ, unit("migration", { ordinal: "3" })];
    const ranked = rankUnits(units);
    expect(ranked).toHaveLength(units.length);
    expect(new Set(ranked.map((entry) => entry.unit.id)).size).toBe(units.length);
  });
});

describe("meanRisk", () => {
  test("averages rather than taking the maximum, because a batch is dispatched whole", () => {
    const scores = [scoreUnit(UNAUTHENTICATED_DELETE), scoreUnit(GUARDED_READ)];
    const mean = meanRisk(scores);
    expect(mean).toBeLessThan(scores[0]?.score ?? 0);
    expect(mean).toBeGreaterThan(scores[1]?.score ?? 0);
  });

  test("an empty batch is worth nothing rather than NaN", () => {
    expect(meanRisk([])).toBe(0);
  });
});

describe("topReasons", () => {
  test("names the signals that fired, not the kind every unit shares", () => {
    const reasons = topReasons([scoreUnit(UNAUTHENTICATED_DELETE), scoreUnit(GUARDED_READ)]);
    expect(reasons).not.toContain("an entry point reachable from outside the process");
    expect(reasons).toContain("reachable without authentication");
    expect(reasons.length).toBeLessThanOrEqual(3);
  });

  test("is empty when nothing but the kind explains the selection", () => {
    expect(topReasons([scoreUnit(unit("data-access", {}))])).toEqual([]);
  });
});

describe("RISK_ORDERING", () => {
  test("is a sentence a dossier can print after 'ordered by'", () => {
    expect(RISK_ORDERING.startsWith("ordered by")).toBe(true);
    expect(RISK_ORDERING.length).toBeGreaterThan(40);
  });
});
