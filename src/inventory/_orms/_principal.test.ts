import { describe, expect, test } from "bun:test";
import {
  comparisonValues,
  filtersByPrincipal,
  isPrincipalColumn,
  isPrincipalExpression,
  memberColumns,
  principalScope,
  splitWords,
} from "./_principal.ts";

describe("splitWords", () => {
  test("reads camel case, snake case and screaming case the same way", () => {
    expect(splitWords("organizationId")).toEqual(["organization", "id"]);
    expect(splitWords("organization_id")).toEqual(["organization", "id"]);
    expect(splitWords("ORGANIZATION_ID")).toEqual(["organization", "id"]);
  });
});

describe("isPrincipalColumn", () => {
  test("a column that names who the row belongs to counts", () => {
    for (const column of [
      "userId",
      "user_id",
      "ownerId",
      "creator_id",
      "tenantId",
      "organization_id",
      "orgId",
      "accountId",
      "workspace_id",
      "created_by",
      "user",
    ]) {
      expect(isPrincipalColumn(column)).toBe(true);
    }
  });

  test("a property of the principal is not the principal", () => {
    // These name something *about* a user; filtering by them isolates nothing.
    for (const column of ["username", "user_agent", "account_type", "org_name", "team_size"]) {
      expect(isPrincipalColumn(column)).toBe(false);
    }
  });

  test("an unrelated column does not count", () => {
    for (const column of ["status", "created_at", "total", "id", "slug"]) {
      expect(isPrincipalColumn(column)).toBe(false);
    }
  });

  test("quoting does not change the answer", () => {
    expect(isPrincipalColumn('"tenant_id"')).toBe(true);
  });
});

describe("isPrincipalExpression", () => {
  test("a value read off the session counts", () => {
    for (const expression of [
      "session.user.id",
      "ctx.user.id",
      "req.user.id",
      "auth.uid()",
      "currentUser.id",
      "locals.user.id",
      "userId",
      "orgId",
      "await getServerSession()",
    ]) {
      expect(isPrincipalExpression(expression)).toBe(true);
    }
  });

  test("a value read off the request body does not", () => {
    for (const expression of ['"open"', "input.status", "params.slug", "20", "body.total"]) {
      expect(isPrincipalExpression(expression)).toBe(false);
    }
  });
});

describe("memberColumns", () => {
  test("reads the column out of a Drizzle comparison", () => {
    expect(memberColumns("eq(bookings.organizationId, orgId)")).toEqual(["organizationId"]);
  });

  test("a session lookup is a value, not a column", () => {
    expect(memberColumns("eq(bookings.id, session.user.id)")).toEqual(["id"]);
  });
});

describe("filtersByPrincipal", () => {
  test("a principal column is enough on its own", () => {
    expect(filtersByPrincipal(["organizationId"], ['"open"'])).toBe(true);
  });

  test("a principal value is enough even when the column is neutral", () => {
    // `WHERE id = session.user.id` isolates the tenant without naming it.
    expect(filtersByPrincipal(["id"], ["session.user.id"])).toBe(true);
  });

  test("a filter on neither is not tenant isolation", () => {
    expect(filtersByPrincipal(["status"], ['"open"'])).toBe(false);
  });

  test("no filter at all is never isolation", () => {
    expect(filtersByPrincipal([], [])).toBe(false);
  });
});

describe("comparisonValues", () => {
  test("keeps the bare identifiers and the request-shaped paths", () => {
    expect(comparisonValues("eq(users.id, session.user.id)")).toContain("session.user.id");
    expect(comparisonValues("eq(users.id, orgId)")).toContain("orgId");
  });
});

describe("principalScope", () => {
  test("a session-derived filter is a proven principal scope", () => {
    expect(principalScope(["user_id"], ["session.user.id"]).scope).toBe("yes");
  });

  // Regression: an app whose tenant column is named after its own owning entity
  // — `businessId`, `workspaceId`, `clinicId` — is still tenant-scoped. Reporting
  // an unrecognised owning-entity id as "no" tells the audit the read was
  // unscoped, which is an IDOR finding against code that has none.
  test("an owning-entity id this module does not recognise is `scoped`, not `no`", () => {
    const result = principalScope(["businessId"], ["businessId"]);
    expect(result.scope).toBe("scoped");
    expect(result.scopeColumns).toEqual(["businessId"]);
  });

  test("a bare primary key is not a scope — that is the IDOR shape", () => {
    expect(principalScope(["id"], ["params.id"]).scope).toBe("no");
  });

  test("no where clause at all is `no`", () => {
    expect(principalScope([], []).scope).toBe("no");
  });
});
