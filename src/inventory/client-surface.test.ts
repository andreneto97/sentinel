import { describe, expect, test } from "bun:test";
import type { StackProfile } from "../contracts/profile.ts";
import {
  astGrepPath,
  enumerationContext,
  fixtureRepo,
  match,
  realSearch,
  stubSearch,
} from "./__fixtures__/enumeration-harness.ts";
import type { DraftUnit } from "./_unit-support.ts";
import {
  CLIENT_SURFACE_ENUMERATORS,
  isClientFile,
  isDynamic,
  nearbyElement,
  nearbyEndpoint,
  roleGateEnumerator,
  sinkEnumerator,
  widestPerLine,
} from "./client-surface.ts";

const TARGET = fixtureRepo("client-target");

/** Null when the pinned ast-grep is not installed; the rule tests then skip. */
const AST_GREP = await astGrepPath();

/** The one unit whose label matches, so a failing assertion names what it looked for. */
function unit(units: readonly DraftUnit[], label: string): DraftUnit {
  const found = units.find((candidate) => candidate.label === label);
  if (found === undefined) {
    throw new Error(`no unit labelled "${label}"; got ${units.map((u) => u.label).join(", ")}`);
  }
  return found;
}

/** A profile that proves the repository has, or has not, a frontend. */
function profile(withFrontend: boolean): StackProfile {
  return {
    schemaVersion: "1.0",
    target: TARGET,
    facts: withFrontend
      ? [
          {
            kind: "frontend",
            value: "react",
            confidence: "high",
            evidence: [{ file: "package.json", line: 1 }],
          },
        ]
      : [],
    absences: withFrontend ? [] : [{ kind: "frontend", searched: ["react", "vue"] }],
    warnings: [],
    scan: { filesSeen: 5, filesRead: 5, truncated: false },
  };
}

describe("isClientFile", () => {
  test("an extension the browser renders is enough", () => {
    expect(isClientFile("components/Panel.tsx", "")).toBe(true);
    expect(isClientFile("components/Panel.jsx", "")).toBe(true);
    expect(isClientFile("src/Page.vue", "")).toBe(true);
  });

  test('a "use client" directive is enough', () => {
    expect(isClientFile("src/hooks/use-user.ts", '"use client";\nexport const x = 1;')).toBe(true);
  });

  test("a component directory is enough", () => {
    expect(isClientFile("src/components/panel.ts", "")).toBe(true);
  });

  test("server code is not the client surface, whatever directory it sits in", () => {
    expect(isClientFile("app/api/users/route.ts", "")).toBe(false);
    expect(isClientFile("src/server/reports.ts", "")).toBe(false);
    expect(isClientFile("src/lib/db.server.ts", "")).toBe(false);
  });
});

describe("nearbyEndpoint", () => {
  const lines = [
    "  const canDelete = viewer.permissions.includes('comment:delete');", // 1
    "  return (", // 2
    "    <button onClick={() => fetch(`/api/comments/${id}`, { method: 'DELETE' })}>", // 3
  ];

  test("names the call the gated action makes", () => {
    expect(nearbyEndpoint(lines, 1)).toBe("/api/comments/${id}");
  });

  test("ignores an absolute URL to somebody else's host", () => {
    expect(nearbyEndpoint(["fetch('https://example.test/x')"], 1)).toBeUndefined();
  });
});

describe("nearbyElement", () => {
  test("prefers the interactive element over the layout around it", () => {
    const lines = ["{isAdmin ? (", "  <div>", "    <button type='button'>Delete</button>"];
    expect(nearbyElement(lines, 1)).toBe("button");
  });

  test("falls back to the container when there is nothing else", () => {
    expect(nearbyElement(["<section>", "  text", "</section>"], 1)).toBe("section");
  });
});

describe("widestPerLine", () => {
  test("one gate per line: the widest expression wins", () => {
    const kept = widestPerLine([
      match({ ruleId: "role-compare", file: "a.tsx", line: 5, text: 'user.role === "admin"' }),
      match({
        ruleId: "role-flag",
        file: "a.tsx",
        line: 5,
        text: 'isAdmin = user.role === "admin"',
      }),
      match({ ruleId: "role-call", file: "a.tsx", line: 9, text: "can('edit')" }),
    ]);
    expect(kept).toHaveLength(2);
    expect(kept[0]?.ruleId).toBe("role-flag");
  });
});

describe("isDynamic", () => {
  test("a fixed string cannot carry user input", () => {
    expect(isDynamic('"SELECT 1"')).toBe(false);
    expect(isDynamic("'/admin'")).toBe(false);
  });

  test("anything else has to be traced", () => {
    expect(isDynamic("`SELECT ${term}`")).toBe(true);
    expect(isDynamic("query")).toBe(true);
    expect(isDynamic(undefined)).toBe(true);
  });
});

describe("roleGateEnumerator", () => {
  test("skips the whole check when phase 0 proved there is no frontend", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]), { profile: profile(false) });
    const outcome = await roleGateEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("skipped");
    expect(outcome.reason).toContain("no frontend");
  });

  test("runs when the profile proves a frontend", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "role-flag",
          file: "components/AdminPanel.jsx",
          line: 5,
          text: 'isAdmin = user.role === "admin"',
        }),
      ]),
      { profile: profile(true) },
    );
    expect((await roleGateEnumerator.enumerate(ctx)).units).toHaveLength(1);
  });

  test("refuses a role check that lives in server code", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "role-compare",
          file: "src/server/reports.ts",
          line: 8,
          text: 'user.role !== "admin"',
        }),
      ]),
    );
    expect((await roleGateEnumerator.enumerate(ctx)).units).toHaveLength(0);
  });

  test("refuses a flag whose name is not an authorization decision", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "role-flag",
          file: "components/AdminPanel.jsx",
          line: 5,
          text: "isLoading = state.pending",
        }),
      ]),
    );
    expect((await roleGateEnumerator.enumerate(ctx)).units).toHaveLength(0);
  });

  test.skipIf(AST_GREP === null)("enumerates one unit per decision in the fixture", async () => {
    const ctx = await enumerationContext(TARGET, await realSearch(TARGET));
    const outcome = await roleGateEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("ok");
    expect(outcome.units).toHaveLength(5);

    const admin = unit(outcome.units, 'isAdmin: isAdmin = user.role === "admin"');
    expect(admin.attributes).toMatchObject({
      check: "role-flag",
      subject: "admin",
      symbol: "isAdmin",
      uiElement: "button",
      endpoint: "/api/admin/users",
    });

    const wrapper = unit(outcome.units, 'AdminPanel: <RequireRole role="owner">');
    expect(wrapper.attributes).toMatchObject({
      check: "role-wrapper",
      subject: "owner",
      uiElement: "RequireRole",
      endpoint: "/api/billing/refund",
    });

    // The server-side check in the same repository is not a client gate.
    expect(outcome.units.some((entry) => entry.file.startsWith("src/server/"))).toBe(false);
  });
});

describe("sinkEnumerator", () => {
  test("keeps a parameterised query out of the inventory", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "sink-sql-query",
          file: "src/server/reports.ts",
          line: 19,
          text: 'client.query("SELECT * FROM reports WHERE id = $1", [id])',
          lists: { ARGS: ['"SELECT * FROM reports WHERE id = $1"', "[id]"] },
        }),
      ]),
    );
    expect((await sinkEnumerator.enumerate(ctx)).units).toHaveLength(0);
  });

  test("refuses a command sink in a file that spawns nothing", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "sink-command",
          file: "src/legacy/render.ts",
          line: 8,
          text: "exec(command)",
          lists: { ARGS: ["command"] },
        }),
      ]),
    );
    expect((await sinkEnumerator.enumerate(ctx)).units).toHaveLength(0);
  });

  test.skipIf(AST_GREP === null)("records every sink with its enclosing symbol", async () => {
    const ctx = await enumerationContext(TARGET, await realSearch(TARGET));
    const units = (await sinkEnumerator.enumerate(ctx)).units;
    expect(units).toHaveLength(6);

    expect(unit(units, "dangerouslySetInnerHTML in AdminPanel").attributes).toMatchObject({
      sinkType: "xss",
      dynamic: "yes",
      symbol: "AdminPanel",
    });
    expect(unit(units, "client.query in search").attributes).toMatchObject({
      sinkType: "sql",
      dynamic: "yes",
      symbol: "search",
    });
    expect(unit(units, "execSync in archive").attributes.sinkType).toBe("command");
    expect(unit(units, "eval in runRecipe").attributes.sinkType).toBe("eval");
    expect(unit(units, "innerHTML in renderBanner").attributes.sinkType).toBe("xss");
  });
});

describe("the enumerator registry", () => {
  test("covers the two client-surface kinds", () => {
    expect(CLIENT_SURFACE_ENUMERATORS.flatMap((entry) => [...entry.kinds]).sort()).toEqual([
      "role-gate",
      "sink",
    ]);
  });
});
