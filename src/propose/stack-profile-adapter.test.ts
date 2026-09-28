import { describe, expect, test } from "bun:test";
import type { ProfileFact } from "./stack-profile-adapter.ts";
import {
  createProfileView,
  evidencePaths,
  factCount,
  kindMatchesTopic,
  parseCountedValue,
  totalCount,
} from "./stack-profile-adapter.ts";

function fact(
  kind: string,
  value: string,
  options: { files?: string[]; detail?: string } = {},
): ProfileFact {
  return {
    kind,
    value,
    confidence: "high",
    evidence: (options.files ?? []).map((file) => ({ file })),
    ...(options.detail === undefined ? {} : { detail: options.detail }),
  };
}

describe("kindMatchesTopic", () => {
  test("matches the exact kind regardless of separator style", () => {
    expect(kindMatchesTopic("Serverless_Platform", "serverless-platform")).toBe(true);
    expect(kindMatchesTopic("migrations/dir", "migrations-dir")).toBe(true);
  });

  test("matches on the first or last dotted segment, for kinds not yet split out", () => {
    expect(kindMatchesTopic("serverless.function", "function")).toBe(true);
    expect(kindMatchesTopic("aws.lambda.function", "function")).toBe(true);
    expect(kindMatchesTopic("iac.terraform", "iac")).toBe(true);
  });

  test("does not match a partial word — migration-tool is not a migrations-dir", () => {
    expect(kindMatchesTopic("migration-tool", "migration")).toBe(false);
    expect(kindMatchesTopic("package-manager", "package")).toBe(false);
  });
});

describe("createProfileView", () => {
  const view = createProfileView(
    [
      fact("iac", "terraform", { files: ["terraform/main.tf"], detail: "12 file(s)" }),
      fact("iac", "helm", { files: ["charts/api/Chart.yaml"], detail: "2 chart(s)" }),
      fact("migrations-dir", "prisma/migrations", { files: ["prisma/migrations/a.sql"] }),
      fact("migration-tool", "prisma", { files: ["prisma/schema.prisma"] }),
    ],
    [{ kind: "frontend", searched: ["*.tsx"], note: "No user interface." }],
  );

  test("selects by kind without dragging in near-miss kinds", () => {
    expect(view.select("migrations-dir").map((f) => f.value)).toEqual(["prisma/migrations"]);
  });

  test("values are distinct and sorted", () => {
    expect(view.values("iac")).toEqual(["helm", "terraform"]);
  });

  test("has() is kind-scoped", () => {
    expect(view.has("iac")).toBe(true);
    expect(view.has("container")).toBe(false);
  });

  test("absences carry the profiler's own note about what is not applicable", () => {
    expect(view.absence("frontend")?.note).toBe("No user interface.");
    expect(view.absence("container")).toBeUndefined();
  });
});

describe("factCount", () => {
  test("reads a count out of the profiler's detail string", () => {
    expect(factCount(fact("container", "dockerfile", { detail: "3 file(s)" }))).toBe(3);
    expect(factCount(fact("iac", "helm", { detail: "2 chart(s)" }))).toBe(2);
    expect(
      factCount(
        fact("serverless-platform", "supabase-functions", { detail: "5 edge function(s)" }),
      ),
    ).toBe(5);
  });

  test("is not fooled by a version number earlier in the detail", () => {
    expect(
      factCount(
        fact("language", "typescript", { detail: "typescript@^5.6.3, 240 TypeScript file(s)" }),
      ),
    ).toBe(240);
  });

  test("falls back to the name:count value convention", () => {
    expect(factCount(fact("language", "python:31"))).toBe(31);
  });

  test("returns undefined rather than counting capped evidence", () => {
    expect(
      factCount(fact("migrations-dir", "prisma/migrations", { files: ["a.sql", "b.sql"] })),
    ).toBeUndefined();
  });
});

describe("totalCount", () => {
  test("sums only the facts that state a count", () => {
    expect(
      totalCount([
        fact("ci", "github-actions", { detail: "6 file(s)" }),
        fact("ci", "circleci", { detail: "1 file(s)" }),
      ]),
    ).toBe(7);
  });

  test("is undefined when nothing stated a count", () => {
    expect(totalCount([fact("migrations-dir", "prisma/migrations")])).toBeUndefined();
    expect(totalCount([])).toBeUndefined();
  });
});

describe("evidencePaths", () => {
  test("de-duplicates, sorts and caps", () => {
    const facts = [
      fact("language", "python", { files: ["b.py", "a.py"] }),
      fact("language", "python", { files: ["a.py", "c.py", "d.py"] }),
    ];
    expect(evidencePaths(facts)).toEqual(["a.py", "b.py", "c.py", "d.py"]);
    expect(evidencePaths(facts, 2)).toEqual(["a.py", "b.py"]);
  });

  test("ignores blank paths", () => {
    expect(evidencePaths([fact("language", "go", { files: ["  ", "main.go"] })])).toEqual([
      "main.go",
    ]);
  });
});

describe("parseCountedValue", () => {
  test("splits the name:count convention", () => {
    expect(parseCountedValue("python:31")).toEqual({ name: "python", count: 31 });
  });

  test("leaves a plain value alone", () => {
    expect(parseCountedValue(" go ")).toEqual({ name: "go", count: undefined });
  });
});
