import { describe, expect, test } from "bun:test";
import {
  type Probe,
  absencesFrom,
  fact,
  mergeFacts,
  ref,
  strongerConfidence,
} from "./fact-builder.ts";

describe("ref", () => {
  test("omits the note instead of setting it to undefined", () => {
    expect(ref("package.json")).toEqual({ file: "package.json", line: 1 });
    expect("note" in ref("package.json")).toBe(false);
    expect(ref("a.ts", 7, "dependencies")).toEqual({ file: "a.ts", line: 7, note: "dependencies" });
  });

  test("clamps a non-positive line to 1, because CodeRef lines are 1-based", () => {
    expect(ref("a.ts", 0).line).toBe(1);
    expect(ref("a.ts", -3).line).toBe(1);
  });
});

describe("fact", () => {
  test("omits an absent detail", () => {
    const built = fact({
      kind: "data-layer",
      value: "prisma",
      confidence: "high",
      evidence: [ref("package.json", 3)],
    });
    expect("detail" in built).toBe(false);
    expect(built.evidence).toHaveLength(1);
  });
});

describe("mergeFacts", () => {
  test("collapses the same (kind, value) into one fact with all the evidence", () => {
    const merged = mergeFacts([
      fact({
        kind: "data-layer",
        value: "prisma",
        confidence: "medium",
        evidence: [ref("package.json", 3)],
      }),
      fact({
        kind: "data-layer",
        value: "prisma",
        confidence: "high",
        evidence: [ref("prisma/schema.prisma", 1)],
        detail: "schema present",
      }),
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.confidence).toBe("high");
    expect(merged[0]?.detail).toBe("schema present");
    expect(merged[0]?.evidence.map((item) => item.file)).toEqual([
      "package.json",
      "prisma/schema.prisma",
    ]);
  });

  test("keeps different values of the same kind apart", () => {
    const merged = mergeFacts([
      fact({ kind: "ci", value: "github-actions", confidence: "high", evidence: [ref("a.yml")] }),
      fact({ kind: "ci", value: "gitlab-ci", confidence: "high", evidence: [ref("b.yml")] }),
    ]);
    expect(merged.map((item) => item.value)).toEqual(["github-actions", "gitlab-ci"]);
  });

  test("does not repeat the same citation twice", () => {
    const merged = mergeFacts([
      fact({
        kind: "container",
        value: "dockerfile",
        confidence: "high",
        evidence: [ref("Dockerfile")],
      }),
      fact({
        kind: "container",
        value: "dockerfile",
        confidence: "high",
        evidence: [ref("Dockerfile")],
      }),
    ]);
    expect(merged[0]?.evidence).toHaveLength(1);
  });

  test("caps evidence so one fact cannot swamp the artifact", () => {
    const merged = mergeFacts(
      Array.from({ length: 10 }, (_, index) =>
        fact({
          kind: "env-var",
          value: "DATABASE_URL",
          confidence: "high",
          evidence: [ref(`src/file-${index}.ts`, index + 1)],
        }),
      ),
      3,
    );
    expect(merged[0]?.evidence).toHaveLength(3);
  });
});

describe("absencesFrom", () => {
  test("reports a probed kind that produced no fact", () => {
    const probes: Probe[] = [{ kind: "frontend", searched: ["react", "vue"], note: "pure API" }];
    expect(absencesFrom(probes, [])).toEqual([
      { kind: "frontend", searched: ["react", "vue"], note: "pure API" },
    ]);
  });

  test("stays silent about a kind that was proven", () => {
    const proven = fact({
      kind: "frontend",
      value: "next",
      confidence: "high",
      evidence: [ref("app/page.tsx")],
    });
    expect(absencesFrom([{ kind: "frontend", searched: ["react"] }], [proven])).toEqual([]);
  });

  test("merges what several detectors searched for the same kind", () => {
    const absences = absencesFrom(
      [
        { kind: "queue", searched: ["bullmq"] },
        { kind: "queue", searched: ["inngest", "bullmq"] },
      ],
      [],
    );
    expect(absences).toHaveLength(1);
    expect(absences[0]?.searched).toEqual(["bullmq", "inngest"]);
  });
});

describe("strongerConfidence", () => {
  test("ranks high over medium over low", () => {
    expect(strongerConfidence("low", "medium")).toBe("medium");
    expect(strongerConfidence("high", "low")).toBe("high");
    expect(strongerConfidence("medium", "medium")).toBe("medium");
  });
});
