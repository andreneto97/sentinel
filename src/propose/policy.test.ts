import { describe, expect, test } from "bun:test";
import {
  AI_DEFAULT_ON_BUDGET_SECONDS,
  DEFAULT_DOMAINS,
  clampSeconds,
  defaultAnswerFor,
  isWithinPath,
  orderDomains,
  slugify,
} from "./policy.ts";

describe("defaultAnswerFor", () => {
  test("deterministic work defaults on", () => {
    expect(defaultAnswerFor({ estimatedSeconds: 40, usesAi: false }, true)).toBe("on");
  });

  test("AI work defaults on only inside the budget", () => {
    expect(
      defaultAnswerFor({ estimatedSeconds: AI_DEFAULT_ON_BUDGET_SECONDS, usesAi: true }, true),
    ).toBe("on");
    expect(
      defaultAnswerFor({ estimatedSeconds: AI_DEFAULT_ON_BUDGET_SECONDS + 1, usesAi: true }, true),
    ).toBe("off");
  });

  test("work blocked on a missing tool defaults off — accepting it buys nothing", () => {
    expect(defaultAnswerFor({ estimatedSeconds: 10, usesAi: false }, false)).toBe("off");
  });
});

describe("isWithinPath", () => {
  test("the repo root contains everything", () => {
    expect(isWithinPath("apps/mobile", ".")).toBe(true);
    expect(isWithinPath("apps/mobile", "")).toBe(true);
  });

  test("a sibling package is outside the analysed path", () => {
    expect(isWithinPath("apps/mobile", "apps/api")).toBe(false);
  });

  test("a nested path is inside, and a prefix collision is not", () => {
    expect(isWithinPath("apps/api/src", "apps/api")).toBe(true);
    expect(isWithinPath("apps/api", "apps/api")).toBe(true);
    expect(isWithinPath("apps/api-worker", "apps/api")).toBe(false);
  });

  test("normalises ./ and trailing slashes", () => {
    expect(isWithinPath("./apps/api/", "apps/api")).toBe(true);
  });
});

describe("orderDomains", () => {
  test("returns canonical report order and drops duplicates", () => {
    expect(orderDomains(["deadcode", "appsec", "appsec", "dependencies"])).toEqual([
      "dependencies",
      "appsec",
      "deadcode",
    ]);
  });

  test("the default scope is D1-D4 plus dead code, whose candidates phase 1 already produces", () => {
    expect(orderDomains(DEFAULT_DOMAINS)).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "deadcode",
    ]);
  });
});

describe("clampSeconds and slugify", () => {
  test("clampSeconds keeps estimates believable", () => {
    expect(clampSeconds(4, 60, 900)).toBe(60);
    expect(clampSeconds(4000, 60, 900)).toBe(900);
    expect(clampSeconds(120.4, 60, 900)).toBe(120);
  });

  test("slugify produces an id-safe fragment", () => {
    expect(slugify("apps/mobile")).toBe("apps-mobile");
    expect(slugify("C#")).toBe("c");
    expect(slugify("///")).toBe("unnamed");
  });
});
