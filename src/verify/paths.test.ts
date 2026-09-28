import { describe, expect, test } from "bun:test";
import { isInside, normaliseCitedPath, resolveRepoPath, toPosix } from "./paths.ts";

const TARGET = "/repo";

describe("normaliseCitedPath", () => {
  test("strips the decoration models add around paths", () => {
    expect(normaliseCitedPath("  `src/a.ts`  ")).toBe("src/a.ts");
    expect(normaliseCitedPath('"./src/a.ts"')).toBe("src/a.ts");
    expect(normaliseCitedPath("file:///repo/src/a.ts")).toBe("/repo/src/a.ts");
    expect(normaliseCitedPath("src/a.ts/")).toBe("src/a.ts");
  });
});

describe("isInside", () => {
  test("accepts descendants and refuses the directory itself", () => {
    expect(isInside("/repo", "/repo/src/a.ts")).toBe(true);
    expect(isInside("/repo", "/repo")).toBe(false);
    expect(isInside("/repo", "/repo-other/a.ts")).toBe(false);
    expect(isInside("/repo", "/etc/passwd")).toBe(false);
  });
});

describe("resolveRepoPath", () => {
  test("returns a repo-relative POSIX path", () => {
    const resolved = resolveRepoPath("src/api/users.ts", TARGET);
    expect(resolved).toEqual({
      ok: true,
      value: { absolute: "/repo/src/api/users.ts", relative: "src/api/users.ts" },
    });
  });

  test("normalises an absolute path inside the target", () => {
    const resolved = resolveRepoPath("/repo/src/a.ts", TARGET);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.value.relative).toBe("src/a.ts");
  });

  test("normalises interior traversal that stays inside", () => {
    const resolved = resolveRepoPath("src/api/../a.ts", TARGET);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.value.relative).toBe("src/a.ts");
  });

  test("refuses a path that escapes the target", () => {
    for (const raw of ["../../etc/passwd", "/etc/passwd", "src/../../secrets.env"]) {
      const resolved = resolveRepoPath(raw, TARGET);
      expect(resolved.ok).toBe(false);
      if (!resolved.ok) expect(resolved.reason).toBe("path-escape");
    }
  });

  test("refuses an empty path and a NUL byte", () => {
    const empty = resolveRepoPath("   ", TARGET);
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.reason).toBe("file-not-found");

    const nul = resolveRepoPath("src/a\0.ts", TARGET);
    expect(nul.ok).toBe(false);
    if (!nul.ok) expect(nul.reason).toBe("path-escape");
  });
});

describe("toPosix", () => {
  test("leaves a POSIX path untouched", () => {
    expect(toPosix("src/a.ts")).toBe("src/a.ts");
  });
});
