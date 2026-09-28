import { describe, expect, test } from "bun:test";
import {
  compareVersions,
  formatVersion,
  minVersionOfRange,
  parseVersion,
  versionGap,
} from "./_semver-lite.ts";

/** Parses, failing the test rather than returning null into an assertion. */
function version(raw: string) {
  const parsed = parseVersion(raw);
  if (parsed === null) throw new Error(`not a version: ${raw}`);
  return parsed;
}

describe("parseVersion", () => {
  test("reads the three components and the prerelease tag", () => {
    expect(parseVersion("1.2.3")).toEqual({ major: 1, minor: 2, patch: 3, prerelease: "" });
    expect(parseVersion("v18.4.0")).toEqual({ major: 18, minor: 4, patch: 0, prerelease: "" });
    expect(parseVersion("2.0.0-rc.1")).toEqual({
      major: 2,
      minor: 0,
      patch: 0,
      prerelease: "rc.1",
    });
  });

  test("fills in the components a short version omits", () => {
    expect(parseVersion("7")).toEqual({ major: 7, minor: 0, patch: 0, prerelease: "" });
    expect(parseVersion("7.5")).toEqual({ major: 7, minor: 5, patch: 0, prerelease: "" });
  });

  test("rejects anything that is not an exact version", () => {
    expect(parseVersion("^1.2.3")).toBeNull();
    expect(parseVersion("workspace:*")).toBeNull();
    expect(parseVersion("latest")).toBeNull();
    expect(parseVersion("")).toBeNull();
  });
});

describe("compareVersions", () => {
  test("orders by major, then minor, then patch", () => {
    expect(compareVersions(version("1.0.0"), version("2.0.0"))).toBeLessThan(0);
    expect(compareVersions(version("1.3.0"), version("1.2.9"))).toBeGreaterThan(0);
    expect(compareVersions(version("1.2.3"), version("1.2.3"))).toBe(0);
  });

  test("a prerelease sorts before the release it leads to", () => {
    expect(compareVersions(version("2.0.0-rc.1"), version("2.0.0"))).toBeLessThan(0);
    expect(compareVersions(version("2.0.0"), version("2.0.0-rc.1"))).toBeGreaterThan(0);
  });
});

describe("versionGap", () => {
  test("classifies the distance to the latest release", () => {
    expect(versionGap("4.1.2", "6.0.0")).toBe("major");
    expect(versionGap("7.5.0", "7.8.5")).toBe("minor");
    expect(versionGap("1.2.3", "1.2.9")).toBe("patch");
  });

  test("an up-to-date or newer installed version is no gap at all", () => {
    expect(versionGap("1.3.0", "1.3.0")).toBe("none");
    expect(versionGap("2.0.0", "1.9.9")).toBe("none");
  });

  test("a 0.x bump is measured by the component that moved", () => {
    expect(versionGap("0.18.0", "0.20.2")).toBe("minor");
  });

  test("says it cannot tell rather than guessing", () => {
    expect(versionGap("workspace:*", "1.0.0")).toBeNull();
    expect(versionGap("1.0.0", "next")).toBeNull();
  });
});

describe("minVersionOfRange", () => {
  test("reads the floor out of the common range syntaxes", () => {
    expect(minVersionOfRange("^1.2.3")).toEqual(version("1.2.3"));
    expect(minVersionOfRange("~4.0.1")).toEqual(version("4.0.1"));
    expect(minVersionOfRange(">=7.5.0")).toEqual(version("7.5.0"));
    expect(minVersionOfRange("7.5.0")).toEqual(version("7.5.0"));
    expect(minVersionOfRange("1.2.x")).toEqual(version("1.2.0"));
  });

  test("reads the first comparator of a compound range", () => {
    expect(minVersionOfRange(">=1.2.3 <2.0.0")).toEqual(version("1.2.3"));
    expect(minVersionOfRange("^1.0.0 || ^2.0.0")).toEqual(version("1.0.0"));
  });

  test("reads through an npm alias", () => {
    expect(minVersionOfRange("npm:@scope/other@^3.1.0")).toEqual(version("3.1.0"));
  });

  test("returns null for a range with no floor", () => {
    expect(minVersionOfRange("*")).toBeNull();
    expect(minVersionOfRange("workspace:*")).toBeNull();
    expect(minVersionOfRange("<2.0.0")).toBeNull();
    expect(minVersionOfRange("")).toBeNull();
  });
});

describe("formatVersion", () => {
  test("round-trips a version, keeping the prerelease tag", () => {
    expect(formatVersion(version("1.2.3"))).toBe("1.2.3");
    expect(formatVersion(version("2.0.0-rc.1"))).toBe("2.0.0-rc.1");
    expect(formatVersion(version("7.5"))).toBe("7.5.0");
  });
});
