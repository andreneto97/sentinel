import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { toLines } from "../../profile/index.ts";
import {
  type ScanPackageJson,
  declaredDependencies,
  declaredInLockfile,
  manifestLineOf,
  overridePins,
  parsePackageJson,
} from "./package-manifest.ts";

/** The fixture repository the package-manager runner is tested against. */
const PM_DEMO = join(import.meta.dir, "../runners/__fixtures__/pm-demo");
const MANIFEST_RAW = await Bun.file(join(PM_DEMO, "package.json")).text();
/** A real npm lockfile (`lockfileVersion` 3), trimmed to the direct dependencies. */
const LOCK_RAW = await Bun.file(join(PM_DEMO, "package-lock.json")).text();

/** Parses the fixture manifest, failing the test rather than the suite. */
function manifest(raw: string = MANIFEST_RAW): ScanPackageJson {
  const parsed = parsePackageJson(raw);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

describe("parsePackageJson", () => {
  test("reads the fixture manifest", () => {
    expect(manifest().name).toBe("outdated-demo");
  });

  test("refuses a manifest that is not JSON instead of throwing", () => {
    const parsed = parsePackageJson("{ not json ]");
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error).toContain("package.json did not produce valid JSON");
  });

  test("ignores fields it does not model", () => {
    const parsed = parsePackageJson('{"name":"x","exports":{".":"./index.js"}}');
    expect(parsed.ok).toBe(true);
  });
});

describe("declaredDependencies", () => {
  test("collects the sections a package declares for itself", () => {
    expect(declaredDependencies(manifest())).toEqual([
      { name: "chalk", range: "^4.0.0", section: "dependencies" },
      { name: "dayjs", range: "^1.11.0", section: "dependencies" },
      { name: "left-pad", range: "^1.3.0", section: "dependencies" },
      { name: "semver", range: "7.5.0", section: "dependencies" },
      { name: "rimraf", range: "^5.0.0", section: "devDependencies" },
    ]);
  });

  test("peer dependencies are somebody else's install, so they are not declared here", () => {
    const peers = manifest('{"peerDependencies":{"react":"^18.0.0"}}');
    expect(declaredDependencies(peers)).toEqual([]);
  });
});

describe("overridePins", () => {
  test("reads npm overrides out of the fixture", () => {
    expect(overridePins(manifest())).toEqual([
      { section: "overrides", path: "semver", name: "semver", spec: "7.3.8" },
      {
        section: "overrides",
        path: "brace-expansion",
        name: "brace-expansion",
        spec: "2.0.1",
      },
    ]);
  });

  test("flattens a nested npm override, resolving the `.` self-key", () => {
    const nested = manifest('{"overrides":{"foo":{".":"1.0.0","bar":"2.0.0"}}}');
    expect(overridePins(nested)).toEqual([
      { section: "overrides", path: "foo > .", name: "foo", spec: "1.0.0" },
      { section: "overrides", path: "foo > bar", name: "bar", spec: "2.0.0" },
    ]);
  });

  test("strips the version selector pnpm allows on an override key", () => {
    const pnpm = manifest('{"pnpm":{"overrides":{"minimist@<1.2.6":"1.2.6"}}}');
    expect(overridePins(pnpm)).toEqual([
      {
        section: "pnpm.overrides",
        path: "minimist@<1.2.6",
        name: "minimist",
        spec: "1.2.6",
      },
    ]);
  });

  test("keeps a scoped package name intact", () => {
    const scoped = manifest('{"resolutions":{"@scope/pkg":"1.0.0"}}');
    expect(overridePins(scoped)[0]?.name).toBe("@scope/pkg");
  });
});

describe("manifestLineOf", () => {
  const lines = toLines(MANIFEST_RAW);

  test("finds a dependency inside its own section", () => {
    expect(manifestLineOf(lines, "dependencies", "chalk")).toBe(6);
    expect(manifestLineOf(lines, "devDependencies", "rimraf")).toBe(12);
    expect(manifestLineOf(lines, "overrides", "brace-expansion")).toBe(16);
  });

  test("a name in two sections cites the one that was asked for", () => {
    expect(manifestLineOf(lines, "dependencies", "semver")).toBe(9);
    expect(manifestLineOf(lines, "overrides", "semver")).toBe(15);
  });

  test("falls back to line 1 rather than citing nothing", () => {
    expect(manifestLineOf(lines, "dependencies", "not-declared")).toBe(1);
  });
});

describe("declaredInLockfile", () => {
  test("finds a dependency in a real npm lockfile", () => {
    expect(declaredInLockfile("npm-json", LOCK_RAW, "chalk")).toBe("present");
    expect(declaredInLockfile("npm-json", LOCK_RAW, "semver")).toBe("present");
  });

  test("a v2+ lockfile lists everything, so an absence is meaningful", () => {
    expect(declaredInLockfile("npm-json", LOCK_RAW, "dayjs")).toBe("absent");
  });

  test("says it does not know rather than guessing at an unreadable lockfile", () => {
    expect(declaredInLockfile("npm-json", "not json", "chalk")).toBe("unknown");
    expect(declaredInLockfile("binary", String.fromCharCode(0, 1), "chalk")).toBe("unknown");
  });

  test("reads a yarn lockfile by name", () => {
    const yarnLock = ["chalk@^4.0.0:", '  version "4.1.2"', "", '"@scope/pkg@^1.0.0":'].join("\n");
    expect(declaredInLockfile("yarn-v1", yarnLock, "chalk")).toBe("present");
    expect(declaredInLockfile("yarn-v1", yarnLock, "@scope/pkg")).toBe("present");
    expect(declaredInLockfile("yarn-v1", yarnLock, "dayjs")).toBe("absent");
  });

  test("reads a pnpm lockfile by name", () => {
    const pnpmLock = ["dependencies:", "  chalk:", "    specifier: ^4.0.0"].join("\n");
    expect(declaredInLockfile("pnpm-yaml", pnpmLock, "chalk")).toBe("present");
    expect(declaredInLockfile("pnpm-yaml", pnpmLock, "dayjs")).toBe("absent");
  });
});
