import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  type OutdatedEntry,
  baselineOf,
  parseBunOutdated,
  parseNpmOutdated,
  parseOutdated,
  parsePnpmOutdated,
  parseYarnOutdated,
} from "./package-manager.ts";

/** Reads one of the captured real outputs in `__fixtures__`. */
async function fixture(name: string): Promise<string> {
  return await Bun.file(join(import.meta.dir, "__fixtures__", name)).text();
}

/** Real `npm 10.9.8 outdated --json --long` with node_modules installed. */
const NPM = await fixture("npm-outdated.json");
/** The same command against a repository that has only a lockfile. */
const NPM_NOT_INSTALLED = await fixture("npm-outdated-not-installed.json");
/** Real `pnpm 10.32.1 outdated --json`. */
const PNPM = await fixture("pnpm-outdated.json");
/** Real `yarn 1.22.19 outdated --json`. */
const YARN = await fixture("yarn-outdated.ndjson");
/** Real `bun 1.3.13 outdated`, which has no JSON reporter. */
const BUN = await fixture("bun-outdated.txt");

/** Unwraps a parse, failing the test rather than the suite when it did not. */
function entriesOf(outcome: ReturnType<typeof parseNpmOutdated>): OutdatedEntry[] {
  if (!outcome.ok) throw new Error(outcome.error);
  return outcome.value;
}

describe("parseNpmOutdated", () => {
  test("reads every entry of real npm output", () => {
    expect(entriesOf(parseNpmOutdated(NPM))).toEqual([
      {
        name: "chalk",
        current: "4.1.2",
        wanted: "4.1.2",
        latest: "6.0.0",
        dependencyType: "dependencies",
        deprecated: false,
      },
      {
        name: "rimraf",
        current: "5.0.10",
        wanted: "5.0.10",
        latest: "6.1.3",
        dependencyType: "devDependencies",
        deprecated: false,
      },
      {
        name: "semver",
        current: "7.5.0",
        wanted: "7.5.0",
        latest: "7.8.5",
        dependencyType: "dependencies",
        deprecated: false,
      },
    ]);
  });

  test("a repository with no node_modules reports no installed version", () => {
    const chalk = entriesOf(parseNpmOutdated(NPM_NOT_INSTALLED)).find(
      (entry) => entry.name === "chalk",
    );
    expect(chalk?.current).toBeNull();
    expect(chalk?.wanted).toBe("4.1.2");
    expect(baselineOf(chalk as OutdatedEntry)).toEqual({ version: "4.1.2", source: "declared" });
  });

  test("collapses the array npm emits for a package outdated in several places", () => {
    const raw = JSON.stringify({
      chalk: [
        { current: "4.1.2", wanted: "4.1.2", latest: "6.0.0", type: "dependencies" },
        { current: "3.0.0", wanted: "3.0.0", latest: "6.0.0", type: "dependencies" },
      ],
    });
    expect(entriesOf(parseNpmOutdated(raw))).toHaveLength(1);
  });

  test("nothing outdated is an empty list, not a failure", () => {
    expect(entriesOf(parseNpmOutdated("{}"))).toEqual([]);
  });

  test("refuses output that is not JSON instead of throwing", () => {
    const outcome = parseNpmOutdated("npm ERR! code ENOTFOUND\n");
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error).toContain("npm outdated");
  });
});

describe("parsePnpmOutdated", () => {
  test("reads real pnpm output, including its deprecation flag", () => {
    const entries = entriesOf(parsePnpmOutdated(PNPM));
    expect(entries.map((entry) => entry.name)).toEqual(["chalk", "left-pad"]);
    expect(entries.find((entry) => entry.name === "left-pad")?.deprecated).toBe(true);
    expect(entries.find((entry) => entry.name === "chalk")).toEqual({
      name: "chalk",
      current: "4.1.2",
      wanted: "4.1.2",
      latest: "6.0.0",
      dependencyType: "dependencies",
      deprecated: false,
    });
  });
});

describe("parseYarnOutdated", () => {
  test("reads the table line out of yarn's newline-delimited JSON", () => {
    expect(entriesOf(parseYarnOutdated(YARN))).toEqual([
      {
        name: "chalk",
        current: "4.1.2",
        wanted: "4.1.2",
        latest: "6.0.0",
        dependencyType: "dependencies",
        deprecated: false,
      },
    ]);
  });

  test("yarn's error stream is not mistaken for a result", () => {
    const outcome = parseYarnOutdated(
      '{"type":"error","data":"No lockfile in this directory. Run `yarn install` to generate one."}\n',
    );
    expect(entriesOf(outcome)).toEqual([]);
  });

  test("refuses output that is not newline-delimited JSON", () => {
    const outcome = parseYarnOutdated("yarn outdated v1.22.19\nerror Command failed.\n");
    expect(outcome.ok).toBe(false);
  });
});

describe("parseBunOutdated", () => {
  test("reads bun's ASCII table, including the dependency-group suffix", () => {
    expect(entriesOf(parseBunOutdated(BUN))).toEqual([
      {
        name: "@biomejs/biome",
        current: "1.9.4",
        wanted: "1.9.4",
        latest: "2.5.14",
        dependencyType: "devDependencies",
        deprecated: false,
      },
      {
        name: "pdfkit",
        current: "0.18.0",
        wanted: "0.18.0",
        latest: "0.20.2",
        dependencyType: "dependencies",
        deprecated: false,
      },
      {
        name: "typescript",
        current: "5.9.3",
        wanted: "5.9.3",
        latest: "7.0.2",
        dependencyType: "devDependencies",
        deprecated: false,
      },
    ]);
  });

  test("a run with nothing outdated prints no table and yields no entries", () => {
    expect(entriesOf(parseBunOutdated("bun outdated v1.3.13 (bf2e2cec)\n"))).toEqual([]);
  });
});

describe("parseOutdated", () => {
  test("dispatches to the parser for the manager that ran", () => {
    expect(entriesOf(parseOutdated("npm", NPM))).toHaveLength(3);
    expect(entriesOf(parseOutdated("pnpm", PNPM))).toHaveLength(2);
    expect(entriesOf(parseOutdated("yarn", YARN))).toHaveLength(1);
    expect(entriesOf(parseOutdated("bun", BUN))).toHaveLength(3);
  });
});

describe("baselineOf", () => {
  test("prefers what is installed over what the range allows", () => {
    const entry = entriesOf(parseNpmOutdated(NPM))[0] as OutdatedEntry;
    expect(baselineOf(entry)).toEqual({ version: "4.1.2", source: "installed" });
  });

  test("returns null when there is nothing to measure from", () => {
    expect(
      baselineOf({
        name: "x",
        current: null,
        wanted: null,
        latest: "1.0.0",
        dependencyType: null,
        deprecated: false,
      }),
    ).toBeNull();
  });
});
