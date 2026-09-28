/**
 * Parsers for the four package managers' "what is out of date" commands.
 *
 * Each manager answers the same question in its own format — npm and pnpm in
 * JSON, yarn 1 in newline-delimited JSON, bun in an ASCII table — so each gets
 * its own parser and they all produce {@link OutdatedEntry}.
 */

import { z } from "zod";
import { type ParseOutcome, parseJsonWith, parsed, unparseable } from "./_parse-outcome.ts";

/** The package managers phase 1 knows how to interrogate. */
export type PackageManagerName = "npm" | "pnpm" | "yarn" | "bun";

/** One dependency that has a newer release, as the manager reported it. */
export interface OutdatedEntry {
  readonly name: string;
  /** The installed version; `null` when the manager could not see node_modules. */
  readonly current: string | null;
  /** The newest version the declared range allows. */
  readonly wanted: string | null;
  /** The newest version on the registry. */
  readonly latest: string | null;
  /** `dependencies`, `devDependencies`, ... as the manager labelled it. */
  readonly dependencyType: string | null;
  /** Only pnpm reports this; false everywhere else rather than unknown. */
  readonly deprecated: boolean;
}

/** Which version to measure the gap from, and whether it is what is installed. */
export interface OutdatedBaseline {
  readonly version: string;
  /** `installed` when the manager saw node_modules, `declared` when it did not. */
  readonly source: "installed" | "declared";
}

/**
 * The version an "N releases behind" statement should be measured from:
 * what is installed, or — when nothing is installed — what the manifest allows.
 */
export function baselineOf(entry: OutdatedEntry): OutdatedBaseline | null {
  if (entry.current !== null && entry.current !== "") {
    return { version: entry.current, source: "installed" };
  }
  if (entry.wanted !== null && entry.wanted !== "") {
    return { version: entry.wanted, source: "declared" };
  }
  return null;
}

/** Sorts entries by package name so two runs of the same repo diff cleanly. */
function byName(a: OutdatedEntry, b: OutdatedEntry): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/** One npm entry; `current` and `location` are absent when nothing is installed. */
const NpmEntrySchema = z.object({
  current: z.string().optional(),
  wanted: z.string().optional(),
  latest: z.string().optional(),
  type: z.string().optional(),
});

/**
 * `npm outdated --json` keys by package name. npm emits an array when the same
 * package is outdated in more than one place in the tree.
 */
const NpmOutdatedSchema = z.record(z.string(), z.union([NpmEntrySchema, z.array(NpmEntrySchema)]));

/** Parse `npm outdated --json --long` output. */
export function parseNpmOutdated(raw: string): ParseOutcome<OutdatedEntry[]> {
  const report = parseJsonWith(raw, NpmOutdatedSchema, "npm outdated");
  if (!report.ok) return report;
  const entries: OutdatedEntry[] = [];
  for (const [name, value] of Object.entries(report.value)) {
    // Several tree locations of one package collapse into one finding: the
    // reader upgrades the package, not the copy.
    const first = Array.isArray(value) ? value[0] : value;
    if (first === undefined) continue;
    entries.push({
      name,
      current: first.current ?? null,
      wanted: first.wanted ?? null,
      latest: first.latest ?? null,
      dependencyType: first.type ?? null,
      deprecated: false,
    });
  }
  return parsed(entries.sort(byName));
}

/** One pnpm entry; pnpm is the only manager that flags deprecation here. */
const PnpmEntrySchema = z.object({
  current: z.string().optional(),
  wanted: z.string().optional(),
  latest: z.string().optional(),
  dependencyType: z.string().optional(),
  isDeprecated: z.boolean().optional(),
});

const PnpmOutdatedSchema = z.record(z.string(), PnpmEntrySchema);

/** Parse `pnpm outdated --json` output. */
export function parsePnpmOutdated(raw: string): ParseOutcome<OutdatedEntry[]> {
  const report = parseJsonWith(raw, PnpmOutdatedSchema, "pnpm outdated");
  if (!report.ok) return report;
  const entries = Object.entries(report.value).map(([name, value]) => ({
    name,
    current: value.current ?? null,
    wanted: value.wanted ?? null,
    latest: value.latest ?? null,
    dependencyType: value.dependencyType ?? null,
    deprecated: value.isDeprecated ?? false,
  }));
  return parsed(entries.sort(byName));
}

/** yarn 1 streams one JSON object per line; the interesting one is the table. */
const YarnTableSchema = z.object({
  type: z.literal("table"),
  data: z.object({
    head: z.array(z.string()),
    body: z.array(z.array(z.string())),
  }),
});

/** Reads a labelled cell out of a yarn table row. */
function cell(head: readonly string[], row: readonly string[], column: string): string | null {
  const index = head.findIndex((name) => name.toLowerCase() === column.toLowerCase());
  if (index === -1) return null;
  const value = row[index];
  return value === undefined || value === "" ? null : value;
}

/**
 * Parse `yarn outdated --json` output (yarn 1). Lines that are not the table —
 * the colour legend, warnings — are ignored; a payload with no table at all is
 * an empty result, which is what yarn emits when nothing is outdated.
 */
export function parseYarnOutdated(raw: string): ParseOutcome<OutdatedEntry[]> {
  const entries: OutdatedEntry[] = [];
  let sawJsonLine = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "" || !trimmed.startsWith("{")) continue;
    let json: unknown;
    try {
      json = JSON.parse(trimmed);
    } catch {
      continue;
    }
    sawJsonLine = true;
    const table = YarnTableSchema.safeParse(json);
    if (!table.success) continue;
    const { head, body } = table.data.data;
    for (const row of body) {
      const name = cell(head, row, "Package");
      if (name === null) continue;
      entries.push({
        name,
        current: cell(head, row, "Current"),
        wanted: cell(head, row, "Wanted"),
        latest: cell(head, row, "Latest"),
        dependencyType: cell(head, row, "Package Type"),
        deprecated: false,
      });
    }
  }
  if (!sawJsonLine && raw.trim() !== "") {
    return unparseable("yarn outdated did not produce newline-delimited JSON");
  }
  return parsed(entries.sort(byName));
}

/** `(dev)`, `(peer)` and `(optional)` suffixes bun appends to a package name. */
const BUN_SCOPE_RE = /^(.*?)\s*\((dev|peer|optional)\)$/;

/** bun labels a column group rather than reporting a dependency type per row. */
function bunDependencyType(suffix: string | undefined): string | null {
  if (suffix === "dev") return "devDependencies";
  if (suffix === "peer") return "peerDependencies";
  if (suffix === "optional") return "optionalDependencies";
  return "dependencies";
}

/**
 * Parse `bun outdated` output. bun has no JSON reporter, so this reads the
 * ASCII table it prints: `| Package | Current | Update | Latest |`, where
 * `Update` is the newest version the declared range allows.
 */
export function parseBunOutdated(raw: string): ParseOutcome<OutdatedEntry[]> {
  const entries: OutdatedEntry[] = [];
  let sawHeader = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("|")) continue;
    const cells = trimmed
      .slice(1, trimmed.endsWith("|") ? -1 : undefined)
      .split("|")
      .map((value) => value.trim());
    if (cells.every((value) => /^-*$/.test(value))) continue;
    if (cells.length < 4) continue;
    const [rawName, current, update, latest] = cells;
    if (rawName === undefined || current === undefined) continue;
    if (rawName.toLowerCase() === "package") {
      sawHeader = true;
      continue;
    }
    const scoped = BUN_SCOPE_RE.exec(rawName);
    entries.push({
      name: (scoped?.[1] ?? rawName).trim(),
      current: current === "" ? null : current,
      wanted: update === undefined || update === "" ? null : update,
      latest: latest === undefined || latest === "" ? null : latest,
      dependencyType: bunDependencyType(scoped?.[2]),
      deprecated: false,
    });
  }
  if (!sawHeader && entries.length > 0) {
    return unparseable("bun outdated produced a table without a recognisable header");
  }
  return parsed(entries.sort(byName));
}

/** Parse the output of whichever manager ran. */
export function parseOutdated(
  manager: PackageManagerName,
  raw: string,
): ParseOutcome<OutdatedEntry[]> {
  switch (manager) {
    case "npm":
      return parseNpmOutdated(raw);
    case "pnpm":
      return parsePnpmOutdated(raw);
    case "yarn":
      return parseYarnOutdated(raw);
    case "bun":
      return parseBunOutdated(raw);
  }
}
