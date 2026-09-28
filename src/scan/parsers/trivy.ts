/**
 * Normalisation of trivy's three payloads into `Finding`s: the vulnerability
 * report (`trivy fs --format json`), the CycloneDX SBOM (`--format cyclonedx`)
 * and the misconfiguration report (`trivy config --format json`).
 *
 * Every schema here describes untrusted tool output, so a payload that does not
 * match comes back as a typed error instead of throwing. Nothing in this module
 * touches the disk: a finding's `snippet` is extracted later by `src/verify`,
 * never copied out of trivy's own `Code.Lines`.
 */

import { z } from "zod";
import type { CodeRef, Finding, Severity } from "../../contracts/findings.ts";
import { type ParsedVersion, compareVersions, parseVersion } from "./_semver-lite.ts";

/** Dotted, stable rule ids for everything trivy can tell us about dependencies. */
export const TRIVY_RULES = {
  vulnerablePackage: "dependencies.vulnerable-package",
  copyleftLicense: "dependencies.copyleft-license",
  unknownLicense: "dependencies.unknown-license",
} as const;

/** `trivy config` result type -> the delivery rule it becomes. */
export const MISCONFIG_RULES: Readonly<Record<string, string>> = {
  dockerfile: "delivery.dockerfile-misconfig",
  "docker-compose": "delivery.compose-misconfig",
  kubernetes: "delivery.kubernetes-misconfig",
  helm: "delivery.helm-misconfig",
  terraform: "delivery.terraform-misconfig",
  terraformplan: "delivery.terraform-misconfig",
  "terraformplan-json": "delivery.terraform-misconfig",
  "terraformplan-snapshot": "delivery.terraform-misconfig",
  cloudformation: "delivery.cloudformation-misconfig",
  "azure-arm": "delivery.azure-arm-misconfig",
  ansible: "delivery.ansible-misconfig",
};

/** Rule for a config type trivy grew after this file was written. */
export const DEFAULT_MISCONFIG_RULE = "delivery.config-misconfig";

/** The tool name every finding from this module is attributed to. */
const SOURCE = { kind: "tool", name: "trivy" } as const;

/** Longest description text kept from a trivy payload, in characters. */
const MAX_TEXT = 420;

/** Most packages named in the aggregated unknown-licence finding. */
const MAX_UNKNOWN_LISTED = 20;

/** Most evidence refs attached to one misconfiguration. */
const MAX_OCCURRENCES = 5;

// ---------------------------------------------------------------------------
// Schemas — trivy's JSON is external input and is validated, never trusted.
// ---------------------------------------------------------------------------

const TrivyLocationSchema = z.object({
  StartLine: z.number().int().optional(),
  EndLine: z.number().int().optional(),
});

const TrivyPackageSchema = z.object({
  ID: z.string().optional(),
  Name: z.string(),
  Version: z.string().optional(),
  /** "root" | "direct" | "indirect" | "workspace" | "unknown" in trivy 0.74. */
  Relationship: z.string().optional(),
  Indirect: z.boolean().optional(),
  Dev: z.boolean().optional(),
  DependsOn: z.array(z.string()).optional(),
  Locations: z.array(TrivyLocationSchema).optional(),
  FilePath: z.string().optional(),
});
/** One package trivy resolved from a lockfile or manifest. */
export type TrivyPackage = z.infer<typeof TrivyPackageSchema>;

const TrivyCvssSchema = z.object({
  V2Vector: z.string().optional(),
  V3Vector: z.string().optional(),
  V40Vector: z.string().optional(),
  V2Score: z.number().optional(),
  V3Score: z.number().optional(),
  V40Score: z.number().optional(),
});

const TrivyVulnerabilitySchema = z.object({
  VulnerabilityID: z.string(),
  PkgID: z.string().optional(),
  PkgName: z.string(),
  /** Set when the package came from a file other than the result target. */
  PkgPath: z.string().optional(),
  InstalledVersion: z.string().optional(),
  FixedVersion: z.string().optional(),
  /** "fixed" | "affected" | "will_not_fix" | "fix_deferred" | "end_of_life". */
  Status: z.string().optional(),
  Title: z.string().optional(),
  Description: z.string().optional(),
  Severity: z.string().optional(),
  SeveritySource: z.string().optional(),
  CweIDs: z.array(z.string()).optional(),
  CVSS: z.record(z.string(), TrivyCvssSchema).optional(),
  PrimaryURL: z.string().optional(),
  References: z.array(z.string()).optional(),
});
/** One vulnerability trivy matched against an installed package version. */
export type TrivyVulnerability = z.infer<typeof TrivyVulnerabilitySchema>;

const TrivyOccurrenceSchema = z.object({
  Resource: z.string().optional(),
  Filename: z.string().optional(),
  Location: TrivyLocationSchema.optional(),
});

const TrivyCauseMetadataSchema = z.object({
  Resource: z.string().optional(),
  Provider: z.string().optional(),
  Service: z.string().optional(),
  StartLine: z.number().int().optional(),
  EndLine: z.number().int().optional(),
  Occurrences: z.array(TrivyOccurrenceSchema).optional(),
});

const TrivyMisconfigurationSchema = z.object({
  Type: z.string().optional(),
  ID: z.string(),
  AVDID: z.string().optional(),
  Title: z.string().optional(),
  Description: z.string().optional(),
  Message: z.string().optional(),
  Resolution: z.string().optional(),
  Severity: z.string().optional(),
  PrimaryURL: z.string().optional(),
  References: z.array(z.string()).optional(),
  /** "FAIL" | "PASS" | "EXCEPTION"; only failures become findings. */
  Status: z.string().optional(),
  /** Present on a few checks only; never synthesised when trivy omits it. */
  CweIDs: z.array(z.string()).optional(),
  CauseMetadata: TrivyCauseMetadataSchema.optional(),
});
/** One failing configuration check. */
export type TrivyMisconfiguration = z.infer<typeof TrivyMisconfigurationSchema>;

const TrivyResultSchema = z.object({
  /** The real path trivy scanned, e.g. `apps/api/package-lock.json`. */
  Target: z.string(),
  Class: z.string().optional(),
  /** Ecosystem for `lang-pkgs` ("npm"), config kind for `config` ("dockerfile"). */
  Type: z.string().optional(),
  Packages: z.array(TrivyPackageSchema).optional(),
  Vulnerabilities: z.array(TrivyVulnerabilitySchema).nullable().optional(),
  Misconfigurations: z.array(TrivyMisconfigurationSchema).nullable().optional(),
});
/** One scanned target inside a trivy report. */
export type TrivyResult = z.infer<typeof TrivyResultSchema>;

/** The envelope shared by `trivy fs --format json` and `trivy config --format json`. */
export const TrivyReportSchema = z.object({
  SchemaVersion: z.number().int().optional(),
  ArtifactName: z.string().optional(),
  ArtifactType: z.string().optional(),
  /** Absent — not empty — when trivy found nothing to scan. */
  Results: z.array(TrivyResultSchema).nullable().optional(),
});
/** A parsed trivy JSON report. */
export type TrivyReport = z.infer<typeof TrivyReportSchema>;

const CycloneDxLicenseSchema = z.object({
  license: z.object({ id: z.string().optional(), name: z.string().optional() }).optional(),
  /** SPDX expression form, e.g. "MIT OR LGPL-2.1-or-later". */
  expression: z.string().optional(),
});

const CycloneDxPropertySchema = z.object({ name: z.string(), value: z.string().optional() });

const CycloneDxComponentSchema = z.object({
  "bom-ref": z.string().optional(),
  type: z.string().optional(),
  name: z.string(),
  /** The npm scope, which CycloneDX keeps out of `name`; see {@link componentName}. */
  group: z.string().optional(),
  version: z.string().optional(),
  purl: z.string().optional(),
  licenses: z.array(CycloneDxLicenseSchema).optional(),
  properties: z.array(CycloneDxPropertySchema).optional(),
});
/** One SBOM component: a library, or the file trivy read it from. */
export type CycloneDxComponent = z.infer<typeof CycloneDxComponentSchema>;

/** The CycloneDX document trivy writes for `--format cyclonedx`. */
export const TrivySbomSchema = z.object({
  bomFormat: z.string().optional(),
  specVersion: z.string().optional(),
  metadata: z.object({ component: CycloneDxComponentSchema.optional() }).optional(),
  components: z.array(CycloneDxComponentSchema).nullable().optional(),
  dependencies: z
    .array(z.object({ ref: z.string(), dependsOn: z.array(z.string()).optional() }))
    .nullable()
    .optional(),
});
/** A parsed CycloneDX SBOM. */
export type TrivySbom = z.infer<typeof TrivySbomSchema>;

/** The outcome of parsing an untrusted payload; parsing never throws. */
export type TrivyParse<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

/** Turns a Zod failure into one line a run report can print. */
function describeIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 3)
    .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
    .join("; ");
}

/** Validates any JSON payload against a schema, degrading to a message on failure. */
function parsePayload<T>(raw: string, schema: z.ZodType<T>, what: string): TrivyParse<T> {
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return { ok: false, error: `${what} is not valid JSON: ${detail}` };
  }
  const result = schema.safeParse(json);
  if (!result.success) {
    return {
      ok: false,
      error: `${what} does not match trivy's shape: ${describeIssues(result.error)}`,
    };
  }
  return { ok: true, value: result.data };
}

/** Parses a `trivy fs`/`trivy config` JSON report. */
export function parseTrivyReport(raw: string): TrivyParse<TrivyReport> {
  return parsePayload(raw, TrivyReportSchema, "trivy JSON report");
}

/** Parses a `trivy fs --format cyclonedx` SBOM. */
export function parseTrivySbom(raw: string): TrivyParse<TrivySbom> {
  return parsePayload(raw, TrivySbomSchema, "trivy CycloneDX SBOM");
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const SEVERITY_BY_TRIVY: Readonly<Record<string, Severity>> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
  NONE: "info",
};

/** Maps trivy's severity word onto Sentinel's scale; anything unknown is `info`. */
export function trivySeverity(raw: string | undefined): Severity {
  return SEVERITY_BY_TRIVY[(raw ?? "UNKNOWN").toUpperCase()] ?? "info";
}

/** A `CodeRef` line is 1-based and positive; trivy omits or zeroes it for file-level checks. */
function positiveLine(value: number | undefined): number {
  return value !== undefined && Number.isInteger(value) && value > 0 ? value : 1;
}

/** Collapses whitespace and caps length, so a PDF table cell stays a cell. */
function tidy(value: string | undefined, max = MAX_TEXT): string {
  const text = (value ?? "").replace(/\s+/g, " ").trim();
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

/** Stable across runs: hash of (domain, rule, file, symbol), per the finding contract. */
function stableId(domain: string, rule: string, file: string, symbol: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update([domain, rule, file, symbol].join("\u0000"));
  return hasher.digest("hex").slice(0, 16);
}

/** Builds a `CodeRef` with the optional fields only when they carry information. */
function codeRef(file: string, line: number, endLine?: number, note?: string): CodeRef {
  return {
    file,
    line,
    ...(endLine !== undefined && endLine > line ? { endLine } : {}),
    ...(note !== undefined && note !== "" ? { note } : {}),
  };
}

// ---------------------------------------------------------------------------
// D1 — vulnerable dependencies
// ---------------------------------------------------------------------------

/** The dependency names a package manifest declares, split by section. */
export interface ManifestDependencies {
  /** `dependencies` plus `optionalDependencies`: shipped to production. */
  readonly runtime: ReadonlySet<string>;
  /** `devDependencies`: present at build time only. */
  readonly dev: ReadonlySet<string>;
}

/** What the runner knows that trivy does not: the manifests behind each scanned target. */
export interface DependencyContext {
  /**
   * Declared dependency names keyed by the target trivy reported
   * (`package-lock.json`, `apps/api/yarn.lock`, …). Absent entries fall back to
   * trivy's own `Relationship`.
   */
  readonly manifests?: ReadonlyMap<string, ManifestDependencies> | undefined;
}

/** How a vulnerable package got into the tree. */
type Directness = "direct" | "direct-dev" | "transitive" | "unknown";

/** The sentence the report prints for each kind of dependency edge. */
const DIRECTNESS_LABEL: Readonly<Record<Directness, string>> = {
  direct: "Direct dependency: it is declared in the project's own manifest.",
  "direct-dev":
    "Direct dev dependency: declared in `devDependencies`, so it ships only if the build does.",
  transitive: "Transitive dependency: nothing in the project declares it directly.",
  unknown:
    "Trivy did not report whether this package is declared directly or pulled in transitively.",
};

/** Package graph of one scanned target, indexed the two ways the normaliser needs. */
interface PackageGraph {
  readonly byId: ReadonlyMap<string, TrivyPackage>;
  /** package id -> the packages that depend on it. */
  readonly parents: ReadonlyMap<string, readonly string[]>;
}

/** The id trivy uses in `DependsOn`, falling back to `name@version`. */
function packageId(pkg: TrivyPackage): string {
  return pkg.ID ?? `${pkg.Name}@${pkg.Version ?? ""}`;
}

/** Indexes a result's packages and inverts its dependency edges. */
function buildGraph(packages: readonly TrivyPackage[]): PackageGraph {
  const byId = new Map<string, TrivyPackage>();
  const parents = new Map<string, string[]>();
  for (const pkg of packages) byId.set(packageId(pkg), pkg);
  for (const pkg of packages) {
    const from = packageId(pkg);
    for (const child of pkg.DependsOn ?? []) {
      const existing = parents.get(child);
      if (existing === undefined) parents.set(child, [from]);
      else existing.push(from);
    }
  }
  return { byId, parents };
}

/** True when trivy itself calls this package a top-level one. */
function trivySaysDirect(pkg: TrivyPackage | undefined): boolean {
  const relationship = pkg?.Relationship?.toLowerCase();
  return relationship === "direct" || relationship === "root" || relationship === "workspace";
}

/**
 * Shortest chain from a directly declared package down to the vulnerable one,
 * e.g. `express@4.17.1 → body-parser@1.19.0 → qs@6.7.0`. Returns null when
 * trivy gave no edges to walk.
 */
function dependencyPath(
  graph: PackageGraph,
  target: string,
  isDirect: (id: string) => boolean,
): string[] | null {
  if (isDirect(target)) return [target];
  const seen = new Set<string>([target]);
  let frontier: Array<readonly string[]> = [[target]];
  // Breadth-first so the shortest explanation wins; the tree is small per target.
  for (let depth = 0; depth < 24 && frontier.length > 0; depth += 1) {
    const next: Array<readonly string[]> = [];
    for (const chain of frontier) {
      const head = chain[0];
      if (head === undefined) continue;
      for (const parent of graph.parents.get(head) ?? []) {
        if (seen.has(parent)) continue;
        seen.add(parent);
        const extended = [parent, ...chain];
        if (isDirect(parent)) return extended;
        next.push(extended);
      }
    }
    frontier = next;
  }
  return null;
}

/** Where a package is written down inside its lockfile, when trivy located it. */
function packageRef(file: string, pkg: TrivyPackage | undefined, note?: string): CodeRef {
  const location = pkg?.Locations?.[0];
  return codeRef(file, positiveLine(location?.StartLine), location?.EndLine, note);
}

/** The CVSS score and vector trivy carries, preferring nvd then ghsa. */
function cvssSummary(vulnerability: TrivyVulnerability): string | null {
  const table = vulnerability.CVSS;
  if (table === undefined) return null;
  const order = ["nvd", "ghsa", ...Object.keys(table)];
  for (const source of order) {
    const entry = table[source];
    if (entry === undefined) continue;
    const score = entry.V40Score ?? entry.V3Score ?? entry.V2Score;
    const vector = entry.V40Vector ?? entry.V3Vector ?? entry.V2Vector;
    if (score === undefined && vector === undefined) continue;
    const parts = [score === undefined ? null : `CVSS ${score}`, vector ?? null].filter(
      (part): part is string => part !== null,
    );
    return `${parts.join(" ")} (${source})`;
  }
  return null;
}

/**
 * The one fixed version that applies to the release line in use.
 *
 * `FixedVersion` is a comma-separated list whenever the advisory was patched on
 * several lines — for CVE-2022-24999 trivy lists nine. Repeating all nine turns
 * the recommendation into "pin qs to 6.10.3, 6.9.7, 6.8.3, …", which is not an
 * instruction anybody can follow. The lowest published fix above the installed
 * version is the smallest move that clears the advisory, so that is the one to
 * name; the full list stays in trivy's untouched report under `raw/`.
 */
export function applicableFix(fixedVersion: string, installedVersion?: string): string {
  const listed = fixedVersion
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  if (listed.length <= 1) return listed[0] ?? fixedVersion.trim();

  const parsed = listed
    .flatMap((raw) => {
      const version = parseVersion(raw);
      return version === null ? [] : [{ raw, version }];
    })
    .sort((left, right) => compareVersions(left.version, right.version));
  const newest = parsed[parsed.length - 1];
  if (newest === undefined) return listed[0] ?? fixedVersion.trim();

  const installed: ParsedVersion | null =
    installedVersion === undefined ? null : parseVersion(installedVersion);
  // Without a parseable installed version there is no line to stay on, so the
  // newest fix is the only one that is certainly not behind.
  if (installed === null) return newest.raw;
  return (parsed.find((entry) => compareVersions(entry.version, installed) > 0) ?? newest).raw;
}

/** Ends a borrowed sentence so the next one does not run into it. */
function asSentence(text: string): string {
  return text === "" || /[.!?]$/.test(text) ? text : `${text}.`;
}

/** What an attacker needs and what a maintainer can do about it, in trivy's own facts. */
function exploitabilityOf(vulnerability: TrivyVulnerability): string {
  const parts: string[] = [];
  if (vulnerability.FixedVersion !== undefined && vulnerability.FixedVersion !== "") {
    const fix = applicableFix(vulnerability.FixedVersion, vulnerability.InstalledVersion);
    const alsoListed = fix !== vulnerability.FixedVersion.trim();
    parts.push(
      `A fixed version exists: ${fix}${alsoListed ? " (the advisory also lists fixes on other release lines)" : ""}.`,
    );
  } else {
    const status = vulnerability.Status ?? "unknown";
    parts.push(`No fixed version is published (trivy status: ${status}).`);
  }
  const cvss = cvssSummary(vulnerability);
  if (cvss !== null) parts.push(`${cvss}.`);
  parts.push(
    "Reachability was not verified: the match is on the installed version, not on a call site.",
  );
  return parts.join(" ");
}

/** Upgrade advice that differs for a package nobody declared. */
function recommendationOf(vulnerability: TrivyVulnerability, directness: Directness): string {
  const name = vulnerability.PkgName;
  const declared = vulnerability.FixedVersion;
  if (declared === undefined || declared === "") {
    return `No fix is published for ${vulnerability.VulnerabilityID}. Assess whether ${name} is reachable from a request path and, if it is, replace it or pin it behind a wrapper you control.`;
  }
  const fix = applicableFix(declared, vulnerability.InstalledVersion);
  if (directness === "transitive") {
    return `Upgrade the dependency that pulls ${name} in so it resolves to ${fix} or later; if its maintainer has not released one, pin ${name} to ${fix} with an npm \`overrides\` (or yarn/pnpm \`resolutions\`) entry and record why.`;
  }
  return `Upgrade ${name} to ${fix} or later and re-run the lockfile install so the pin is committed.`;
}

/** Decides, from the manifest first and trivy second, how the package got here. */
function directnessOf(
  vulnerability: TrivyVulnerability,
  pkg: TrivyPackage | undefined,
  manifest: ManifestDependencies | undefined,
): Directness {
  if (manifest !== undefined) {
    if (manifest.runtime.has(vulnerability.PkgName)) return "direct";
    if (manifest.dev.has(vulnerability.PkgName)) return "direct-dev";
    if (pkg !== undefined || manifest.runtime.size + manifest.dev.size > 0) return "transitive";
  }
  if (trivySaysDirect(pkg)) return pkg?.Dev === true ? "direct-dev" : "direct";
  if (pkg?.Indirect === true || pkg?.Relationship?.toLowerCase() === "indirect")
    return "transitive";
  return "unknown";
}

/**
 * One finding per (package, vulnerability), located in the manifest trivy
 * actually read and carrying the chain that pulls the package in.
 */
export function vulnerabilityFindings(
  report: TrivyReport,
  context: DependencyContext = {},
): Finding[] {
  const findings: Finding[] = [];
  for (const result of report.Results ?? []) {
    const vulnerabilities = result.Vulnerabilities ?? [];
    if (vulnerabilities.length === 0) continue;
    const graph = buildGraph(result.Packages ?? []);
    const manifest = context.manifests?.get(result.Target);

    for (const vulnerability of vulnerabilities) {
      const pkg =
        (vulnerability.PkgID === undefined ? undefined : graph.byId.get(vulnerability.PkgID)) ??
        graph.byId.get(`${vulnerability.PkgName}@${vulnerability.InstalledVersion ?? ""}`);
      // The manifest trivy reports, never a hardcoded lockfile name.
      const file = vulnerability.PkgPath ?? result.Target;
      const installed = vulnerability.InstalledVersion ?? pkg?.Version ?? "unknown";
      const coordinates = `${vulnerability.PkgName}@${installed}`;
      const directness = directnessOf(vulnerability, pkg, manifest);

      const isDirect = (id: string): boolean => {
        const candidate = graph.byId.get(id);
        if (candidate === undefined) return false;
        if (manifest !== undefined) {
          if (manifest.runtime.has(candidate.Name) || manifest.dev.has(candidate.Name)) return true;
        }
        return trivySaysDirect(candidate);
      };
      const chain =
        directness === "transitive" && pkg !== undefined
          ? dependencyPath(graph, packageId(pkg), isDirect)
          : null;
      const pathSentence =
        chain !== null && chain.length > 1 ? ` Pulled in by ${chain.join(" → ")}.` : "";

      const evidence: CodeRef[] = [];
      const introducedBy = chain === null ? undefined : graph.byId.get(chain[0] ?? "");
      if (
        introducedBy !== undefined &&
        packageId(introducedBy) !== packageId(pkg ?? introducedBy)
      ) {
        evidence.push(packageRef(file, introducedBy, `introduces ${coordinates}`));
      }

      const headline = tidy(vulnerability.Title) || tidy(vulnerability.Description, 160);
      findings.push({
        id: stableId(
          "dependencies",
          TRIVY_RULES.vulnerablePackage,
          file,
          `${coordinates}:${vulnerability.VulnerabilityID}`,
        ),
        domain: "dependencies",
        rule: TRIVY_RULES.vulnerablePackage,
        severity: trivySeverity(vulnerability.Severity),
        confidence: "high",
        title: `${vulnerability.VulnerabilityID} in ${coordinates}`,
        description:
          `${asSentence(headline) || `${vulnerability.VulnerabilityID} affects ${coordinates}.`} ${DIRECTNESS_LABEL[directness]}${pathSentence}`.trim(),
        location: packageRef(file, pkg, `${directness} dependency`),
        evidence,
        exploitability: exploitabilityOf(vulnerability),
        impact: `${coordinates} is resolved by ${file}; the advisory rates ${vulnerability.VulnerabilityID} ${(vulnerability.Severity ?? "UNKNOWN").toUpperCase()}${vulnerability.SeveritySource === undefined ? "" : ` (source: ${vulnerability.SeveritySource})`}.`,
        recommendation: recommendationOf(vulnerability, directness),
        acceptanceCriteria: [
          vulnerability.FixedVersion === undefined || vulnerability.FixedVersion === ""
            ? `A decision on ${vulnerability.VulnerabilityID} is recorded (replace ${vulnerability.PkgName}, or accept the risk with a dated note)`
            : `\`${file}\` resolves ${vulnerability.PkgName} to ${applicableFix(vulnerability.FixedVersion, vulnerability.InstalledVersion)} or later`,
          `\`trivy fs\` no longer reports ${vulnerability.VulnerabilityID} for this repository`,
        ],
        cwe: vulnerability.CweIDs ?? [],
        owasp: [],
        source: SOURCE,
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// D1 — licence inventory, mined from the SBOM
// ---------------------------------------------------------------------------

/** A package's location inside the manifest that resolved it. */
export interface PackageLocation {
  readonly file: string;
  readonly line: number;
  readonly endLine?: number | undefined;
}

/**
 * Indexes where each package is written down, keyed by `name@version` and by
 * trivy's package id, so the SBOM's components can be placed on a real line.
 */
export function packageLocations(report: TrivyReport): Map<string, PackageLocation> {
  const index = new Map<string, PackageLocation>();
  for (const result of report.Results ?? []) {
    for (const pkg of result.Packages ?? []) {
      const location = pkg.Locations?.[0];
      const entry: PackageLocation = {
        file: pkg.FilePath ?? result.Target,
        line: positiveLine(location?.StartLine),
        ...(location?.EndLine === undefined ? {} : { endLine: location.EndLine }),
      };
      index.set(`${pkg.Name}@${pkg.Version ?? ""}`, entry);
      if (pkg.ID !== undefined) index.set(pkg.ID, entry);
    }
  }
  return index;
}

/** Copyleft families Sentinel flags, in the order they are tested. */
const COPYLEFT_PATTERNS: ReadonlyArray<{
  readonly family: string;
  readonly pattern: RegExp;
  readonly severity: Severity;
  readonly note: string;
}> = [
  {
    family: "AGPL",
    pattern: /\bAGPL\b|\bAGPL-[\d.]+/i,
    severity: "low",
    note: "network copyleft: serving the software over a network counts as distribution, so the source of your service may have to be offered to its users",
  },
  {
    family: "GPL",
    pattern: /(?<![AL])\bGPL\b|(?<![AL])GPL-[\d.]+/i,
    severity: "low",
    note: "strong copyleft: distributing a work that links this code can oblige you to release that work under the GPL as well",
  },
  {
    family: "LGPL",
    pattern: /\bLGPL\b|\bLGPL-[\d.]+/i,
    severity: "info",
    note: "weak copyleft: dynamic linking is normally fine, but modifications to the library itself must be published",
  },
];

/**
 * The package name a reader can act on.
 *
 * CycloneDX keeps an npm scope in `group`, so trivy's SBOM splits
 * `@img/sharp-libvips-darwin-arm64` into group `@img` and name
 * `sharp-libvips-darwin-arm64`. Reporting the bare half names a package that
 * does not exist — nobody can find it in the lockfile or `npm why` it — and it
 * also fails to match trivy's *own* vulnerability report, which uses the
 * qualified name, so the finding loses the line the package is declared on.
 */
export function componentName(component: CycloneDxComponent): string {
  const group = component.group?.trim();
  return group === undefined || group === "" ? component.name : `${group}/${component.name}`;
}

/** Every licence string a component declares, id or SPDX expression alike. */
function licensesOf(component: CycloneDxComponent): string[] {
  const values: string[] = [];
  for (const entry of component.licenses ?? []) {
    const value = entry.expression ?? entry.license?.id ?? entry.license?.name;
    if (value !== undefined && value.trim() !== "") values.push(value.trim());
  }
  return values;
}

/** True when a dual licence offers a permissive alternative to the copyleft one. */
function hasPermissiveAlternative(expression: string): boolean {
  return /\bOR\b/i.test(expression) && /\b(MIT|BSD|Apache|ISC|Zlib|Unlicense)\b/i.test(expression);
}

/** The single `lang-pkgs` file component, used when no package location is known. */
function fallbackFile(sbom: TrivySbom): string | null {
  const applications = (sbom.components ?? []).filter(
    (component) =>
      component.type === "application" &&
      (component.properties ?? []).some(
        (property) =>
          property.name === "aquasecurity:trivy:Class" && property.value === "lang-pkgs",
      ),
  );
  return applications.length === 1 ? (applications[0]?.name ?? null) : null;
}

/**
 * Turns the SBOM into a licence inventory: one finding per copyleft component
 * and one aggregated finding for everything trivy could not attribute a licence
 * to. Components are placed on the line the vulnerability report located them
 * at, so the citation resolves like any other.
 */
export function licenseFindings(
  sbom: TrivySbom,
  locations: ReadonlyMap<string, PackageLocation> = new Map(),
): Finding[] {
  const findings: Finding[] = [];
  const unknown: string[] = [];
  const libraries = (sbom.components ?? []).filter((component) => component.type === "library");
  const fallback = fallbackFile(sbom);

  const refFor = (component: CycloneDxComponent): CodeRef | null => {
    const key = `${componentName(component)}@${component.version ?? ""}`;
    const located =
      locations.get(key) ??
      (component.purl === undefined ? undefined : locations.get(component.purl));
    if (located !== undefined) return codeRef(located.file, located.line, located.endLine);
    return fallback === null ? null : codeRef(fallback, 1);
  };

  for (const component of libraries) {
    const coordinates = `${componentName(component)}@${component.version ?? "unknown"}`;
    const declared = licensesOf(component);
    if (declared.length === 0) {
      unknown.push(coordinates);
      continue;
    }
    const expression = declared.join(" AND ");
    const match = COPYLEFT_PATTERNS.find((candidate) => candidate.pattern.test(expression));
    if (match === undefined) continue;
    const location = refFor(component);
    if (location === null) continue;

    const permissive = hasPermissiveAlternative(expression);
    findings.push({
      id: stableId("dependencies", TRIVY_RULES.copyleftLicense, location.file, coordinates),
      domain: "dependencies",
      rule: TRIVY_RULES.copyleftLicense,
      severity: permissive ? "info" : match.severity,
      confidence: "high",
      title: `${coordinates} is licensed ${expression}`,
      description: `The SBOM records ${coordinates} under \`${expression}\` — ${match.family}, ${match.note}.${permissive ? " The expression also offers a permissive alternative, so the copyleft terms are avoidable by choosing it explicitly." : ""}`,
      location,
      evidence: [],
      exploitability:
        "Not an attack path: this is a distribution obligation that applies when the software is shipped or served.",
      impact: `Shipping this build carries the ${match.family} obligations of ${coordinates}.`,
      recommendation: permissive
        ? `Record which arm of \`${expression}\` this project relies on, so the obligation is a decision rather than an accident.`
        : `Confirm with whoever owns licensing that ${match.family} terms are acceptable for this product; otherwise replace ${componentName(component)} or isolate it behind a service boundary.`,
      acceptanceCriteria: [
        `The licence of ${coordinates} is listed in the project's licence inventory with an owner and a decision`,
      ],
      cwe: [],
      owasp: [],
      source: SOURCE,
    });
  }

  if (unknown.length > 0) {
    const anchor =
      fallback === null ? null : codeRef(fallback, 1, undefined, "licence inventory anchor");
    const first = libraries.find((component) =>
      unknown.includes(`${componentName(component)}@${component.version ?? "unknown"}`),
    );
    const location = anchor ?? (first === undefined ? null : refFor(first));
    if (location !== null) {
      const listed = unknown.slice(0, MAX_UNKNOWN_LISTED);
      const rest = unknown.length - listed.length;
      findings.push({
        id: stableId("dependencies", TRIVY_RULES.unknownLicense, location.file, "unknown-licences"),
        domain: "dependencies",
        rule: TRIVY_RULES.unknownLicense,
        severity: "info",
        confidence: "medium",
        title: `${unknown.length} of ${libraries.length} dependencies have no licence in the SBOM`,
        description: `Trivy could not attribute a licence to: ${listed.join(", ")}${rest > 0 ? `, and ${rest} more` : ""}. A lockfile alone carries no licence metadata, so this usually means the packages were not installed when the SBOM was generated — not that the packages are unlicensed.`,
        location,
        evidence: [],
        exploitability:
          "Not an attack path: it is missing provenance, which blocks a licence review rather than enabling an attacker.",
        impact:
          "The licence inventory is incomplete, so a copyleft or no-licence package can reach production unnoticed.",
        recommendation:
          "Re-run the scan with dependencies installed (`npm ci`), or generate the SBOM in CI after the install step, so every component carries a licence.",
        acceptanceCriteria: [
          "The SBOM attributes a licence to every component, or each exception is listed with a reason",
        ],
        cwe: [],
        owasp: [],
        source: SOURCE,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// D4 — misconfiguration (Dockerfile, Kubernetes, Helm, Terraform, …)
// ---------------------------------------------------------------------------

/** The dotted rule a config result's type maps to. */
export function misconfigRule(type: string | undefined): string {
  if (type === undefined) return DEFAULT_MISCONFIG_RULE;
  return MISCONFIG_RULES[type.toLowerCase()] ?? DEFAULT_MISCONFIG_RULE;
}

/** Extra places the same misconfiguration was observed, when trivy lists them. */
function occurrenceRefs(
  misconfiguration: TrivyMisconfiguration,
  target: string,
  primaryLine: number,
): CodeRef[] {
  const refs: CodeRef[] = [];
  for (const occurrence of misconfiguration.CauseMetadata?.Occurrences ?? []) {
    const file = occurrence.Filename ?? target;
    const line = positiveLine(occurrence.Location?.StartLine);
    if (file === target && line === primaryLine) continue;
    refs.push(codeRef(file, line, occurrence.Location?.EndLine, occurrence.Resource));
    if (refs.length >= MAX_OCCURRENCES) break;
  }
  return refs;
}

/**
 * One finding per failing configuration check: Dockerfile, Kubernetes, Helm and
 * Terraform misconfiguration are first-class delivery findings, not a footnote.
 */
export function misconfigurationFindings(report: TrivyReport): Finding[] {
  const findings: Finding[] = [];
  for (const result of report.Results ?? []) {
    const misconfigurations = result.Misconfigurations ?? [];
    const rule = misconfigRule(result.Type);
    for (const misconfiguration of misconfigurations) {
      // Only failures; `--include-non-failures` would add PASS entries.
      if ((misconfiguration.Status ?? "FAIL").toUpperCase() !== "FAIL") continue;
      const cause = misconfiguration.CauseMetadata;
      const line = positiveLine(cause?.StartLine);
      const resource = cause?.Resource;
      const message = tidy(misconfiguration.Message);
      const title = tidy(misconfiguration.Title, 120);

      findings.push({
        id: stableId("delivery", rule, result.Target, `${misconfiguration.ID}:${resource ?? line}`),
        domain: "delivery",
        rule,
        severity: trivySeverity(misconfiguration.Severity),
        confidence: "high",
        title: `${misconfiguration.ID}: ${title || misconfiguration.ID}`,
        description: `${message || title}${resource === undefined ? "" : ` Resource: \`${resource}\`.`}`,
        location: codeRef(result.Target, line, cause?.EndLine, resource),
        evidence: occurrenceRefs(misconfiguration, result.Target, line),
        exploitability: `Evaluated statically against the file, not against a running environment${cause?.Provider === undefined ? "" : ` (${cause.Provider}${cause.Service === undefined ? "" : `/${cause.Service}`})`}. Whether it is exploitable depends on where this configuration is deployed.`,
        impact: tidy(misconfiguration.Description) || message || title,
        recommendation:
          tidy(misconfiguration.Resolution) ||
          `Resolve ${misconfiguration.ID}${misconfiguration.PrimaryURL === undefined ? "" : ` (${misconfiguration.PrimaryURL})`}.`,
        acceptanceCriteria: [
          `\`trivy config\` no longer reports ${misconfiguration.ID} for \`${result.Target}\``,
        ],
        // Trivy's config checks rarely carry a CWE; none is ever invented here.
        cwe: misconfiguration.CweIDs ?? [],
        owasp: [],
        source: SOURCE,
      });
    }
  }
  return findings;
}
