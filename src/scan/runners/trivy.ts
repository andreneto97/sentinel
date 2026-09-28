/**
 * Phase 1 runner for trivy — three passes over the target repository:
 *
 * 1. `trivy fs --format json` — dependency CVEs (D1), located in the manifest
 *    trivy actually read.
 * 2. `trivy fs --format cyclonedx` — the SBOM, kept as an artifact and mined
 *    for the licence inventory (D1).
 * 3. `trivy config --format json` — Dockerfile, Kubernetes, Helm and Terraform
 *    misconfiguration (D4). A first-class pass rather than an optional extra:
 *    it runs whenever the profile proves there is something for it to read, so
 *    a delivery finding is never missing because nobody asked for the pass.
 *
 * Everything the runner spawns goes through the process port, every byte it
 * writes goes through the filesystem port, and every finding's snippet comes
 * from `src/verify` — never from trivy's own `Code.Lines`.
 */

import { join } from "node:path";
import type { Finding } from "../../contracts/findings.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import { PackageJsonSchema, packageManager, valuesOf } from "../../profile/index.ts";
import { type VerifyFileSystem, verifyFindings } from "../../verify/index.ts";
import {
  type DependencyContext,
  type ManifestDependencies,
  type PackageLocation,
  licenseFindings,
  misconfigurationFindings,
  packageLocations,
  parseTrivyReport,
  parseTrivySbom,
  vulnerabilityFindings,
} from "../parsers/trivy.ts";
import type { StepOutcome, StepStatus } from "../types.ts";
import { joinReasons } from "./_runner-support.ts";

/** Step name, matching the tool it drives. */
export const TRIVY_STEP = "trivy";

/** Lockfile name in `tools.lock.json`; the resolver maps it to the pinned binary. */
export const TRIVY_TOOL = "trivy";

/** Directory under the run dir where this step's untouched output lands. */
export const TRIVY_RAW_DIR = join("raw", "trivy");

/** Each pass gets its own budget; a cold vulnerability DB download is ~120 MB. */
export const TRIVY_DEFAULT_TIMEOUT_MS = 600_000;

/** Misconfiguration scanners trivy is asked for when there is no profile to narrow them. */
export const DEFAULT_MISCONFIG_SCANNERS = [
  "dockerfile",
  "kubernetes",
  "helm",
  "terraform",
  "cloudformation",
] as const;

/** Profile `iac`/`container` values mapped onto trivy's `--misconfig-scanners`. */
const SCANNER_BY_FACT: Readonly<Record<string, string>> = {
  dockerfile: "dockerfile",
  kubernetes: "kubernetes",
  helm: "helm",
  terraform: "terraform",
  cloudformation: "cloudformation",
};

/**
 * Detected delivery technologies trivy has no built-in checks for, with what
 * covers them instead. Reported rather than silently dropped.
 */
const UNCOVERED_BY_TRIVY: Readonly<Record<string, string>> = {
  "docker-compose":
    "docker-compose files have no built-in trivy checks; compose misconfiguration is covered by Sentinel's own delivery rules",
  pulumi: "Pulumi programs are code, not config: trivy config cannot read them",
};

/** Lockfiles whose direct dependencies are declared in a sibling `package.json`. */
const NODE_LOCKFILES: readonly string[] = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
];

/** The lockfile each package manager writes, so an unusual one is still recognised. */
const LOCKFILES_BY_MANAGER: Readonly<Record<string, readonly string[]>> = {
  npm: ["package-lock.json", "npm-shrinkwrap.json"],
  yarn: ["yarn.lock"],
  pnpm: ["pnpm-lock.yaml"],
  bun: ["bun.lock", "bun.lockb"],
};

/** stderr lines that mean trivy ran with less than it wanted. */
const DEGRADED_PATTERNS: readonly RegExp[] = [
  /falling back to embedded checks/i,
  /unable to (?:download|fetch|update|get)/i,
  /failed to (?:download|fetch|update)/i,
  /no such host|network is unreachable|connection refused|i\/o timeout|dial tcp/i,
  /db update was skipped|skipping db update/i,
];

/** The filesystem operations this runner needs; the real port satisfies it structurally. */
export interface TrivyFileSystem {
  readFile(path: string): Promise<string>;
  readFileBytes(path: string): Promise<Uint8Array>;
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  realpath(path: string): Promise<string>;
}

/** The fields of a spawned command this runner reads. */
export interface TrivyProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly truncated: boolean;
  readonly notFound: boolean;
}

/** The spawn options this runner sets; a subset of `ProcessRunOptions`. */
export interface TrivyProcessOptions {
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

/** The slice of `src/ports/process-executor.ts` this runner depends on. */
export interface TrivyProcessExecutor {
  run(
    command: string,
    args?: readonly string[],
    options?: TrivyProcessOptions,
  ): Promise<TrivyProcessResult>;
}

/** The slice of `src/tools/resolve.ts#ToolResolver` this runner depends on. */
export interface TrivyToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/**
 * Everything the runner is handed. The field names match the phase 1 runner
 * context, so the orchestrator can pass its own context object straight in.
 */
export interface TrivyRunContext {
  readonly fs: TrivyFileSystem;
  readonly exec: TrivyProcessExecutor;
  readonly tools: TrivyToolResolver;
  /** Absolute path of the repository under analysis. Never written to. */
  readonly targetDir: string;
  /** Absolute path of this run's output directory; raw output lands under it. */
  readonly runDir: string;
  /** Phase 0 output, used to decide which misconfiguration scanners are worth running. */
  readonly profile?: StackProfile | undefined;
  /** Allow a trivy found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  /** Wall-clock budget for a single pass. */
  readonly timeoutMs?: number | undefined;
  /** Air-gapped run: reuse the cached database and checks instead of updating them. */
  readonly offline?: boolean | undefined;
  /** Overrides trivy's own cache location (a CI cache, or a test's temp dir). */
  readonly cacheDir?: string | undefined;
}

/** Flags shared by every pass: no progress bar to parse, no telemetry, no version ping. */
function commonArgs(context: TrivyRunContext): string[] {
  return context.cacheDir === undefined ? [] : ["--cache-dir", context.cacheDir];
}

/** Arguments for pass 1: dependency CVEs, with the package graph that explains them. */
export function vulnerabilityArgs(context: TrivyRunContext, target: string): string[] {
  return [
    "fs",
    "--format",
    "json",
    "--scanners",
    "vuln",
    // The graph is what turns "qs is vulnerable" into "express pulls in qs".
    "--list-all-pkgs",
    "--no-progress",
    "--skip-version-check",
    "--disable-telemetry",
    ...(context.offline === true ? ["--skip-db-update"] : []),
    ...commonArgs(context),
    target,
  ];
}

/** Arguments for pass 2: the SBOM. `license` keeps the vulnerability DB out of it. */
export function sbomArgs(context: TrivyRunContext, target: string): string[] {
  return [
    "fs",
    "--format",
    "cyclonedx",
    "--scanners",
    "license",
    "--no-progress",
    "--skip-version-check",
    "--disable-telemetry",
    ...commonArgs(context),
    target,
  ];
}

/** Arguments for pass 3: misconfiguration over the config kinds the repo actually has. */
export function configArgs(
  context: TrivyRunContext,
  target: string,
  scanners: readonly string[],
): string[] {
  return [
    "config",
    "--format",
    "json",
    "--misconfig-scanners",
    scanners.join(","),
    "--skip-version-check",
    "--disable-telemetry",
    ...(context.offline === true ? ["--skip-check-update"] : []),
    ...commonArgs(context),
    target,
  ];
}

/** What the misconfiguration pass should scan, and what it cannot cover. */
export interface MisconfigPlan {
  /** Values for `--misconfig-scanners`; empty means the pass has nothing to do. */
  readonly scanners: string[];
  /** Detected technologies trivy has no checks for, already phrased for the report. */
  readonly uncovered: string[];
}

/**
 * Chooses the misconfiguration scanners from the profile's `container` and
 * `iac` facts. Without a profile the full supported set runs, because guessing
 * narrow would silently drop coverage.
 */
export function misconfigPlan(profile: StackProfile | undefined): MisconfigPlan {
  if (profile === undefined) {
    return { scanners: [...DEFAULT_MISCONFIG_SCANNERS], uncovered: [] };
  }
  const detected = [...valuesOf(profile, "container"), ...valuesOf(profile, "iac")];
  const scanners = new Set<string>();
  const uncovered: string[] = [];
  for (const value of detected) {
    const scanner = SCANNER_BY_FACT[value];
    if (scanner !== undefined) {
      scanners.add(scanner);
      continue;
    }
    const note = UNCOVERED_BY_TRIVY[value];
    if (note !== undefined) uncovered.push(note);
  }
  return { scanners: [...scanners].sort(), uncovered };
}

/** How one pass ended, before the three are combined into a step outcome. */
interface PassOutcome {
  readonly status: StepStatus;
  readonly reason: string | null;
  /** stdout, or null when there is nothing worth parsing. */
  readonly stdout: string | null;
  readonly artifacts: string[];
}

/** Trims a tool's stderr to something one report line can hold. */
function briefly(text: string, limit = 240): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}…`;
}

/** The most telling line of trivy's stderr: its own FATAL/ERROR beats the noise. */
function stderrHighlight(stderr: string): string {
  const lines = stderr.split("\n").filter((line) => line.trim() !== "");
  const fatal =
    lines.find((line) => /\bFATAL\b/.test(line)) ?? lines.find((line) => /\bERROR\b/.test(line));
  return briefly(fatal ?? lines.at(-1) ?? "no output");
}

/** The degradation trivy admitted to in its logs, if any. */
function degradationOf(stderr: string): string | null {
  for (const line of stderr.split("\n")) {
    if (DEGRADED_PATTERNS.some((pattern) => pattern.test(line))) return briefly(line, 160);
  }
  return null;
}

/**
 * Runs one pass and writes its untouched output under `<runDir>/raw/trivy/`.
 *
 * A non-zero exit with parseable output is a success: that is how trivy reports
 * findings when an exit code is configured. A non-zero exit with nothing to
 * parse is a failure, and a pass that admitted to an offline database or
 * embedded fallback checks is degraded, never `ok`.
 */
async function runPass(
  context: TrivyRunContext,
  binary: string,
  args: readonly string[],
  fileName: string,
): Promise<PassOutcome> {
  const result = await context.exec.run(binary, args, {
    cwd: context.targetDir,
    timeoutMs: context.timeoutMs ?? TRIVY_DEFAULT_TIMEOUT_MS,
  });

  const artifacts: string[] = [];
  const rawDir = join(context.runDir, TRIVY_RAW_DIR);
  if (result.stdout !== "") {
    const path = join(rawDir, fileName);
    await context.fs.writeFile(path, result.stdout);
    artifacts.push(path);
  }
  if (result.stderr.trim() !== "") {
    const path = join(rawDir, `${fileName}.stderr.log`);
    await context.fs.writeFile(path, result.stderr);
    artifacts.push(path);
  }

  if (result.notFound) {
    return { status: "skipped", reason: `${binary} is not executable`, stdout: null, artifacts };
  }
  if (result.timedOut) {
    return {
      status: "failed",
      reason: `timed out after ${context.timeoutMs ?? TRIVY_DEFAULT_TIMEOUT_MS} ms`,
      stdout: null,
      artifacts,
    };
  }
  if (result.truncated) {
    return {
      status: "degraded",
      reason: "output exceeded the capture limit and was truncated",
      stdout: null,
      artifacts,
    };
  }
  if (result.stdout.trim() === "") {
    return {
      status: "failed",
      reason: `trivy printed nothing (exit ${result.exitCode}): ${stderrHighlight(result.stderr)}`,
      stdout: null,
      artifacts,
    };
  }

  const degradation = degradationOf(result.stderr);
  if (degradation !== null) {
    return { status: "degraded", reason: degradation, stdout: result.stdout, artifacts };
  }
  return { status: "ok", reason: null, stdout: result.stdout, artifacts };
}

/** Every lockfile name whose direct dependencies live in a sibling `package.json`. */
function lockfileNames(profile: StackProfile | undefined): Set<string> {
  const names = new Set<string>(NODE_LOCKFILES);
  const manager = profile === undefined ? undefined : packageManager(profile);
  for (const name of (manager === undefined ? undefined : LOCKFILES_BY_MANAGER[manager]) ?? []) {
    names.add(name);
  }
  names.add("package.json");
  return names;
}

/** The directory part of a repo-relative path; `""` for a file at the root. */
function directoryOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? "" : path.slice(0, index);
}

/** The file name part of a repo-relative path. */
function baseNameOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

/**
 * Reads the `package.json` next to each scanned lockfile, so "direct" and
 * "transitive" come from what the project declares rather than from a guess.
 * A manifest that will not parse is skipped — trivy's own `Relationship` is
 * then the fallback.
 */
async function manifestIndex(
  context: TrivyRunContext,
  targets: readonly string[],
): Promise<Map<string, ManifestDependencies>> {
  const names = lockfileNames(context.profile);
  const index = new Map<string, ManifestDependencies>();
  const cache = new Map<string, ManifestDependencies | null>();

  for (const target of targets) {
    if (!names.has(baseNameOf(target))) continue;
    const directory = directoryOf(target);
    const manifestPath = directory === "" ? "package.json" : `${directory}/package.json`;

    let parsed = cache.get(manifestPath);
    if (parsed === undefined) {
      parsed = await readManifest(context, manifestPath);
      cache.set(manifestPath, parsed);
    }
    if (parsed !== null) index.set(target, parsed);
  }
  return index;
}

/** Reads and validates one `package.json`; unreadable or malformed yields null. */
async function readManifest(
  context: TrivyRunContext,
  manifestPath: string,
): Promise<ManifestDependencies | null> {
  const absolute = join(context.targetDir, manifestPath);
  if (!(await context.fs.exists(absolute))) return null;
  let raw: string;
  try {
    raw = await context.fs.readFile(absolute);
  } catch {
    return null;
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  const result = PackageJsonSchema.safeParse(json);
  if (!result.success) return null;
  return {
    runtime: new Set([
      ...Object.keys(result.data.dependencies ?? {}),
      ...Object.keys(result.data.optionalDependencies ?? {}),
    ]),
    dev: new Set(Object.keys(result.data.devDependencies ?? {})),
  };
}

/** Adapts the filesystem port to the narrower seam the citation verifier takes. */
function verifyFileSystem(fs: TrivyFileSystem): VerifyFileSystem {
  return {
    readBytes: (path: string) => fs.readFileBytes(path),
    realpath: (path: string) => fs.realpath(path),
  };
}

/** Builds the outcome, keeping `reason` off the object entirely when there is none. */
function outcome(
  status: StepStatus,
  reason: string | undefined,
  findings: readonly Finding[],
  artifacts: readonly string[],
  startedAt: number,
): StepOutcome {
  return {
    step: TRIVY_STEP,
    status,
    ...(reason === undefined ? {} : { reason }),
    findings,
    artifacts: [...artifacts],
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  };
}

/**
 * Runs trivy's three passes and returns their findings, already verified
 * against disk. Never throws: a missing binary is `skipped`, a stale offline
 * database is `degraded`, and output that cannot be trusted is `failed`.
 */
export async function runTrivy(context: TrivyRunContext): Promise<StepOutcome> {
  const startedAt = performance.now();
  const binary = await context.tools.resolve(TRIVY_TOOL, {
    allowPath: context.allowPathTools ?? false,
  });
  if (binary === null) {
    return outcome(
      "skipped",
      "trivy is not installed (run `sentinel setup`): dependency CVEs, the SBOM licence inventory and Dockerfile/Kubernetes/Helm/Terraform misconfiguration were not checked",
      [],
      [],
      startedAt,
    );
  }

  await context.fs.mkdirp(join(context.runDir, TRIVY_RAW_DIR));

  // trivy runs with the repository as its working directory, so every `Target`
  // it reports is already the repo-relative path a citation needs.
  const target = ".";
  const notes: Array<string | null> = [];
  const artifacts: string[] = [];
  const findings: Finding[] = [];
  const statuses: StepStatus[] = [];

  // --- pass 1: dependency CVEs -------------------------------------------
  const vulnerabilityPass = await runPass(
    context,
    binary,
    vulnerabilityArgs(context, target),
    "fs.json",
  );
  artifacts.push(...vulnerabilityPass.artifacts);
  statuses.push(vulnerabilityPass.status);
  notes.push(
    vulnerabilityPass.reason === null ? null : `vulnerabilities: ${vulnerabilityPass.reason}`,
  );
  if (context.offline === true) {
    notes.push("vulnerability database was not updated (offline run)");
    statuses.push("degraded");
  }

  let locations = new Map<string, PackageLocation>();
  if (vulnerabilityPass.stdout !== null) {
    const parsed = parseTrivyReport(vulnerabilityPass.stdout);
    if (parsed.ok) {
      const targets = (parsed.value.Results ?? []).map((result) => result.Target);
      const manifests = await manifestIndex(context, targets);
      const dependencyContext: DependencyContext = { manifests };
      findings.push(...vulnerabilityFindings(parsed.value, dependencyContext));
      locations = packageLocations(parsed.value);
    } else {
      statuses.push("failed");
      notes.push(`vulnerabilities: ${parsed.error}`);
    }
  }

  // --- pass 2: SBOM + licence inventory ----------------------------------
  const sbomPass = await runPass(context, binary, sbomArgs(context, target), "sbom.cdx.json");
  artifacts.push(...sbomPass.artifacts);
  statuses.push(sbomPass.status);
  notes.push(sbomPass.reason === null ? null : `sbom: ${sbomPass.reason}`);
  if (sbomPass.stdout !== null) {
    const parsed = parseTrivySbom(sbomPass.stdout);
    if (parsed.ok) {
      findings.push(...licenseFindings(parsed.value, locations));
    } else {
      statuses.push("failed");
      notes.push(`sbom: ${parsed.error}`);
    }
  }

  // --- pass 3: misconfiguration ------------------------------------------
  const plan = misconfigPlan(context.profile);
  for (const uncovered of plan.uncovered) notes.push(uncovered);
  if (plan.scanners.length === 0) {
    notes.push(
      "misconfiguration: no Dockerfile, Kubernetes manifest, Helm chart or Terraform file in this repository",
    );
  } else {
    const configPass = await runPass(
      context,
      binary,
      configArgs(context, target, plan.scanners),
      "config.json",
    );
    artifacts.push(...configPass.artifacts);
    statuses.push(configPass.status);
    notes.push(configPass.reason === null ? null : `misconfiguration: ${configPass.reason}`);
    if (configPass.stdout !== null) {
      const parsed = parseTrivyReport(configPass.stdout);
      if (parsed.ok) {
        findings.push(...misconfigurationFindings(parsed.value));
      } else {
        statuses.push("failed");
        notes.push(`misconfiguration: ${parsed.error}`);
      }
    }
  }

  // --- verification: this is where every snippet comes from ---------------
  const verified = await verifyFindings(findings, {
    fs: verifyFileSystem(context.fs),
    targetDir: context.targetDir,
  });
  if (verified.droppedFindings > 0) {
    statuses.push("degraded");
    notes.push(
      `${verified.droppedFindings} finding(s) dropped: the file trivy named does not resolve to a readable file in the repository`,
    );
  }

  const ran = statuses.filter((entry) => entry !== "skipped");
  const status: StepStatus =
    ran.length === 0
      ? "skipped"
      : ran.every((entry) => entry === "failed")
        ? "failed"
        : ran.some((entry) => entry === "failed" || entry === "degraded")
          ? "degraded"
          : "ok";

  return outcome(status, joinReasons(notes), verified.kept, artifacts, startedAt);
}
