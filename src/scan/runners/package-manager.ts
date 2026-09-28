/**
 * Phase 1 runner for the package manager itself: what is out of date, and
 * whether the lockfile can be trusted.
 *
 * Two guarantees shape it. The analysed repository is read, never written:
 * every manager is pointed at a Sentinel-owned registry cache, so a target
 * `.npmrc` that puts the cache inside the repo cannot cause a write there, and
 * no install or lockfile-writing command is ever run. And the registry is
 * optional: the outdated pass degrades to a recorded "needs network" reason
 * while the lockfile checks, which are pure filesystem work, still produce
 * findings.
 */

import { join } from "node:path";
import type { Finding, Severity } from "../../contracts/findings.ts";
import { packageManager, toLines } from "../../profile/index.ts";
import { defaultCacheRoot } from "../../tools/installer.ts";
import {
  type ParsedVersion,
  compareVersions,
  formatVersion,
  minVersionOfRange,
  parseVersion,
  versionGap,
} from "../parsers/_semver-lite.ts";
import {
  type OutdatedEntry,
  type PackageManagerName,
  baselineOf,
  parseOutdated,
} from "../parsers/package-manager.ts";
import {
  LOCKFILES,
  type LockfileKind,
  type OverridePin,
  type ScanPackageJson,
  declaredDependencies,
  declaredInLockfile,
  manifestLineOf,
  overridePins,
  parsePackageJson,
} from "../parsers/package-manifest.ts";
import type { StepOutcome, StepStatus } from "../types.ts";
import {
  type RunnerContext,
  type RunnerProcessResult,
  briefly,
  failedStep,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
  verifyStepFindings,
  writeRaw,
} from "./_runner-support.ts";

/** Step name; this runner drives whichever manager the repository uses. */
export const PACKAGE_MANAGER_STEP = "package-manager";

/** A registry round trip is not a graph walk: fail fast rather than hang. */
export const PACKAGE_MANAGER_DEFAULT_TIMEOUT_MS = 120_000;

/** Ceiling on outdated findings, so a neglected repository cannot flood the report. */
export const MAX_OUTDATED_FINDINGS = 500;

/** The managers this runner knows how to interrogate. */
const MANAGERS: readonly PackageManagerName[] = ["npm", "pnpm", "yarn", "bun"];

/** Registry errors every manager surfaces in one wording or another. */
const NETWORK_FAILURE_RE =
  /ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNREFUSED|ECONNRESET|ERR_SOCKET|getaddrinfo|network|offline|registry.*(?:unreachable|failed)|failed to fetch|request to .* failed/i;

/** Severity per distance behind: a major gap is planned work, a patch gap is a chore. */
const GAP_SEVERITY = { major: "low", minor: "info", patch: "info" } as const;

/** The root manifest, kept next to its lines so a finding can cite the right one. */
interface ManifestText {
  readonly path: string;
  readonly lines: readonly string[];
  readonly data: ScanPackageJson;
}

/** Reads and validates the root manifest, or returns why it could not. */
async function readManifest(ctx: RunnerContext): Promise<ManifestText | string> {
  let raw: string;
  try {
    raw = await ctx.fs.readFile(join(ctx.targetDir, "package.json"));
  } catch {
    return "package.json could not be read";
  }
  const manifest = parsePackageJson(raw);
  if (!manifest.ok) return manifest.error;
  return { path: "package.json", lines: toLines(raw), data: manifest.value };
}

/** Every lockfile Sentinel recognises at the repository root. */
async function surveyLockfiles(ctx: RunnerContext): Promise<LockfileKind[]> {
  const present: LockfileKind[] = [];
  for (const kind of LOCKFILES) {
    if (await ctx.fs.exists(join(ctx.targetDir, kind.file))) present.push(kind);
  }
  return present;
}

/** The manager to drive: what phase 0 proved, else what the lockfiles imply. */
export function resolveManager(
  ctx: RunnerContext,
  lockfiles: readonly LockfileKind[],
): PackageManagerName | null {
  const profiled = ctx.profile === undefined ? undefined : packageManager(ctx.profile);
  const named = MANAGERS.find((name) => name === profiled);
  if (named !== undefined) return named;
  const managers = [...new Set(lockfiles.map((kind) => kind.manager))];
  return managers.length === 1 ? (managers[0] ?? null) : null;
}

/** True when the repo uses yarn 2+, whose CLI has no built-in `outdated`. */
async function isYarnBerry(ctx: RunnerContext): Promise<boolean> {
  if (await ctx.fs.exists(join(ctx.targetDir, ".yarnrc.yml"))) return true;
  try {
    return (await ctx.fs.readFile(join(ctx.targetDir, "yarn.lock"))).includes("__metadata:");
  } catch {
    return false;
  }
}

/** Builds a D1 finding with this runner's source stamp. */
function hygieneFinding(input: {
  rule: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  title: string;
  description: string;
  impact: string;
  recommendation: string;
  acceptanceCriteria: readonly string[];
  file: string;
  line: number;
  symbol: string;
  evidence?: readonly { file: string; line: number; note?: string }[];
}): Finding {
  return makeFinding({
    domain: "dependencies",
    rule: input.rule,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    description: input.description,
    impact: input.impact,
    recommendation: input.recommendation,
    acceptanceCriteria: input.acceptanceCriteria,
    file: input.file,
    line: input.line,
    symbol: input.symbol,
    ...(input.evidence === undefined ? {} : { evidence: input.evidence }),
    source: { kind: "tool", name: PACKAGE_MANAGER_STEP },
  });
}

/** The finding for a repository that commits no lockfile at all. */
function missingLockfileFinding(manifest: ManifestText): Finding {
  return hygieneFinding({
    rule: "dependencies.missing-lockfile",
    severity: "medium",
    confidence: "high",
    title: "No lockfile is committed",
    description:
      "The repository declares dependencies but commits no lockfile, so every install resolves the declared ranges afresh. Two installs of the same commit can produce different dependency trees, and a compromised release of a transitive package is picked up silently.",
    impact:
      "Builds are not reproducible, and a dependency audit describes a tree that may never be installed again.",
    recommendation:
      "Run the package manager's install once and commit the lockfile it writes, then enforce it in CI with the manager's frozen-lockfile flag.",
    acceptanceCriteria: [
      "A lockfile for the project's package manager is committed.",
      "CI installs with the frozen-lockfile flag and fails when the lockfile is stale.",
    ],
    file: manifest.path,
    line: 1,
    symbol: "lockfile",
  });
}

/** The finding for a repository that carries two managers' lockfiles at once. */
function multipleLockfilesFinding(head: LockfileKind, lockfiles: readonly LockfileKind[]): Finding {
  const names = lockfiles.map((kind) => kind.file).join(", ");
  return hygieneFinding({
    rule: "dependencies.multiple-lockfiles",
    severity: "medium",
    confidence: "high",
    title: `Two package managers claim this repository (${names})`,
    description: `The repository carries lockfiles for more than one package manager: ${names}. Whichever one a developer, a container build or CI happens to invoke resolves a different tree, and only one of those trees is the one that was reviewed.`,
    impact:
      "The dependency tree that ships depends on which command ran, so a CVE fixed in one lockfile can still be installed from the other.",
    recommendation:
      "Pick one package manager, delete the other lockfiles, and declare the choice in the `packageManager` field so every tool agrees.",
    acceptanceCriteria: [
      "Exactly one lockfile remains in the repository.",
      "`package.json` declares the chosen manager in its `packageManager` field.",
      "CI and the container build both use that manager.",
    ],
    file: head.file,
    line: 1,
    symbol: "lockfiles",
    evidence: lockfiles
      .slice(1)
      .map((kind) => ({ file: kind.file, line: 1, note: "second package manager" })),
  });
}

/** What the lockfile checks produced, and what they could not check. */
interface LockfilePass {
  readonly findings: readonly Finding[];
  readonly notes: readonly string[];
}

/** Findings about the lockfile itself: missing, duplicated, or out of sync. */
async function lockfilePass(
  ctx: RunnerContext,
  manifest: ManifestText,
  lockfiles: readonly LockfileKind[],
): Promise<LockfilePass> {
  const findings: Finding[] = [];
  const notes: string[] = [];

  if (lockfiles.length === 0) {
    return { findings: [missingLockfileFinding(manifest)], notes };
  }

  const primary = lockfiles[0];
  if (primary === undefined) return { findings, notes };

  if (new Set(lockfiles.map((kind) => kind.manager)).size > 1) {
    findings.push(multipleLockfilesFinding(primary, lockfiles));
  }

  let lockContent: string;
  try {
    lockContent = await ctx.fs.readFile(join(ctx.targetDir, primary.file));
  } catch {
    notes.push(`${primary.file} could not be read, so it was not checked against package.json`);
    return { findings, notes };
  }

  const declared = declaredDependencies(manifest.data);
  const missing: string[] = [];
  let unreadable = false;
  for (const dependency of declared) {
    const coverage = declaredInLockfile(primary.format, lockContent, dependency.name);
    if (coverage === "absent") missing.push(dependency.name);
    if (coverage === "unknown") unreadable = true;
  }

  if (unreadable) {
    notes.push(
      `${primary.file} is a format Sentinel does not read, so it could not be checked against package.json`,
    );
  }

  const first = missing[0];
  if (first !== undefined) {
    const section = declared.find((dependency) => dependency.name === first)?.section ?? null;
    const plural = missing.length === 1;
    findings.push(
      hygieneFinding({
        rule: "dependencies.lockfile-out-of-sync",
        severity: "medium",
        confidence: "medium",
        title: `${primary.file} does not cover ${missing.length} declared dependenc${plural ? "y" : "ies"}`,
        description: `\`package.json\` declares ${missing.map((name) => `\`${name}\``).join(", ")}, but ${primary.file} never mentions ${plural ? "it" : "them"}. The lockfile was not regenerated after the manifest changed, so a frozen-lockfile install fails and an ordinary install resolves versions nobody reviewed.`,
        impact:
          "CI installs either break or silently resolve unreviewed versions, and the dependency audit in this report describes a tree that differs from the one installed.",
        recommendation:
          "Regenerate the lockfile with the project's package manager and commit it in the same change as the manifest.",
        acceptanceCriteria: [
          "The lockfile lists every dependency declared in `package.json`.",
          "A frozen-lockfile install succeeds from a clean checkout.",
        ],
        file: manifest.path,
        line: manifestLineOf(manifest.lines, section, first),
        symbol: `lockfile-sync:${missing.join(",")}`,
        evidence: [{ file: primary.file, line: 1, note: "lockfile that omits them" }],
      }),
    );
  }

  return { findings, notes };
}

/** The declared range's floor for a package, when the manifest declares one. */
function declaredFloor(manifest: ScanPackageJson, name: string): ParsedVersion | null {
  const declared = declaredDependencies(manifest).find((entry) => entry.name === name);
  return declared === undefined ? null : minVersionOfRange(declared.range);
}

/** One override pin, escalated when it holds a package below its declared floor. */
export function overrideFinding(
  manifest: ManifestText,
  pin: OverridePin,
  pinned: ParsedVersion,
  belowFloor: ParsedVersion | null,
): Finding {
  const section = pin.section === "pnpm.overrides" ? "overrides" : pin.section;
  const line = manifestLineOf(manifest.lines, section, pin.path.split(" > ").at(-1) ?? pin.name);
  const pinnedText = formatVersion(pinned);

  if (belowFloor !== null) {
    return hygieneFinding({
      rule: "dependencies.override-below-declared-range",
      severity: "medium",
      confidence: "high",
      title: `\`${pin.section}\` holds ${pin.name} at ${pinnedText}, below the declared range`,
      description: `\`${pin.section}.${pin.path}\` forces ${pin.name} to ${pinnedText}, while the manifest declares a range whose lowest accepted version is ${formatVersion(belowFloor)}. The override wins, so the version actually installed is older than the one the manifest says the project depends on — including any security fix released in between.`,
      impact:
        "A pin below the declared floor silently reinstates versions the project already moved past, which is exactly how a patched advisory comes back.",
      recommendation:
        "Raise the override to at least the declared floor, and to the patched version of any advisory that affects it, or delete the override if the reason for it no longer holds.",
      acceptanceCriteria: [
        `The override for ${pin.name} is at or above ${formatVersion(belowFloor)}, or removed.`,
        "A fresh dependency scan reports no known advisory against the resolved version.",
      ],
      file: manifest.path,
      line,
      symbol: `${pin.section}:${pin.path}`,
    });
  }

  return hygieneFinding({
    rule: "dependencies.pinned-override",
    severity: "low",
    confidence: "medium",
    title: `\`${pin.section}\` pins ${pin.name} to ${pinnedText}`,
    description: `\`${pin.section}.${pin.path}\` forces ${pin.name} to exactly ${pinnedText} everywhere in the tree, overriding whatever any dependency asks for. A pin does not move when an advisory is published, so it is worth confirming that ${pinnedText} is at or above the patched version for every advisory affecting ${pin.name}.`,
    impact:
      "An override freezes one package for the whole tree, so a security release for it is never picked up until somebody edits the manifest by hand.",
    recommendation:
      "Record why the pin exists, check it against the advisories for this package, and remove it once the upstream fix makes it unnecessary.",
    acceptanceCriteria: [
      `The reason for pinning ${pin.name} is documented next to the override.`,
      `${pinnedText} is at or above the patched version of every advisory affecting ${pin.name}.`,
    ],
    file: manifest.path,
    line,
    symbol: `${pin.section}:${pin.path}`,
  });
}

/** Findings for every `overrides` / `resolutions` entry that forces a fixed version. */
function overridePass(manifest: ManifestText): Finding[] {
  const findings: Finding[] = [];
  for (const pin of overridePins(manifest.data)) {
    const pinned = parseVersion(pin.spec);
    // A range as an override (`^1.2.3`) still moves with releases; only an
    // exact pin is the frozen-version problem this check is about.
    if (pinned === null) continue;
    const floor = declaredFloor(manifest.data, pin.name);
    const belowDeclared = floor !== null && compareVersions(pinned, floor) < 0;
    findings.push(overrideFinding(manifest, pin, pinned, belowDeclared ? floor : null));
  }
  return findings;
}

/** How the outdated command is spelled for each manager. */
export function outdatedArgs(
  manager: PackageManagerName,
  cacheDir: string,
  offline: boolean,
): string[] {
  switch (manager) {
    case "npm":
      return ["outdated", "--json", "--long", ...(offline ? ["--offline"] : [])];
    case "pnpm":
      return ["outdated", "--json", ...(offline ? ["--offline"] : [])];
    case "yarn":
      return [
        "outdated",
        "--json",
        "--non-interactive",
        "--no-progress",
        "--cache-folder",
        cacheDir,
        ...(offline ? ["--offline"] : []),
      ];
    case "bun":
      return ["outdated", "--cache-dir", cacheDir];
  }
}

/**
 * Environment for the outdated command. The registry cache is redirected into
 * Sentinel's own cache root — never the target's — and install scripts are
 * disabled, so interrogating the manager cannot execute repository code.
 */
export function outdatedEnv(cacheDir: string): Readonly<Record<string, string | undefined>> {
  return {
    NO_COLOR: "1",
    npm_config_cache: cacheDir,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_update_notifier: "false",
    npm_config_ignore_scripts: "true",
  };
}

/** Whether a failed run failed because it could not reach the registry. */
function looksLikeNetworkFailure(result: RunnerProcessResult): boolean {
  return NETWORK_FAILURE_RE.test(`${result.stderr}\n${result.stdout}`);
}

/** Turns one outdated entry into a finding, or null when there is no real gap. */
export function outdatedFinding(manifest: ManifestText, entry: OutdatedEntry): Finding | null {
  const baseline = baselineOf(entry);
  if (baseline === null || entry.latest === null) return null;
  const gap = versionGap(baseline.version, entry.latest);
  if (gap === null || gap === "none") return null;

  const section = entry.dependencyType === "devDependencies" ? "devDependencies" : "dependencies";
  const wanted = entry.wanted ?? "unknown";
  const observed =
    baseline.source === "installed"
      ? `installed ${baseline.version}`
      : `${baseline.version} is the newest the declared range allows and nothing is installed to compare against`;

  return hygieneFinding({
    rule: `dependencies.outdated-${gap}`,
    severity: GAP_SEVERITY[gap],
    confidence: baseline.source === "installed" ? "high" : "medium",
    title: `${entry.name} is a ${gap} release behind (${baseline.version} to ${entry.latest})`,
    description: `${entry.name}: ${observed}; the declared range allows up to ${wanted}, and the registry's latest is ${entry.latest} — a ${gap} gap.${entry.deprecated ? " The package manager also reports this package as deprecated." : ""}${gap === "major" ? " A major gap usually carries breaking changes and has to be planned rather than batched with routine updates." : " A gap this size is normally a lockfile refresh rather than a migration."}`,
    impact:
      gap === "major"
        ? "The longer a major gap is left, the more releases the eventual migration has to cross, and upstream stops backporting security fixes to the line in use."
        : "Fixes published upstream, including security fixes, are not being picked up.",
    recommendation:
      gap === "major"
        ? `Plan the upgrade of ${entry.name} to ${entry.latest}: read the release notes for the breaking changes, then move in one reviewed change.`
        : `Update ${entry.name} to ${entry.latest} and refresh the lockfile.`,
    acceptanceCriteria: [
      `${entry.name} resolves to ${entry.latest}, or the reason to stay behind is recorded.`,
      "The lockfile is regenerated and the test suite passes.",
    ],
    file: manifest.path,
    line: manifestLineOf(manifest.lines, section, entry.name),
    symbol: entry.name,
  });
}

/** The outcome of the registry-dependent half of the step. */
interface OutdatedPass {
  readonly findings: readonly Finding[];
  readonly notes: readonly string[];
  readonly artifacts: readonly string[];
}

/** Runs the manager's outdated command and normalises it, degrading on failure. */
async function outdatedPass(
  ctx: RunnerContext,
  manifest: ManifestText,
  manager: PackageManagerName | null,
): Promise<OutdatedPass> {
  const nothing = (note: string): OutdatedPass => ({
    findings: [],
    notes: [note],
    artifacts: [],
  });

  if (manager === null) {
    return nothing(
      "outdated check skipped: no package manager could be determined (no lockfile and no `packageManager` field)",
    );
  }
  const offline = ctx.offline === true;
  if (manager === "bun" && offline) {
    return nothing("outdated check skipped (needs network): `bun outdated` has no offline mode");
  }
  if (manager === "yarn" && (await isYarnBerry(ctx))) {
    return nothing(
      "outdated check skipped: yarn 2+ has no built-in `outdated` command (it needs the interactive-tools plugin)",
    );
  }

  const timeoutMs = ctx.timeoutMs ?? PACKAGE_MANAGER_DEFAULT_TIMEOUT_MS;
  const cacheDir = join(defaultCacheRoot(), "package-manager", manager);
  await ctx.fs.mkdirp(cacheDir);

  const result = await ctx.exec.run(manager, outdatedArgs(manager, cacheDir, offline), {
    cwd: ctx.targetDir,
    timeoutMs,
    env: outdatedEnv(cacheDir),
  });

  if (result.notFound) {
    return nothing(`outdated check skipped: \`${manager}\` is not on PATH`);
  }
  if (result.timedOut) {
    return nothing(
      `outdated check skipped (needs network): \`${manager} outdated\` did not finish within ${timeoutMs} ms`,
    );
  }

  const stdout = result.stdout.trim();
  // Every manager exits non-zero when it finds something, so only an empty
  // payload tells a real failure apart from a useful answer.
  if (stdout === "" || stdout === "{}") {
    if (result.exitCode === 0) return { findings: [], notes: [], artifacts: [] };
    return nothing(
      looksLikeNetworkFailure(result)
        ? `outdated check skipped (needs network): ${briefly(result.stderr, 200) || "the registry could not be reached"}`
        : `outdated check failed: \`${manager} outdated\` exited ${result.exitCode}: ${briefly(result.stderr, 200) || "no stderr"}`,
    );
  }

  const artifacts = [
    await writeRaw(
      ctx,
      PACKAGE_MANAGER_STEP,
      `${manager}-outdated.${manager === "bun" ? "txt" : "json"}`,
      result.stdout,
    ),
  ];

  const report = parseOutdated(manager, stdout);
  if (!report.ok) {
    return { findings: [], notes: [`outdated check failed: ${report.error}`], artifacts };
  }

  const findings: Finding[] = [];
  const notes: string[] = [];
  let incomparable = 0;
  for (const entry of report.value) {
    const finding = outdatedFinding(manifest, entry);
    if (finding !== null) {
      findings.push(finding);
      continue;
    }
    if (baselineOf(entry) === null || entry.latest === null) incomparable += 1;
  }
  if (incomparable > 0) {
    notes.push(
      `${incomparable} outdated entr${incomparable === 1 ? "y" : "ies"} carried no comparable version and were not reported`,
    );
  }
  if (findings.length > MAX_OUTDATED_FINDINGS) {
    notes.push(
      `${findings.length} outdated dependencies were found; only the first ${MAX_OUTDATED_FINDINGS} are reported`,
    );
  }
  return { findings: findings.slice(0, MAX_OUTDATED_FINDINGS), notes, artifacts };
}

/**
 * Checks the target's dependency hygiene: what is out of date, whether the
 * lockfile exists, is unique and matches the manifest, and whether an override
 * forces a package to a fixed version. Never throws and never writes to the
 * analysed repository.
 */
export async function runPackageManager(ctx: RunnerContext): Promise<StepOutcome> {
  const startedAt = performance.now();

  if (!(await ctx.fs.exists(join(ctx.targetDir, "package.json")))) {
    return skipped(PACKAGE_MANAGER_STEP, startedAt, "the target has no package.json");
  }
  const manifest = await readManifest(ctx);
  if (typeof manifest === "string") {
    return failedStep(PACKAGE_MANAGER_STEP, startedAt, manifest);
  }

  const lockfiles = await surveyLockfiles(ctx);
  const manager = resolveManager(ctx, lockfiles);
  const lockCheck = await lockfilePass(ctx, manifest, lockfiles);
  const outdated = await outdatedPass(ctx, manifest, manager);

  const notes: string[] = [...lockCheck.notes, ...outdated.notes];
  const verified = await verifyStepFindings(
    [...lockCheck.findings, ...overridePass(manifest), ...outdated.findings],
    ctx,
  );
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} finding(s) dropped: the manifest line they cite does not resolve in the repository`,
    );
  }

  const status: StepStatus = notes.length === 0 ? "ok" : "degraded";
  return outcome(
    PACKAGE_MANAGER_STEP,
    status,
    joinReasons(notes),
    verified.kept,
    outdated.artifacts,
    startedAt,
  );
}
