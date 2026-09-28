import { join } from "node:path";
import {
  type CoverageLoss,
  type DoctorCheck,
  type DoctorReport,
  DoctorReportSchema,
  isReady,
  summarizeChecks,
} from "../contracts/doctor.ts";
import { type Domain, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { ToolsLock } from "../contracts/tools.ts";

/** What a spawned command returned; the shape the process port is expected to produce. */
export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** The slice of the process port the preflight needs. */
export interface DoctorProcessPort {
  run(
    command: string,
    args: readonly string[],
    options?: { cwd?: string | undefined; timeoutMs?: number | undefined },
  ): Promise<CommandResult>;
}

/** The slice of the filesystem port the preflight needs. */
export interface DoctorFileSystemPort {
  exists(path: string): Promise<boolean>;
  isDirectory(path: string): Promise<boolean>;
  listDirectory(path: string): Promise<readonly string[]>;
  ensureDirectory(path: string): Promise<void>;
  writeFile(path: string, contents: string): Promise<void>;
  remove(path: string): Promise<void>;
}

/** A pinned analysis tool as `tools.lock.json` declares it. */
export interface PinnedTool {
  readonly name: string;
  readonly version: string | null;
}

/** How the preflight learns which tools are pinned and where they live. */
export interface ToolProbe {
  listPinned(): Promise<readonly PinnedTool[]>;
  resolve(name: string): Promise<string | null>;
}

/** What one tool contributes, and therefore what its absence costs. */
export interface ToolCoverage {
  /** One sentence, reused verbatim in the report and in the scope proposals. */
  readonly sentence: string;
  readonly domains: readonly Domain[];
  /** Arguments that make the tool print its version. */
  readonly versionArgs: readonly string[];
}

/** Minimum Bun the pipeline is written against. */
export const MINIMUM_BUN_VERSION = "1.2.0";

/** Minimum git; below this, `git log` options the secret scan relies on differ. */
export const MINIMUM_GIT_VERSION = "2.30.0";

/** Free space the pinned toolchain needs on first download, with room to unpack. */
export const MINIMUM_FREE_DISK_BYTES = 2 * 1024 * 1024 * 1024;

/** Host probed to decide whether a first-run tool download can succeed. */
export const NETWORK_PROBE_URL = "https://github.com";

const SETUP_HINT = "Run `sentinel setup` to download the pinned tools (hash-verified, no sudo).";

/**
 * Every tool Sentinel knows about, with the coverage sentence the report and
 * the scope proposals quote. Tools pinned in the lock but missing here still
 * get a generic sentence, so a new pin never silently loses its disclosure.
 */
export const TOOL_CATALOGUE: Readonly<Record<string, ToolCoverage>> = {
  trivy: {
    sentence:
      "trivy missing → no dependency CVE scan, no SBOM or licence inventory, and no Dockerfile, compose, Kubernetes or Terraform misconfiguration checks.",
    domains: ["dependencies", "delivery"],
    versionArgs: ["--version"],
  },
  gitleaks: {
    sentence: "gitleaks missing → no secret scanning, including git history.",
    domains: ["appsec"],
    versionArgs: ["version"],
  },
  opengrep: {
    sentence:
      "opengrep missing → no SAST pass over Sentinel's rule pack, so injection, XSS and unsafe-input findings are limited to what the AI audit happens to read.",
    domains: ["appsec", "api"],
    versionArgs: ["--version"],
  },
  "ast-grep": {
    sentence:
      "ast-grep missing → no structural enumeration, so the inventory of routes, data-access sites, jobs and sinks is incomplete and coverage cannot be proven.",
    domains: ["appsec", "data", "serverless", "api"],
    versionArgs: ["--version"],
  },
  hadolint: {
    sentence: "hadolint missing → Dockerfile findings are limited to Sentinel's own rules.",
    domains: ["delivery"],
    versionArgs: ["--version"],
  },
  actionlint: {
    sentence:
      "actionlint missing → GitHub Actions workflows are checked only by Sentinel's own rules, with no shellcheck of `run:` steps.",
    domains: ["delivery"],
    versionArgs: ["--version"],
  },
  knip: {
    sentence:
      "knip missing → no unused file, export or dependency candidates, so the dead-code domain reports nothing.",
    domains: ["deadcode", "dependencies"],
    versionArgs: ["--version"],
  },
  "dependency-cruiser": {
    sentence: "dependency-cruiser missing → no circular-dependency or orphan-module detection.",
    domains: ["deadcode"],
    versionArgs: ["--version"],
  },
  eslint: {
    sentence:
      "eslint missing → no lint-rule corroboration for the reliability and maintainability findings.",
    domains: ["reliability", "deadcode"],
    versionArgs: ["--version"],
  },
};

/** The coverage sentence for a tool, with a safe fallback for unknown pins. */
export function coverageLossFor(tool: string): CoverageLoss {
  const known = TOOL_CATALOGUE[tool];
  if (known) {
    return { tool, sentence: known.sentence, domains: [...known.domains] };
  }
  return {
    tool,
    sentence: `${tool} missing → every check that depends on ${tool} is skipped and the domains it feeds are reported as not covered.`,
    domains: [],
  };
}

/** Arguments that make `tool` print its version. */
function versionArgsFor(tool: string): readonly string[] {
  return TOOL_CATALOGUE[tool]?.versionArgs ?? ["--version"];
}

/** Extracts the first dotted version number from arbitrary `--version` output. */
export function extractVersion(text: string): string | null {
  const match = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(text);
  return match ? match[0] : null;
}

/** Compares two dotted versions; missing or non-numeric segments read as 0. */
export function compareVersions(a: string, b: string): number {
  const left = a.split(".");
  const right = b.split(".");
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = Number.parseInt(left[index] ?? "0", 10);
    const rightPart = Number.parseInt(right[index] ?? "0", 10);
    const leftValue = Number.isNaN(leftPart) ? 0 : leftPart;
    const rightValue = Number.isNaN(rightPart) ? 0 : rightPart;
    if (leftValue !== rightValue) {
      return leftValue < rightValue ? -1 : 1;
    }
  }
  return 0;
}

/** True when `observed` is at least `minimum`. */
export function meetsMinimum(observed: string, minimum: string): boolean {
  return compareVersions(observed, minimum) >= 0;
}

/** Available bytes reported by `df -Pk`, or null when the output is unparseable. */
export function parseDfAvailableBytes(stdout: string): number | null {
  const lines = stdout.trim().split("\n");
  const last = lines[lines.length - 1];
  if (!last || lines.length < 2) {
    return null;
  }
  const columns = last.trim().split(/\s+/);
  // `df -Pk` guarantees one line per filesystem: available blocks are column 4.
  const available = columns[3];
  if (available === undefined) {
    return null;
  }
  const kibibytes = Number.parseInt(available, 10);
  return Number.isNaN(kibibytes) ? null : kibibytes * 1024;
}

/** Human-readable size, used only in check details. */
function formatBytes(bytes: number): string {
  const gib = bytes / (1024 * 1024 * 1024);
  if (gib >= 1) {
    return `${gib.toFixed(1)} GiB`;
  }
  return `${Math.round(bytes / (1024 * 1024))} MiB`;
}

/** The message of an unknown throwable, without leaking its shape. */
function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Home directory of the current user, with a neutral fallback. */
function homeDirectory(): string {
  return process.env.HOME ?? process.env.USERPROFILE ?? ".";
}

/** Where `sentinel setup` installs the pinned binaries. */
export function defaultCacheDir(): string {
  return join(homeDirectory(), ".cache", "sentinel", "tools");
}

/**
 * Flattens `tools.lock.json` — binaries and Node tools are separate records in
 * `contracts/tools.ts` — into the single name/version list the preflight walks.
 * `readToolsLock` has already validated the document, so nothing is re-parsed
 * here: a second, hand-written schema is exactly how the two drift apart.
 */
export function pinnedFromLock(lock: ToolsLock): PinnedTool[] {
  return [
    ...Object.entries(lock.binaries).map(([name, tool]) => ({ name, version: tool.version })),
    ...Object.entries(lock.node).map(([name, tool]) => ({ name, version: tool.version })),
  ];
}

/**
 * The single seam onto the tools package: everything the preflight knows about
 * pinned binaries arrives through these two calls, so a signature change in
 * `installer.ts` or `resolve.ts` is a one-function fix here. Imports are lazy
 * so that `doctor` stays loadable — and testable — without them.
 */
export function createToolProbe(): ToolProbe {
  return {
    async listPinned(): Promise<readonly PinnedTool[]> {
      const { readToolsLock } = await import("./installer.ts");
      return pinnedFromLock(await readToolsLock());
    },
    async resolve(name: string): Promise<string | null> {
      const { resolveTool } = await import("./resolve.ts");
      return await resolveTool(name, { allowPath: true });
    },
  };
}

/** Everything `runDoctor` needs; ports are injected, nothing is reached for directly. */
export interface DoctorOptions {
  readonly target: string;
  readonly outputDir: string;
  readonly fs: DoctorFileSystemPort;
  readonly proc: DoctorProcessPort;
  readonly tools?: ToolProbe | undefined;
  readonly cacheDir?: string | undefined;
  readonly bunVersion?: string | undefined;
  readonly platform?: string | undefined;
  readonly arch?: string | undefined;
  readonly now?: (() => Date) | undefined;
  /** Overridable so tests never touch the network. */
  readonly probeNetwork?: (() => Promise<boolean>) | undefined;
}

/** Builds a check, omitting the optional fields rather than setting them undefined. */
function check(
  base: Pick<DoctorCheck, "id" | "tier" | "label" | "status" | "detail">,
  extra: {
    remediation?: string | undefined;
    version?: string | undefined;
    expected?: string | undefined;
    path?: string | undefined;
  } = {},
): DoctorCheck {
  const result: DoctorCheck = { ...base };
  if (extra.remediation !== undefined) {
    result.remediation = extra.remediation;
  }
  if (extra.version !== undefined) {
    result.version = extra.version;
  }
  if (extra.expected !== undefined) {
    result.expected = extra.expected;
  }
  if (extra.path !== undefined) {
    result.path = extra.path;
  }
  return result;
}

/** Bun itself: read from the running runtime unless a caller pins it. */
function checkBun(observed: string): DoctorCheck {
  const ok = meetsMinimum(observed, MINIMUM_BUN_VERSION);
  return check(
    {
      id: "required.bun",
      tier: "required",
      label: "Bun runtime",
      status: ok ? "ok" : "fail",
      detail: ok ? observed : `${observed} is older than the minimum ${MINIMUM_BUN_VERSION}`,
    },
    {
      version: observed,
      expected: `>= ${MINIMUM_BUN_VERSION}`,
      remediation: ok ? undefined : "Upgrade Bun: `bun upgrade`, or reinstall from https://bun.sh.",
    },
  );
}

/** git, needed to resolve the target's history for the secret scan. */
async function checkGit(proc: DoctorProcessPort): Promise<DoctorCheck> {
  const base = { id: "required.git", tier: "required", label: "Git", status: "fail" } as const;
  const remediation = "Install git >= 2.30 (`xcode-select --install`, or your package manager).";
  let result: CommandResult;
  try {
    result = await proc.run("git", ["--version"], { timeoutMs: 10_000 });
  } catch (error) {
    return check(
      { ...base, detail: `git could not be executed: ${describeError(error)}` },
      { expected: `>= ${MINIMUM_GIT_VERSION}`, remediation },
    );
  }
  const observed = result.exitCode === 0 ? extractVersion(result.stdout) : null;
  if (observed === null) {
    return check(
      { ...base, detail: "git is not on PATH or did not report a version" },
      { expected: `>= ${MINIMUM_GIT_VERSION}`, remediation },
    );
  }
  const ok = meetsMinimum(observed, MINIMUM_GIT_VERSION);
  return check(
    {
      ...base,
      status: ok ? "ok" : "fail",
      detail: ok ? observed : `${observed} is older than the minimum ${MINIMUM_GIT_VERSION}`,
    },
    {
      version: observed,
      expected: `>= ${MINIMUM_GIT_VERSION}`,
      remediation: ok ? undefined : remediation,
    },
  );
}

/** The target must be a directory whose entries can actually be listed. */
async function checkTargetReadable(fs: DoctorFileSystemPort, target: string): Promise<DoctorCheck> {
  const base = {
    id: "required.target-readable",
    tier: "required",
    label: "Target readable",
    status: "fail",
  } as const;
  const remediation = `Point Sentinel at a readable directory, or fix the permissions on ${target}.`;
  try {
    if (!(await fs.isDirectory(target))) {
      return check({ ...base, detail: `${target} is not a directory` }, { remediation });
    }
    const entries = await fs.listDirectory(target);
    return check(
      { ...base, status: "ok", detail: `${entries.length} entries at the repository root` },
      { path: target },
    );
  } catch (error) {
    return check(
      { ...base, detail: `${target} could not be read: ${describeError(error)}` },
      { remediation },
    );
  }
}

/** The output directory must be writable now, not at the end of a long run. */
async function checkOutputWritable(
  fs: DoctorFileSystemPort,
  outputDir: string,
  stamp: number,
): Promise<DoctorCheck> {
  const base = {
    id: "required.output-writable",
    tier: "required",
    label: "Output dir writable",
    status: "fail",
  } as const;
  const probe = join(outputDir, `.sentinel-doctor-${stamp}.tmp`);
  try {
    await fs.ensureDirectory(outputDir);
    await fs.writeFile(probe, "sentinel doctor write probe\n");
    await fs.remove(probe);
    return check({ ...base, status: "ok", detail: outputDir }, { path: outputDir });
  } catch (error) {
    return check(
      { ...base, detail: `${outputDir} is not writable: ${describeError(error)}` },
      { remediation: `Create ${outputDir} with write permission, or pass --out <dir>.` },
    );
  }
}

/** Absent `.git` means the secret scan sees the working tree only. */
async function checkGitHistory(
  fs: DoctorFileSystemPort,
  target: string,
): Promise<{ readonly check: DoctorCheck; readonly loss: CoverageLoss | null }> {
  const base = {
    id: "optional.git-history",
    tier: "optional",
    label: "Git history",
    status: "ok",
  } as const;
  let present: boolean;
  try {
    present = await fs.exists(join(target, ".git"));
  } catch {
    present = false;
  }
  if (present) {
    return { check: check({ ...base, detail: "available for the secret scan" }), loss: null };
  }
  const sentence =
    "git history unavailable → secrets are scanned in the working tree only, so a credential that was committed and later removed is not found.";
  return {
    check: check(
      { ...base, status: "warn", detail: `${target} has no .git directory` },
      { remediation: "Run Sentinel against a git clone rather than an exported snapshot." },
    ),
    loss: { tool: "git-history", sentence, domains: ["appsec"] },
  };
}

/** Result of walking the pinned tool list. */
interface ToolTierResult {
  readonly checks: readonly DoctorCheck[];
  readonly coverageLoss: readonly CoverageLoss[];
  readonly missing: readonly string[];
}

/** One pinned tool: present with a version, present but odd, or missing. */
async function checkTool(
  proc: DoctorProcessPort,
  probe: ToolProbe,
  tool: PinnedTool,
): Promise<{ readonly check: DoctorCheck; readonly loss: CoverageLoss | null }> {
  const base = { id: `tools.${tool.name}`, tier: "tools", label: tool.name } as const;
  const expected = tool.version ?? undefined;
  let resolved: string | null;
  try {
    resolved = await probe.resolve(tool.name);
  } catch {
    resolved = null;
  }
  if (resolved === null) {
    const loss = coverageLossFor(tool.name);
    return {
      check: check(
        { ...base, status: "warn", detail: loss.sentence },
        { expected, remediation: SETUP_HINT },
      ),
      loss,
    };
  }

  let observed: string | null = null;
  try {
    const result = await proc.run(resolved, versionArgsFor(tool.name), { timeoutMs: 15_000 });
    observed = result.exitCode === 0 ? extractVersion(`${result.stdout}\n${result.stderr}`) : null;
  } catch {
    observed = null;
  }

  if (observed === null) {
    return {
      check: check(
        {
          ...base,
          status: "warn",
          detail: "installed but did not report a version; it may be corrupt",
        },
        { expected, path: resolved, remediation: SETUP_HINT },
      ),
      loss: null,
    };
  }
  // A drifted binary still runs, so this costs no coverage — only comparability.
  if (tool.version !== null && compareVersions(observed, tool.version) !== 0) {
    return {
      check: check(
        {
          ...base,
          status: "warn",
          detail: `found ${observed}, pinned ${tool.version}; results may differ from the pinned baseline`,
        },
        { version: observed, expected, path: resolved, remediation: SETUP_HINT },
      ),
      loss: null,
    };
  }
  return {
    check: check(
      { ...base, status: "ok", detail: observed },
      { version: observed, expected, path: resolved },
    ),
    loss: null,
  };
}

/** Walks the pinned list, falling back to the catalogue when the lock is unreadable. */
async function checkToolTier(proc: DoctorProcessPort, probe: ToolProbe): Promise<ToolTierResult> {
  const checks: DoctorCheck[] = [];
  const coverageLoss: CoverageLoss[] = [];
  const missing: string[] = [];

  let pinned: readonly PinnedTool[];
  try {
    pinned = await probe.listPinned();
  } catch (error) {
    checks.push(
      check(
        {
          id: "tools.lock",
          tier: "tools",
          label: "tools.lock.json",
          status: "warn",
          detail: `pinned tool list unreadable (${describeError(error)}); falling back to the built-in catalogue`,
        },
        { remediation: "Reinstall Sentinel's dependencies or restore src/tools/tools.lock.json." },
      ),
    );
    pinned = Object.keys(TOOL_CATALOGUE).map((name) => ({ name, version: null }));
  }

  const sorted = [...pinned].sort((left, right) => left.name.localeCompare(right.name));
  for (const tool of sorted) {
    const result = await checkTool(proc, probe, tool);
    checks.push(result.check);
    if (result.loss !== null) {
      coverageLoss.push(result.loss);
      missing.push(tool.name);
    }
  }
  return { checks, coverageLoss, missing };
}

/** Default reachability probe: a HEAD request with a short timeout, never in tests. */
async function defaultProbeNetwork(): Promise<boolean> {
  try {
    const response = await fetch(NETWORK_PROBE_URL, {
      method: "HEAD",
      signal: AbortSignal.timeout(5_000),
    });
    return response.ok || response.status < 500;
  } catch {
    return false;
  }
}

/** Network only matters when something still has to be downloaded. */
async function checkNetwork(
  missingCount: number,
  probe: () => Promise<boolean>,
): Promise<DoctorCheck> {
  const base = {
    id: "optional.network",
    tier: "optional",
    label: "Network",
    status: "ok",
  } as const;
  if (missingCount === 0) {
    return check({ ...base, detail: "not needed: every pinned tool is already installed" });
  }
  const reachable = await probe();
  if (reachable) {
    return check({ ...base, detail: `${NETWORK_PROBE_URL} reachable for the first-run download` });
  }
  return check(
    { ...base, status: "warn", detail: `${NETWORK_PROBE_URL} unreachable` },
    {
      remediation:
        "Connect to the network before `sentinel setup`, or copy a prepared tools cache onto this machine.",
    },
  );
}

/** Free space where the toolchain is unpacked. */
async function checkDiskSpace(
  proc: DoctorProcessPort,
  fs: DoctorFileSystemPort,
  cacheDir: string,
): Promise<DoctorCheck> {
  const base = {
    id: "optional.disk",
    tier: "optional",
    label: "Free disk",
    status: "ok",
  } as const;
  const unknown = check(
    { ...base, status: "warn", detail: "free disk space could not be determined" },
    {
      remediation: `Check manually that ${cacheDir} has ${formatBytes(MINIMUM_FREE_DISK_BYTES)} free.`,
    },
  );
  let probeDir = cacheDir;
  try {
    if (!(await fs.exists(cacheDir))) {
      probeDir = homeDirectory();
    }
  } catch {
    probeDir = homeDirectory();
  }
  try {
    const result = await proc.run("df", ["-Pk", probeDir], { timeoutMs: 10_000 });
    if (result.exitCode !== 0) {
      return unknown;
    }
    const available = parseDfAvailableBytes(result.stdout);
    if (available === null) {
      return unknown;
    }
    if (available >= MINIMUM_FREE_DISK_BYTES) {
      return check({ ...base, detail: `${formatBytes(available)} available on ${probeDir}` });
    }
    return check(
      {
        ...base,
        status: "warn",
        detail: `${formatBytes(available)} available on ${probeDir}, below the ${formatBytes(MINIMUM_FREE_DISK_BYTES)} the toolchain needs`,
      },
      { remediation: "Free disk space before running `sentinel setup`." },
    );
  } catch {
    return unknown;
  }
}

/**
 * Runs the whole preflight and returns a schema-validated report; it never
 * throws for a failed check, because a failed check *is* the result.
 */
export async function runDoctor(options: DoctorOptions): Promise<DoctorReport> {
  const now = options.now?.() ?? new Date();
  const cacheDir = options.cacheDir ?? defaultCacheDir();
  const probe = options.tools ?? createToolProbe();

  const bunVersion = options.bunVersion ?? Bun.version;

  const required: DoctorCheck[] = [
    checkBun(bunVersion),
    await checkGit(options.proc),
    await checkTargetReadable(options.fs, options.target),
    await checkOutputWritable(options.fs, options.outputDir, now.getTime()),
  ];

  const tools = await checkToolTier(options.proc, probe);
  const history = await checkGitHistory(options.fs, options.target);
  const optional: DoctorCheck[] = [
    await checkNetwork(tools.missing.length, options.probeNetwork ?? defaultProbeNetwork),
    await checkDiskSpace(options.proc, options.fs, cacheDir),
    history.check,
  ];

  const checks = [...required, ...tools.checks, ...optional];
  const coverageLoss = [...tools.coverageLoss, ...(history.loss === null ? [] : [history.loss])];

  return DoctorReportSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    generatedAt: now.toISOString(),
    target: options.target,
    outputDir: options.outputDir,
    cacheDir,
    environment: {
      platform: options.platform ?? process.platform,
      arch: options.arch ?? process.arch,
      bunVersion,
    },
    checks,
    coverageLoss,
    summary: summarizeChecks(checks),
    ready: isReady(checks),
  } satisfies DoctorReport);
}
