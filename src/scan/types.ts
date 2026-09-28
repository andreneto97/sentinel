/**
 * The contract every phase 1 step returns.
 *
 * Owned by the scan orchestrator; this file holds the shape the runners were
 * written against so they compile before the orchestrator lands. A runner never
 * throws — a missing tool, a crash, an unparseable payload or a degraded
 * database all come back as a {@link StepOutcome}, so the run reports honestly
 * what ran and what did not.
 */

import type { Domain, Finding } from "../contracts/findings.ts";
import type { StackProfile } from "../contracts/profile.ts";
import type { FileSystem } from "../ports/file-system.ts";
import type { Logger } from "../ports/logger.ts";
import type { ProcessExecutor } from "../ports/process-executor.ts";

/**
 * How a step ended.
 *
 * - `ok` — the step ran with everything it needs.
 * - `degraded` — it ran, but with less than it needs (a stale offline database,
 *   embedded fallback rules, truncated output); its findings are usable, its
 *   coverage is not complete.
 * - `skipped` — it could not apply: the tool is not installed, or the
 *   repository has nothing for it to look at.
 * - `failed` — it ran and its output cannot be trusted.
 */
export type StepStatus = "ok" | "degraded" | "skipped" | "failed";

/** What one phase 1 step contributed to the run. */
export interface StepOutcome {
  /** Step name, matching the tool it drives (`trivy`, `gitleaks`, ...). */
  readonly step: string;
  readonly status: StepStatus;
  /** Why the step is not `ok`, or context worth disclosing when it is. */
  readonly reason?: string | undefined;
  /** Verified findings; every snippet was extracted from disk by `src/verify`. */
  readonly findings: readonly Finding[];
  /** Paths written under `<runDir>/raw/`, so the report can point at the evidence. */
  readonly artifacts: readonly string[];
  readonly durationMs: number;
}

/**
 * The slice of `src/tools/resolve.ts#ToolResolver` phase 1 depends on. Declared
 * structurally so a test can say "these tools are installed" in one line.
 */
export interface ScanToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/**
 * Everything a phase 1 step is handed.
 *
 * The field names are the ones the runners were written against, so the
 * orchestrator passes this object straight into every runner — `RunnerContext`,
 * `TrivyRunContext`, `GitleaksContext` and `OpengrepContext` are all satisfied
 * structurally by it. `logger` and `signal` are the orchestrator's own and are
 * simply ignored by a runner that does not read them.
 */
export interface ScanContext {
  /** The filesystem port. The target repository is read, never written to. */
  readonly fs: FileSystem;
  /** The process port. The only way a step spawns anything. */
  readonly exec: ProcessExecutor;
  readonly tools: ScanToolResolver;
  /** Absolute path of the repository under analysis. */
  readonly targetDir: string;
  /** Absolute path of this run's output directory; `raw/` lives under it. */
  readonly runDir: string;
  /** Identifies the run in every artifact it writes. */
  readonly runId: string;
  /** Phase 0 output: what is worth running, and what cannot apply. */
  readonly profile?: StackProfile | undefined;
  readonly logger: Logger;
  /**
   * Cancels the whole phase. On abort the orchestrator stops scheduling and
   * calls the process port's `killAll`, so Ctrl-C reaches the analyzers
   * themselves rather than leaving them orphaned.
   */
  readonly signal?: AbortSignal | undefined;
  /** Allow a tool found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  /** Air-gapped run: registry-backed checks degrade instead of reaching out. */
  readonly offline?: boolean | undefined;
  /**
   * Overrides every step's own command budget. Left unset — the normal case —
   * each step uses the budget declared in {@link ScanStep.timeoutMs}.
   */
  readonly timeoutMs?: number | undefined;
  /** Overrides an analyzer's own cache location (a CI cache, or a test's temp dir). */
  readonly cacheDir?: string | undefined;
}

/** One unit of work in phase 1: a tool runner or one of Sentinel's own rule packs. */
export interface ScanStep {
  /** Matches the `step` field of the outcome it returns. */
  readonly name: string;
  /**
   * The domains this step contributes to. A step that is skipped subtracts from
   * every one of them, which is how "no Dockerfile" reaches the coverage table.
   */
  readonly domains: readonly Domain[];
  /** Wall-clock budget for the whole step, not only for the command it spawns. */
  readonly timeoutMs: number;
  /** Never throws: everything it can go wrong about comes back as an outcome. */
  run(ctx: ScanContext): Promise<StepOutcome>;
}
