/**
 * Phase 1 — the scan.
 *
 * Runs the pinned analyzers and Sentinel's own rule packs over the target
 * concurrently, normalises everything they say into one set of `Finding`s, and
 * writes the run's artifacts.
 *
 * Three properties the rest of the pipeline depends on:
 *
 * - **A failing step is a reported step, not a failed run.** Every runner
 *   returns a `StepOutcome` instead of throwing; the orchestrator additionally
 *   guards each one with a wall-clock budget and a catch, so a step that hangs
 *   or throws becomes one `failed` line and the other nine still finish.
 * - **What did not run says so.** A step that cannot apply returns its own
 *   sentence — `hadolint: skipped: the target has no Dockerfile` — and that
 *   sentence travels into the coverage table and out into the report.
 * - **Cancellation reaches the children.** On abort the orchestrator stops
 *   scheduling and calls the process port's `killAll`, which signals each
 *   analyzer's whole process group, so Ctrl-C does not leave a trivy scan
 *   running in the background.
 */

import type { Coverage, Domain, Finding, FindingsDocument } from "../contracts/findings.ts";
import { isWithinScope } from "../contracts/scope.ts";
import { discoverDeliveryFiles } from "./_delivery-files.ts";
import {
  type ScanReport,
  ScanReportSchema,
  buildCoverage,
  buildFindingsDocument,
  toStepReport,
  writeFindingsDocument,
  writeScanReport,
} from "./artifacts.ts";
import { normaliseFindings } from "./normalise.ts";
import { CI_RULES_STEP, runCiRules } from "./rules/ci.ts";
import { CONTAINER_RULES_STEP, runContainerRules } from "./rules/container.ts";
import { ACTIONLINT_STEP, runActionlint } from "./runners/actionlint.ts";
import { DEPENDENCY_CRUISER_STEP, runDependencyCruiser } from "./runners/dependency-cruiser.ts";
import { GITLEAKS_STEP, runGitleaks } from "./runners/gitleaks.ts";
import { HADOLINT_STEP, runHadolint } from "./runners/hadolint.ts";
import { KNIP_STEP, runKnip } from "./runners/knip.ts";
import { OPENGREP_STEP, runOpengrep } from "./runners/opengrep.ts";
import { PACKAGE_MANAGER_STEP, runPackageManager } from "./runners/package-manager.ts";
import { TRIVY_STEP, runTrivy } from "./runners/trivy.ts";
import type { ScanContext, ScanStep, StepOutcome } from "./types.ts";

/**
 * How many steps run at once by default.
 *
 * Four, not "as many as there are steps": trivy, opengrep and gitleaks are each
 * happy to saturate a machine, and a laptop that swaps finishes later than one
 * that queues. This is unrelated to the AI fan-out limit in `contracts/config.ts`,
 * which is bounded by the subscription rather than by the CPU.
 */
export const DEFAULT_SCAN_PARALLELISM = 4;

/**
 * Slack between a step's command budget and the orchestrator's guard.
 *
 * The runner's own timeout should always fire first, because it can say *which*
 * command timed out and can still write what it had. The guard below is only
 * there for a step that hangs somewhere the runner does not have a timeout on.
 */
export const STEP_GRACE_MS = 30_000;

/** Command budgets, per step. A runner receives its own as `ctx.timeoutMs`. */
const TIMEOUTS = {
  trivy: 600_000,
  gitleaks: 600_000,
  opengrep: 600_000,
  knip: 300_000,
  dependencyCruiser: 300_000,
  packageManager: 120_000,
  actionlint: 120_000,
  hadolint: 120_000,
  rules: 60_000,
} as const;

/**
 * The phase 1 step registry, in the order the pool picks them up: the long
 * analyzers first, so the short ones fill the gaps while they run rather than
 * leaving one core busy at the end.
 *
 * `domains` is what the step *contributes to*, and is what a skip subtracts
 * from in the coverage table. opengrep's rule pack can tag a rule with any
 * domain, so it is listed against the ones its shipped pack actually covers.
 *
 * The file lists come from {@link discoverDeliveryFiles} rather than from the
 * profile alone, because phase 0 caps the evidence it carries per fact and a
 * repository with thirty workflows would otherwise have ten of them silently
 * left out of a coverage claim.
 */
export async function buildScanSteps(ctx: ScanContext): Promise<ScanStep[]> {
  const delivery = await discoverDeliveryFiles(ctx.fs, ctx.targetDir, ctx.profile);

  return [
    {
      name: TRIVY_STEP,
      domains: ["dependencies", "delivery"],
      timeoutMs: TIMEOUTS.trivy,
      run: (context) => runTrivy(context),
    },
    {
      name: GITLEAKS_STEP,
      domains: ["appsec"],
      timeoutMs: TIMEOUTS.gitleaks,
      run: (context) => runGitleaks(context),
    },
    {
      name: OPENGREP_STEP,
      domains: ["appsec", "data"],
      timeoutMs: TIMEOUTS.opengrep,
      run: (context) => runOpengrep(context),
    },
    {
      name: KNIP_STEP,
      domains: ["deadcode", "dependencies"],
      timeoutMs: TIMEOUTS.knip,
      run: (context) => runKnip(context),
    },
    {
      name: DEPENDENCY_CRUISER_STEP,
      domains: ["deadcode"],
      timeoutMs: TIMEOUTS.dependencyCruiser,
      run: (context) => runDependencyCruiser(context),
    },
    {
      name: PACKAGE_MANAGER_STEP,
      domains: ["dependencies"],
      timeoutMs: TIMEOUTS.packageManager,
      run: (context) => runPackageManager(context),
    },
    {
      name: ACTIONLINT_STEP,
      domains: ["delivery"],
      timeoutMs: TIMEOUTS.actionlint,
      run: (context) => runActionlint(context, { files: delivery.workflows }),
    },
    {
      name: HADOLINT_STEP,
      domains: ["delivery"],
      timeoutMs: TIMEOUTS.hadolint,
      run: (context) => runHadolint(context, { files: delivery.dockerfiles }),
    },
    {
      name: CI_RULES_STEP,
      domains: ["delivery"],
      timeoutMs: TIMEOUTS.rules,
      run: (context) => runCiRules(context, { files: delivery.workflows }),
    },
    {
      name: CONTAINER_RULES_STEP,
      domains: ["delivery"],
      timeoutMs: TIMEOUTS.rules,
      run: (context) =>
        runContainerRules(context, {
          dockerfiles: delivery.dockerfiles,
          composeFiles: delivery.composeFiles,
        }),
    },
  ];
}

/** Builds the per-step context: the shared one, with that step's command budget. */
function stepContext(ctx: ScanContext, step: ScanStep): ScanContext {
  return { ...ctx, timeoutMs: ctx.timeoutMs ?? step.timeoutMs };
}

/** An outcome for a step that never got to speak for itself. */
function synthetic(
  step: string,
  status: "skipped" | "failed",
  reason: string,
  durationMs: number,
): StepOutcome {
  return { step, status, reason, findings: [], artifacts: [], durationMs };
}

/**
 * Says so when a step failed because the run was cancelled underneath it.
 *
 * The runner reports what it saw — `gitleaks exited with code 143` — which is
 * accurate and useless to a reader who pressed Ctrl-C. Only a step that was
 * already running when the abort arrived is annotated, so the note is never a
 * guess about why something failed.
 */
function annotateCancelled(outcome: StepOutcome, cancelledDuring: boolean): StepOutcome {
  if (!cancelledDuring || outcome.status !== "failed") return outcome;
  const reason = outcome.reason ?? "";
  return {
    ...outcome,
    reason: `the run was cancelled while this step was running${reason === "" ? "" : `; the analyzer reported: ${reason}`}`,
  };
}

/**
 * Runs one step under a wall-clock guard and a catch.
 *
 * A runner is contracted never to throw, and this is what makes that contract
 * safe to rely on downstream: if one ever does, or hangs past its budget, the
 * breach is converted into a `failed` outcome here instead of unwinding the
 * pool and taking the other steps' findings with it.
 *
 * `graceMs` is the slack over the command budget, defaulting to
 * {@link STEP_GRACE_MS}; it is a parameter so a test can prove the guard fires
 * without waiting half a minute for it.
 */
export async function runStep(
  step: ScanStep,
  ctx: ScanContext,
  graceMs: number = STEP_GRACE_MS,
): Promise<StepOutcome> {
  const startedAt = performance.now();
  const budget = (ctx.timeoutMs ?? step.timeoutMs) + graceMs;
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    const guard = new Promise<StepOutcome>((resolve) => {
      timer = setTimeout(() => {
        resolve(
          synthetic(
            step.name,
            "failed",
            `the step did not finish within ${budget} ms and was abandoned; its analyzer may still be draining`,
            performance.now() - startedAt,
          ),
        );
      }, budget);
      timer.unref?.();
    });
    return await Promise.race([step.run(stepContext(ctx, step)), guard]);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return synthetic(
      step.name,
      "failed",
      `the step threw instead of returning an outcome: ${detail}`,
      performance.now() - startedAt,
    );
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs `worker` over `items` with at most `limit` in flight, returning the
 * results in the order of the input rather than the order they finished — the
 * document has to be reproducible, and completion order never is.
 */
export async function withPool<Item, Result>(
  items: readonly Item[],
  limit: number,
  worker: (item: Item, index: number) => Promise<Result>,
): Promise<Result[]> {
  const results = new Array<Result>(items.length);
  let cursor = 0;

  const lane = async (): Promise<void> => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item === undefined) return;
      results[index] = await worker(item, index);
    }
  };

  const lanes = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: lanes }, lane));
  return results;
}

/** Knobs the CLI turns; everything has a defensible default. */
export interface ScanOptions {
  /** Steps in flight at once. Default {@link DEFAULT_SCAN_PARALLELISM}. */
  readonly maxParallel?: number | undefined;
  /**
   * The enabled scope from phase 0.5. A step contributing to none of these
   * domains is not planned, and a finding outside them is counted and dropped.
   * Omitted means every domain.
   */
  readonly domains?: readonly Domain[] | undefined;
  /**
   * `--path`: the subtrees the run analysed.
   *
   * Phase 1 is **not** narrowed by it, and that is a decision rather than an
   * omission. Each of these analyzers reasons about a repository-level
   * artifact: trivy reads one lockfile, gitleaks reads one git history,
   * hadolint and actionlint read the Dockerfiles and workflows that build a
   * subtree from above it, and knip and dependency-cruiser would report an
   * export used only from outside the scope as dead if the module graph
   * stopped at the scope boundary. So the scope is carried here only to
   * *count*: {@link ScanResult.outsideScope} says how many of the findings
   * below came from files the run did not otherwise analyse, which is the
   * number that stops a scoped dossier reading as if those files had been.
   */
  readonly scope?: readonly string[] | undefined;
  /** Replaces the registry; the seam tests drive the orchestrator through. */
  readonly steps?: readonly ScanStep[] | undefined;
  /** CVE ids known to be exploited in the wild; feeds the severity policy's R3. */
  readonly knownExploitedCves?: ReadonlySet<string> | undefined;
  /** Write `findings.json` and `scan-report.json`. Default true. */
  readonly write?: boolean | undefined;
}

/** Everything phase 1 produced, in memory, whether or not it was written. */
export interface ScanResult {
  readonly runId: string;
  readonly target: string;
  /** One per planned step, in registry order. */
  readonly outcomes: readonly StepOutcome[];
  /** Verified, deduplicated and sorted. */
  readonly findings: readonly Finding[];
  readonly coverage: readonly Coverage[];
  readonly document: FindingsDocument;
  readonly report: ScanReport;
  /** Findings for a domain the run's scope excluded, counted rather than hidden. */
  readonly outOfScope: number;
  /**
   * Findings in files outside the analysed subtree — always `0` for a
   * whole-repository run.
   *
   * They are kept: a leaked credential in `libs/persistence` is a real finding
   * whatever `--path` said. What they are not is evidence that
   * `libs/persistence` was analysed, so they are counted here and disclosed
   * beside the scope rather than folded into the total in silence.
   */
  readonly outsideScope: number;
  /** True when the run was cancelled before every step finished. */
  readonly aborted: boolean;
  readonly durationMs: number;
  /** Absolute paths this phase wrote, raw tool output included. */
  readonly artifacts: readonly string[];
}

/**
 * Runs phase 1 end to end: plan, execute concurrently, normalise, write.
 *
 * Two runs over an unchanged repository produce byte-identical `findings.json`
 * apart from `runId` and `target`; the timings that necessarily differ live in
 * `scan-report.json`, which is why they are two documents.
 */
export async function runScan(ctx: ScanContext, options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = performance.now();
  const log = ctx.logger.child({ phase: "scan", runId: ctx.runId });
  const signal = ctx.signal;

  let aborted = signal?.aborted ?? false;
  const onAbort = (): void => {
    aborted = true;
    log.warn("scan cancelled; signalling every analyzer still running");
    void ctx.exec.killAll("SIGTERM");
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const registry = options.steps ?? (await buildScanSteps(ctx));
    const domains = options.domains;
    const steps =
      domains === undefined
        ? [...registry]
        : registry.filter((step) => step.domains.some((domain) => domains.includes(domain)));

    log.info("phase 1 planned", {
      steps: steps.map((step) => step.name),
      maxParallel: options.maxParallel ?? DEFAULT_SCAN_PARALLELISM,
    });

    const outcomes = await withPool(
      steps,
      options.maxParallel ?? DEFAULT_SCAN_PARALLELISM,
      async (step) => {
        if (aborted) {
          return synthetic(
            step.name,
            "skipped",
            "the run was cancelled before this step started",
            0,
          );
        }
        // Remembered before the step runs, so "the abort happened while this was
        // in flight" is a fact rather than an inference from the final state.
        const startedClean = !aborted;
        const outcome = annotateCancelled(await runStep(step, ctx), startedClean && aborted);
        log.info("step finished", {
          step: outcome.step,
          status: outcome.status,
          findings: outcome.findings.length,
          durationMs: Math.round(outcome.durationMs),
          ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
        });
        return outcome;
      },
    );

    const collected = outcomes.flatMap((outcome) => [...outcome.findings]);
    const inScope =
      domains === undefined
        ? collected
        : collected.filter((finding) => domains.includes(finding.domain));
    const outOfScope = collected.length - inScope.length;

    const normalised = await normaliseFindings(inScope, {
      targetDir: ctx.targetDir,
      fs: ctx.fs,
      ...(options.knownExploitedCves === undefined
        ? {}
        : { knownExploitedCves: options.knownExploitedCves }),
    });

    if (normalised.droppedFindings > 0) {
      log.warn("findings dropped: their citation did not resolve on disk", {
        dropped: normalised.droppedFindings,
        byReason: normalised.dropReasons,
      });
    }

    const coverage = buildCoverage(steps, outcomes, domains);
    const document = buildFindingsDocument({
      runId: ctx.runId,
      target: ctx.targetDir,
      findings: normalised.findings,
      coverage,
      droppedFindings: normalised.droppedFindings,
    });

    const report = ScanReportSchema.parse({
      schemaVersion: document.schemaVersion,
      runId: ctx.runId,
      target: ctx.targetDir,
      aborted,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
      steps: outcomes.map(toStepReport),
      dropped: {
        findings: normalised.droppedFindings,
        evidence: normalised.droppedEvidence,
        byReason: normalised.dropReasons,
      },
      relocated: normalised.relocated,
      merged: [...normalised.merged],
      escalations: [...normalised.escalations],
    });

    const artifacts = [...new Set(outcomes.flatMap((outcome) => [...outcome.artifacts]))].sort();
    if (options.write !== false) {
      await ctx.fs.mkdirp(ctx.runDir);
      artifacts.push(await writeFindingsDocument(ctx.fs, ctx.runDir, document));
      artifacts.push(await writeScanReport(ctx.fs, ctx.runDir, report));
    }

    // Counted over the written document, not over the raw outcomes: these are
    // the findings a reader will actually see in the dossier.
    const scope = (options.scope ?? []).filter((entry) => entry.trim() !== "");
    const outsideScope =
      scope.length === 0
        ? 0
        : document.findings.filter((finding) => !isWithinScope(finding.location.file, scope))
            .length;

    log.info("phase 1 finished", {
      findings: document.findings.length,
      dropped: document.droppedFindings,
      outOfScope,
      outsideScope,
      aborted,
      durationMs: report.durationMs,
    });

    return {
      runId: ctx.runId,
      target: ctx.targetDir,
      outcomes,
      findings: document.findings,
      coverage,
      document,
      report,
      outOfScope,
      outsideScope,
      aborted,
      durationMs: report.durationMs,
      artifacts,
    };
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}
