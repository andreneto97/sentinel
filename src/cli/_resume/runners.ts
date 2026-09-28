/**
 * The real phase runners `sentinel resume` drives.
 *
 * This is a composition root, not logic: it builds the ports each phase needs —
 * the filesystem, the process executor, the tool resolver, a logger, the agent
 * runtime — and adapts what the phase returns into the one-line
 * {@link PhaseOutcome} the command prints. Everything above it is injectable, so
 * `resume.ts` is testable without a subprocess, a network call or a model.
 *
 * Two things here are not mere plumbing, and both exist to keep a re-run
 * honest:
 *
 * - **A re-audit never merges into a document that already holds its own
 *   output.** Phase 4's normal path merges into `findings.json`, whose coverage
 *   already contains the previous audit's rows; merging again would double
 *   every total. So a forced re-audit strips the previous audit out of the base
 *   document first, and a `--retry-failed` run recomposes the rows instead of
 *   adding them.
 * - **A retry re-dispatches exactly the batches that failed.** The batch ids in
 *   `audit.json` are content-addressed, so re-planning the same inventory
 *   reproduces them; the units behind the failed ids are the only ones sent
 *   again. When the plan contains *none* of those ids — the inventory changed
 *   under the run — the retry refuses rather than quietly auditing something
 *   else, and when it contains only some of them it names the rest instead of
 *   passing over them. Reproducing the ids means re-planning under the ceilings
 *   the original attempt used, which is why the budget is recovered from
 *   `bound.limits` rather than defaulted: an unbounded first attempt re-planned
 *   under the default batch ceiling yields a plan ordered by risk, which holds
 *   none of the migration or workflow-job batches whose ids a retry looks for.
 */

import { join } from "node:path";
import type { CitedRanges } from "../../audit/batch.ts";
import type { AuditBudget } from "../../audit/budget.ts";
import type { AuditProgress } from "../../audit/progress.ts";
import type { Domain, FindingsDocument } from "../../contracts/findings.ts";
import { StackProfileSchema } from "../../contracts/profile.ts";
import { partitionUnits } from "../../contracts/scope.ts";
import type { FileSystem } from "../../ports/file-system.ts";
import type { Logger } from "../../ports/logger.ts";
import type { ToolResolver } from "../../tools/resolve.ts";
import { SCOPE_PROPOSAL_FILE, STACK_PROFILE_FILE } from "../_shared/run-artifacts.ts";
import type { CliContext } from "../index.ts";
import type { PhaseOutcome, PhaseRequest, ResumeRunners } from "../resume.ts";
import {
  mergeRetryIntoAudit,
  subtractAuditFromFindings,
  unitIdsOfBatches,
  writeMergedRetry,
} from "../resume.ts";

/** Knobs the CLI passes down; everything else is built here. */
export interface ResumeRunnerOptions {
  /** `--verbose`: raises the log threshold on stderr. */
  readonly verbose: boolean;
  /** `--quiet`: phase 4 reports no per-batch progress. */
  readonly quiet?: boolean;
  /** `--json`: per-batch progress goes to stderr as JSON, one object per line. */
  readonly json?: boolean;
  /** Batches in flight at once when nothing else says. */
  readonly defaultParallel?: number;
}

/** Default batches in flight; matches phase 4's own default under `analyze`. */
const DEFAULT_PARALLEL = 2;

/** Two-space JSON with a trailing newline, matching every other artifact. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** `1 unit` / `4 units`, with `-es` after a sibilant. */
function plural(count: number, noun: string): string {
  if (count === 1) return `${count} ${noun}`;
  return `${count} ${noun}${/(?:s|x|z|ch|sh)$/.test(noun) ? "es" : "s"}`;
}

/**
 * Builds the six real runners.
 *
 * Every port is created lazily and shared: a resume that only renders the
 * report never constructs a tool resolver, and a resume that runs three phases
 * constructs one resolver for all of them — so the scan and the inventory can
 * never disagree about which analyzers exist.
 */
export function createResumeRunners(
  context: CliContext,
  options: ResumeRunnerOptions,
): ResumeRunners {
  const parallel = options.defaultParallel ?? DEFAULT_PARALLEL;

  let progressWriter: Promise<AuditProgress | undefined> | undefined;
  /** Phase 4's per-batch reporter, built from this command's own output flags. */
  const auditProgress = async (): Promise<AuditProgress | undefined> => {
    progressWriter ??= (async () =>
      (await import("../../audit/progress.ts")).createProgressWriter({
        write: context.write,
        writeError: context.writeError,
        ...(options.verbose === undefined ? {} : { verbose: options.verbose }),
        ...(options.quiet === undefined ? {} : { quiet: options.quiet }),
        ...(options.json === undefined ? {} : { json: options.json }),
      }))();
    return progressWriter;
  };

  let filesystem: Promise<FileSystem> | undefined;
  /** The real filesystem port, built once and shared by every phase below. */
  const fsPort = (): Promise<FileSystem> => {
    filesystem ??= (async () => (await import("../../ports/file-system.ts")).createFileSystem())();
    return filesystem;
  };

  let resolver: Promise<ToolResolver> | undefined;
  const tools = (): Promise<ToolResolver> => {
    resolver ??= (async () => {
      const [resolve, installer, fs] = await Promise.all([
        import("../../tools/resolve.ts"),
        import("../../tools/installer.ts"),
        fsPort(),
      ]);
      return resolve.createToolResolver({ lock: await installer.readToolsLock(), fs });
    })();
    return resolver;
  };

  /** Tools that are actually present; a missing lockfile means "none". */
  const availableTools = async (): Promise<readonly string[]> => {
    try {
      const statuses = await (await tools()).statusAll({ allowPath: true });
      return statuses.filter((status) => status.path !== null).map((status) => status.name);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      context.writeError(`sentinel: could not read the pinned tool list (${message})\n`);
      return [];
    }
  };

  const buildLogger = async (): Promise<Logger> => {
    const logging = await import("../../ports/logger.ts");
    return logging.createJsonLogger({
      level: logging.parseLogThreshold(context.env.SENTINEL_LOG, options.verbose ? "info" : "warn"),
      write: (line: string) => {
        context.writeError(`${line}\n`);
      },
    });
  };

  /** Runs `work` with Ctrl-C wired to an abort signal, exactly as `analyze` does. */
  const withCancellation = async <T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> => {
    const controller = new AbortController();
    const onSignal = (): void => controller.abort();
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    try {
      return await work(controller.signal);
    } finally {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    }
  };

  /** The scope a run recorded, or every domain when it recorded none. */
  const domainsOf = (request: PhaseRequest): readonly Domain[] | undefined =>
    request.artifacts.scope?.decision.enabledDomains;

  /**
   * The subtrees the original run analysed, from its own `analysis-scope.json`.
   *
   * Re-entering a run must not widen it. A `--path apps/api` run whose audit is
   * resumed over the whole repository's inventory would spend the hours the flag
   * exists to avoid, and would leave a dossier whose scope artifact and whose
   * coverage disagree.
   */
  const pathsOf = (request: PhaseRequest): readonly string[] =>
    request.artifacts.analysisScope?.paths ?? [];

  /**
   * The run-level ceilings the original attempt planned under.
   *
   * `audit.json` records them in `bound.limits`, so `--no-budget` survives a
   * resume instead of being re-imposed as the default. A run with no recorded
   * bound keeps the default, which is what a fresh plan would have used anyway.
   */
  const spendOf = (request: PhaseRequest): { readonly spend?: AuditBudget } => {
    const limits = request.artifacts.audit?.bound?.limits;
    return limits === undefined ? {} : { spend: limits };
  };

  return {
    async profile(request: PhaseRequest): Promise<PhaseOutcome> {
      const [{ profileStack }, fs] = await Promise.all([
        import("../../profile/index.ts"),
        fsPort(),
      ]);
      const paths = pathsOf(request);
      const profile = await profileStack(fs, request.targetDir, {
        ...(paths.length === 0 ? {} : { analysisScope: paths }),
      });
      const path = join(request.runDir, STACK_PROFILE_FILE);
      await fs.writeFile(path, serialise(StackProfileSchema.parse(profile)));
      return {
        ok: true,
        summary: `${plural(profile.facts.length, "stack fact")} detected in ${request.targetDir}`,
        artifacts: [path],
      };
    },

    async propose(request: PhaseRequest): Promise<PhaseOutcome> {
      const [propose, fs, available] = await Promise.all([
        import("../../propose/index.ts"),
        fsPort(),
        availableTools(),
      ]);
      const profile =
        request.artifacts.profile ??
        (await (await import("../../profile/index.ts")).profileStack(fs, request.targetDir));
      const set = propose.proposeScope(
        propose.createProposalContext({
          profile: propose.toProfileView(profile),
          availableTools: available,
          // The path scope the run recorded, when it recorded exactly one; see
          // `analyze` for why several paths fall back to the repository root.
          analysedPath: pathsOf(request).length === 1 ? (pathsOf(request)[0] ?? ".") : ".",
        }),
      );
      const decision = propose.decideScope(set, {
        acceptDefaults: true,
        availableTools: available,
      });
      const path = join(request.runDir, SCOPE_PROPOSAL_FILE);
      await fs.writeFile(
        path,
        propose.renderScopeProposalJson(
          propose.buildScopeProposalDocument({
            runId: request.runId,
            target: request.targetDir,
            decision,
          }),
        ),
      );
      return {
        ok: true,
        summary: `${decision.enabledDomains.length} domain(s) enabled from the proposal defaults`,
        artifacts: [path],
        notes: [
          "resume answered the scope proposals with their defaults; `sentinel analyze` is where a human answers them.",
        ],
      };
    },

    async scan(request: PhaseRequest): Promise<PhaseOutcome> {
      const profile = request.artifacts.profile;
      if (profile === null) {
        return {
          ok: false,
          summary: `${STACK_PROFILE_FILE} is missing, so phase 1 has no stack to scan against`,
          artifacts: [],
        };
      }
      const [scan, processExecutor, fs, logger, toolset] = await Promise.all([
        import("../../scan/scan.ts"),
        import("../../ports/process-executor.ts"),
        fsPort(),
        buildLogger(),
        tools(),
      ]);
      const domains = domainsOf(request);
      const exec = processExecutor.createProcessExecutor();
      const result = await withCancellation((signal) =>
        scan.runScan(
          {
            fs,
            exec,
            tools: toolset,
            targetDir: request.targetDir,
            runDir: request.runDir,
            runId: request.runId,
            profile,
            logger,
            signal,
            allowPathTools: true,
          },
          {
            ...(domains === undefined ? {} : { domains }),
            ...(pathsOf(request).length === 0 ? {} : { scope: pathsOf(request) }),
          },
        ),
      );
      return {
        ok: !result.aborted,
        summary: result.aborted
          ? "the scan was cancelled before every step finished"
          : `${plural(result.outcomes.length, "step")}, ${plural(result.findings.length, "finding")}`,
        artifacts: result.artifacts,
        ...(domains === undefined
          ? {
              notes: [`${SCOPE_PROPOSAL_FILE} records no scope, so every domain was scanned.`],
            }
          : {}),
      };
    },

    async inventory(request: PhaseRequest): Promise<PhaseOutcome> {
      const profile = request.artifacts.profile;
      if (profile === null) {
        return {
          ok: false,
          summary: `${STACK_PROFILE_FILE} is missing, so phase 2 cannot enumerate anything`,
          artifacts: [],
        };
      }
      const [inventory, processExecutor, fs, toolset] = await Promise.all([
        import("../../inventory/inventory.ts"),
        import("../../ports/process-executor.ts"),
        fsPort(),
        tools(),
      ]);
      const exec = processExecutor.createProcessExecutor();
      const result = await withCancellation((signal) =>
        inventory.runInventory({
          fs,
          exec,
          tools: toolset,
          targetDir: request.targetDir,
          runDir: request.runDir,
          runId: request.runId,
          profile,
          allowPathTools: true,
          signal,
        }),
      );
      return {
        ok: true,
        summary: `${plural(result.document.units.length, "unit")} of audit enumerated`,
        artifacts: result.artifacts,
      };
    },

    async audit(request: PhaseRequest): Promise<PhaseOutcome> {
      const enumerated = request.artifacts.inventory?.units;
      if (enumerated === undefined) {
        return {
          ok: false,
          summary: "inventory.json is missing, so there are no units to audit",
          artifacts: [],
        };
      }
      // `inventory.json` is the whole repository's enumeration even for a scoped
      // run, so the boundary has to be re-applied here rather than assumed.
      const paths = pathsOf(request);
      const units = paths.length === 0 ? enumerated : partitionUnits(enumerated, paths).inScope;
      if (units.length === 0 && enumerated.length > 0) {
        return {
          ok: false,
          summary: `every one of the ${enumerated.length} enumerated units is outside this run's --path scope, so there is nothing to audit`,
          artifacts: [],
        };
      }
      const profile = request.artifacts.profile ?? undefined;
      const [audit, batch, verdict, agents, fs, logger] = await Promise.all([
        import("../../audit/audit.ts"),
        import("../../audit/batch.ts"),
        import("../../audit/verdict.ts"),
        import("../../agents/index.ts"),
        fsPort(),
        buildLogger(),
      ]);

      // The ceiling the *original* run planned under, recovered from its own
      // `bound.limits`. Without this a run launched with `--no-budget` is
      // re-planned under DEFAULT_MAX_BATCHES on the way back in: the leading
      // batches by risk are route handlers, so every migration and workflow-job
      // batch vanishes from the plan. The units a quota stop left unaudited are
      // exactly the ones a resume exists to reach, and the retry below would
      // then resolve its failed batch ids against a plan no longer holding them.
      const planner = batch.createBatchPlanner(spendOf(request));
      const ranges = new Map<string, CitedRanges>();
      /** The line-level slice gate, wired exactly as `analyze` wires it. */
      const shown = (dispatched: { readonly id: string }) => {
        let own = ranges.get(dispatched.id);
        if (own === undefined) {
          const planned = planner
            .plan()
            ?.batches.find((candidate) => candidate.id === dispatched.id);
          if (planned !== undefined) {
            own = batch.citedRanges(planned);
            ranges.set(dispatched.id, own);
          }
        }
        const index = own;
        return index === undefined
          ? () => true
          : (file: string, line: number) => batch.wasShown(index, file, line);
      };

      const previous = request.artifacts.audit;
      const domains = domainsOf(request);
      const concurrency = request.maxParallel ?? parallel;

      /** Units this dispatch is about, and the batches it replaces. */
      let dispatchUnits = units;
      let retriedUnitIds: readonly string[] = [];
      /** What re-planning revealed, merged into the phase's notes below. */
      const planNotes: string[] = [];
      /** Batch ids the retry really re-dispatched, for the merge below. */
      let replacedBatchIds: readonly string[] = request.retryBatchIds ?? [];
      if (request.retryBatchIds !== undefined) {
        const wanted = new Set(request.retryBatchIds);
        const planned = await planner(units, {
          fs,
          targetDir: request.targetDir,
          runDir: request.runDir,
          ...(profile === undefined ? {} : { profile }),
        });
        // A batch id is how a retry *names* what failed, but the thing that has
        // to be re-asked is a unit with no verdict — and the two can come apart.
        // A previous merge that dropped a failed batch's record, or a re-plan that
        // packs the same units differently, leaves units pending under a batch id
        // nobody asked for. So the fresh plan's batches that hold a pending unit
        // join the set: `--retry-failed` means "re-dispatch what this run has no
        // verdict for", which is both what the flag promises and what the recompose
        // below is able to fold back in.
        if (previous !== null) {
          const pending = new Set<string>();
          for (const row of previous.kinds) {
            for (const skip of row.skipped) pending.add(skip.unitId);
          }
          for (const candidate of planned) {
            if (candidate.units.some((unit) => pending.has(unit.id))) wanted.add(candidate.id);
          }
        }
        retriedUnitIds = unitIdsOfBatches(planned, wanted);
        if (retriedUnitIds.length === 0) {
          return {
            ok: false,
            summary: `none of the ${wanted.size} failed batch(es) exist in a fresh plan of this inventory, so they cannot be retried; use --force-phase audit to re-dispatch everything`,
            artifacts: [],
          };
        }
        // A *partial* resolution must not pass in silence: a retry that reports
        // "replaced N batches covering M units" while the batches a quota stop
        // killed are not among them is a retry that read as complete. Any id the
        // plan does not hold is named here, because the units behind it keep the
        // verdict they never got and the reader has to know the retry did not
        // reach them.
        const asked = wanted.size;
        const unresolved = [...wanted].filter(
          (id) => !planned.some((candidate) => candidate.id === id),
        );
        // Only these batches are superseded. An id the plan did not hold was not
        // re-dispatched, so its report — often a `failed` one — has to survive the
        // merge; see `mergeRetryIntoAudit`.
        for (const id of unresolved) wanted.delete(id);
        replacedBatchIds = [...wanted];
        if (unresolved.length > 0) {
          const named = unresolved.slice(0, 6).join(", ");
          const rest = unresolved.length > 6 ? `, and ${unresolved.length - 6} more` : "";
          planNotes.push(
            `${unresolved.length} of the ${asked} batch(es) asked for are not in a fresh plan of this inventory, so their units were not retried: ${named}${rest}.`,
            "A plan is a function of the inventory, the scope and the run's ceilings, so one of those differs from the attempt that produced those ids.",
          );
        }
        const keep = new Set(retriedUnitIds);
        dispatchUnits = units.filter((unit) => keep.has(unit.id));
      }

      const auditContext = {
        fs,
        targetDir: request.targetDir,
        runDir: request.runDir,
        runId: request.runId,
        ...(profile === undefined ? {} : { profile }),
        logger,
      };

      // A previous audit exists, so writing through phase 4's own merge would
      // add its coverage to itself. Both re-run paths take the document apart
      // first and write it back deliberately.
      const write = previous === null;
      const progress = await auditProgress();
      const result = await withCancellation(async (signal) => {
        const runtime = agents.createClaudeAgentRuntime({
          fs,
          runDir: request.runDir,
          concurrency,
          logger,
          signal,
        });
        return await audit.runAudit(
          { ...auditContext, signal },
          {
            runtime,
            verdicts: verdict.verdictSource(),
            batches: planner,
            prompt: batch.buildPrompt,
            units: dispatchUnits,
            ...(domains === undefined ? {} : { domains }),
            shown,
            write,
            // A resumed audit is as long as a fresh one, so it reports the
            // same way: silence for an hour is what the progress writer exists
            // to prevent (src/audit/progress.ts).
            ...(progress === undefined ? {} : { progress }),
          },
        );
      });

      const artifacts: string[] = [...result.artifacts];
      const notes: string[] = [...planNotes];

      if (previous !== null) {
        const base = request.artifacts.findings;
        if (base === null) {
          return {
            ok: false,
            summary:
              "findings.json is missing, so the audit's output has no document to merge into",
            artifacts: [],
          };
        }
        if (request.retryBatchIds === undefined) {
          // A full re-audit: the previous audit's own findings, assurances and
          // coverage come out of the base document, then the fresh audit goes in
          // through phase 4's normal merge.
          const documents = await import("../../audit/artifacts.ts");
          const stripped: FindingsDocument = subtractAuditFromFindings(base, previous);
          const merged = documents.mergeAuditIntoFindings(stripped, {
            runId: request.runId,
            target: request.targetDir,
            findings: result.findings,
            assurances: result.assurances,
            coverage: result.coverage,
            droppedFindings: result.dropped.unresolved + result.dropped.outOfSlice,
          });
          artifacts.push(await documents.writeMergedFindings(fs, request.runDir, merged));
          artifacts.push(await documents.writeAuditReport(fs, request.runDir, result.report));
          artifacts.push(
            await documents.writeAssurancesDocument(
              fs,
              request.runDir,
              documents.buildAssurancesDocument({
                runId: request.runId,
                target: request.targetDir,
                assurances: result.assurances,
                coverage: result.coverage,
              }),
            ),
          );
          notes.push(
            "The previous audit's findings and coverage were removed before this one was merged in, so no total was counted twice.",
          );
        } else {
          const merged = mergeRetryIntoAudit(previous, base, {
            report: result.report,
            findings: result.findings,
            assurances: result.assurances,
            replacedBatchIds: [...replacedBatchIds],
            retriedUnitIds,
          });
          artifacts.push(...(await writeMergedRetry(fs, request.runDir, merged)));
          notes.push(
            `The retry replaced ${plural(request.retryBatchIds.length, "batch")} covering ${plural(retriedUnitIds.length, "unit")}; coverage rows were recomposed, not added.`,
            "Findings were merged by id: a problem the previous attempt reported and this one did not is kept, not deleted.",
          );
        }
      }

      const failed = result.batches.filter((entry) => entry.status === "failed").length;
      return {
        ok: !result.aborted,
        summary: `${result.units.audited}/${result.units.total} units audited across ${plural(result.batches.length, "batch")}${failed > 0 ? `, ${failed} failed` : ""}; ${plural(result.findings.length, "finding")}, ${plural(result.assurances.length, "assurance")}`,
        artifacts,
        notes,
      };
    },

    async report(request: PhaseRequest): Promise<PhaseOutcome> {
      const [report, fs] = await Promise.all([import("../report.ts"), fsPort()]);
      try {
        const rendered = await report.renderDossier(request.artifacts, {
          select: report.selectionFor("all"),
          sentinelVersion: context.version,
        });
        const written = await report.writeDossier(fs, request.runDir, rendered);
        const score = rendered.scorecard.overall;
        return {
          ok: true,
          summary: `${written.length} file(s) rendered, score ${score.score === null ? "not assessed" : `${score.score} (${score.band})`} — no AI was spent`,
          artifacts: written.map((entry) => entry.path),
        };
      } catch (error) {
        return {
          ok: false,
          summary: error instanceof Error ? error.message : String(error),
          artifacts: [],
        };
      }
    },
  };
}
