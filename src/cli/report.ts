/**
 * `sentinel report <run-dir>` — phases 6 and 7, on their own, for free.
 *
 * The point of this verb is that rendering is a pure function of a run
 * directory. Phases 1 to 5 cost minutes and, for two of them, subscription
 * budget; scoring what they produced and turning it into a dossier costs
 * nothing. So a wording bug in a renderer, a missing column, a table nobody can
 * read — all of it is fixed by editing `src/report/` and re-rendering a run that
 * was already paid for.
 *
 * Which gives this command exactly three jobs:
 *
 * - **Spend nothing.** No agent runtime is constructed, no tool is resolved, no
 *   file in the target repository is opened. Every snippet in the document was
 *   extracted and verified by `src/verify` when the finding was created, so the
 *   renderers need no repository at all — only the artifacts.
 * - **Refuse clearly.** A run directory missing the artifact the render needs is
 *   named, with the file. Optional artifacts are different: `inventory.json`
 *   missing costs the endpoint matrix, and the report says so rather than
 *   failing.
 * - **Score, then render.** Phase 6 is deterministic and cheap, so it is
 *   recomputed here from the findings, the coverage and the two phase reports
 *   rather than read from disk. Both renderers get the same scorecard, which is
 *   why the PDF and the markdown cannot disagree about a number.
 *
 * `--triage <file>` adds a fourth: **apply a human review without editing the
 * run.** The reviewer's verdicts are read and validated like any other document,
 * the adjusted findings are written to `findings.triaged.json` *beside* the
 * original — which is never touched, so the raw model output stays auditable —
 * the scores are recomputed from the corrected severities, and the dossier
 * states who reviewed it, what changed, and how much of it nobody reviewed.
 */

import { isAbsolute, join, resolve } from "node:path";
import { AUDIT_FILE } from "../audit/artifacts.ts";
import type { Domain, FindingsDocument } from "../contracts/findings.ts";
import { INVENTORY_FILE } from "../contracts/inventory.ts";
import type { AnalysisScope } from "../contracts/scope.ts";
import { renderScopePaths } from "../contracts/scope.ts";
import type { Scorecard, DomainScore as ScoredDomain } from "../contracts/scorecard.ts";
import type { TriageDocument } from "../contracts/triage.ts";
import { TRIAGED_FINDINGS_FILE, TriageDocumentSchema } from "../contracts/triage.ts";
import type { BriefOmissions } from "../report/brief.ts";
import {
  REPORT_BRIEF_MARKDOWN_FILE,
  buildBriefModel,
  renderBriefMarkdown,
} from "../report/brief.ts";
import { ISSUES_FILE, buildIssues, renderIssuesMarkdown } from "../report/issues.ts";
import type { DossierInput, DossierScore } from "../report/markdown.ts";
import { REPORT_MARKDOWN_FILE, renderReportMarkdown } from "../report/markdown.ts";
import type { ScorecardInput as PdfScorecardInput } from "../report/pdf/index.ts";
import {
  REPORT_BRIEF_PDF_FILE,
  REPORT_PDF_FILE,
  buildReportModel,
  renderBriefDocument,
  renderReportPdf,
  reportInputFromRunArtifacts,
} from "../report/pdf/index.ts";
import type { DomainScorer, TriageSummary } from "../report/triage.ts";
import { StaleTriageError, applyTriage } from "../report/triage.ts";
import { SCAN_REPORT_FILE } from "../scan/artifacts.ts";
import { buildScorecardFromArtifacts } from "../score/index.ts";
import type { RunArtifacts } from "./_shared/run-artifacts.ts";
import {
  MissingArtifactError,
  type RunArtifactFileSystem,
  type RunVerdict,
  SCOPE_PROPOSAL_FILE,
  STACK_PROFILE_FILE,
  assessRun,
  describeRunPhases,
  loadRunArtifacts,
  requireFindings,
} from "./_shared/run-artifacts.ts";
import { type RunDirFileSystem, type RunDirResolution, resolveRunDir } from "./_shared/run-dir.ts";
import type { CliContext, OutputFlags } from "./index.ts";
import { EXIT } from "./index.ts";

/**
 * What `--format` accepts. `all` is the default and renders the three files.
 *
 * `brief` is the one value that renders *neither* of the dossier's two prose
 * files: it produces only `report-brief.pdf` and `report-brief.md`, which is what
 * makes iterating on the short document cheap when the full dossier runs to
 * hundreds of pages. `--brief` adds those two files to any other format instead
 * of replacing it, so `--format all --brief` writes all five.
 */
export const REPORT_FORMATS = ["all", "pdf", "md", "issues", "brief"] as const;

/** One of {@link REPORT_FORMATS}. */
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** A parsed `sentinel report` invocation. */
export interface ReportInvocation {
  /** The `<run-dir>` argument as typed: a run directory or an output directory. */
  readonly runDir: string;
  readonly cwd: string;
  readonly output: OutputFlags;
  readonly format: ReportFormat;
  /** Write the rendered files here instead of into the run directory. */
  readonly out?: string | undefined;
  /**
   * `--triage <file>`: a reviewer's verdicts, applied before the render.
   *
   * The path as typed; relative paths resolve against {@link ReportInvocation.cwd}.
   */
  readonly triage?: string | undefined;
  /**
   * `--brief`: also render the executive brief.
   *
   * Additive rather than exclusive, because the brief is a second document about
   * the same run and not a different rendering of it: a reader gets the brief
   * *and* the dossier it summarises, and the brief's own last page names the
   * dossier by file name. `--format brief` is the way to ask for the brief alone.
   */
  readonly brief?: boolean | undefined;
}

/** The filesystem surface rendering needs: read the artifacts, write the files. */
export interface ReportFileSystem extends RunArtifactFileSystem, RunDirFileSystem {
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
}

/** Everything the command reaches outside itself. */
export interface ReportDeps {
  readonly fs: ReportFileSystem;
}

/** One rendered file. */
export interface RenderedFile {
  readonly file: string;
  readonly path: string;
  readonly bytes: number;
}

/** What `--json` prints. */
export interface ReportJson {
  readonly runId: string;
  readonly runDir: string;
  readonly outDir: string;
  readonly format: ReportFormat;
  readonly written: readonly RenderedFile[];
  readonly findings: number;
  readonly assurances: number;
  /** Phase 6's run-level number, or null when no domain earned one. */
  readonly score: number | null;
  readonly band: string | null;
  readonly confidence: string;
  /** True when the run is complete enough to hand to a client. */
  readonly shareable: boolean;
  /** Why it is not, when it is not. */
  readonly blockers: readonly string[];
  /** Optional artifacts that were absent, and what their absence cost. */
  readonly degraded: readonly string[];
  /** What `--triage` changed; absent when no review was applied. */
  readonly triage?: ReportTriageJson | undefined;
  /** What the brief detailed and what it only counted; absent without `--brief`. */
  readonly brief?: ReportBriefJson | undefined;
}

/** The brief, as `--json` reports it: the split, so a caller can check it. */
export interface ReportBriefJson {
  /** Findings printed in full: every critical and high. */
  readonly detailed: number;
  /** Findings that appear only as a counted row. */
  readonly counted: number;
  /** Counted rules, one row each. */
  readonly groups: number;
  /** Detailed findings carrying no human verdict; 0 is the claim worth making. */
  readonly detailedUnreviewed: number;
  /** Counted findings carrying no human verdict. */
  readonly countedUnreviewed: number;
}

/** The review, as `--json` reports it. */
export interface ReportTriageJson {
  readonly reviewer: string;
  /** The triage file this render read, resolved. */
  readonly file: string;
  /** Where the adjusted findings were written; `findings.json` is untouched. */
  readonly findingsFile: string;
  readonly reviewed: number;
  readonly confirmed: number;
  readonly corrected: number;
  readonly withheld: number;
  readonly contested: number;
  /** Findings in the rendered dossier that no human examined. */
  readonly unreviewed: number;
}

/** The sentence each failed resolution gets; `<run-dir>` accepts two shapes. */
export function describeRunDirFailure(
  resolution: RunDirResolution & { ok: false },
  path: string,
): string {
  switch (resolution.reason) {
    case "not-found":
      return `${path} does not exist`;
    case "no-latest":
      return `${path} is neither a run directory nor an output directory with a .latest pointer`;
    case "not-a-run-dir":
      return `${join(path, ".latest")} does not name a run directory`;
    default:
      return `${path} could not be resolved`;
  }
}

/** Two-space JSON with a trailing newline, matching every other artifact. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** `12.4 kB`, the size a human reads on the "wrote" line. */
export function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

/**
 * Why an artifact is missing, in the words the run directory supports.
 *
 * "Absent" and "on disk but rejected" are different problems with different
 * fixes, and saying the first when the second is true sends a reader looking for
 * a file that is right there. `loadRunArtifacts` already recorded the violation;
 * this is what puts it in the sentence instead of dropping it.
 */
function absenceOf(artifacts: RunArtifacts, file: string): string {
  const unreadable = artifacts.unreadable.find((entry) => entry.file === file);
  return unreadable === undefined
    ? `${file} is absent`
    : `${file} could not be read (${unreadable.reason})`;
}

/** Optional artifacts, and the sentence each absence costs the report. */
export function degradations(artifacts: RunArtifacts): string[] {
  const notes: string[] = [];
  if (artifacts.inventory === null) {
    notes.push(
      `${absenceOf(artifacts, INVENTORY_FILE)}: the endpoint matrix and the unit counts are empty`,
    );
  }
  if (artifacts.audit === null) {
    notes.push(
      `${absenceOf(artifacts, AUDIT_FILE)}: the report has no per-unit-kind coverage and no model verdicts`,
    );
  }
  if (artifacts.scan === null) {
    notes.push(
      `${absenceOf(artifacts, SCAN_REPORT_FILE)}: the report cannot say which analyzers ran`,
    );
  }
  if (artifacts.profile === null) {
    notes.push(
      `${absenceOf(artifacts, STACK_PROFILE_FILE)}: the report cannot state which stack it examined`,
    );
  }
  if (artifacts.scope === null) {
    notes.push(
      `${absenceOf(artifacts, SCOPE_PROPOSAL_FILE)}: the report cannot say which domains were left out`,
    );
  }
  return notes;
}

// ---------------------------------------------------------------------------
// Phase 6 → the two renderers
// ---------------------------------------------------------------------------

/**
 * The binding ceiling's prose, when one capped this domain.
 *
 * A ceiling that fired without lowering the score is recorded in the scorecard
 * but is not an explanation of the number, so only the binding one is shown
 * beside it.
 */
function bindingCeiling(domain: ScoredDomain): string | undefined {
  return domain.ceilings.find((ceiling) => ceiling.binding)?.reason;
}

/**
 * True when what held this domain back was the evidence nobody examined rather
 * than the checks that did not run.
 *
 * The PDF builds its own sentence out of the coverage fraction, and for exactly
 * these domains that fraction is the misleading number: `1 of 1 checks ran
 * (100%)` is what a data-layer domain reports when its one planned check ran and
 * every migration in the repository went unaudited. Phase 6's statement names the
 * units instead, so it is handed over and the report prints it.
 */
function evidenceLimited(domain: ScoredDomain): boolean {
  return domain.evidence.applies && domain.evidence.ratio < domain.coverage.ratio;
}

/**
 * Phase 6's scorecard in the shape the PDF's adapter reads.
 *
 * `score` is mandatory there and `null` is not representable, so a
 * `not-assessed` domain is passed with its status and a zero the adapter is
 * contractually required to ignore — it renders the words, never the number.
 * The run-level block is omitted entirely when no domain earned a number: an
 * overall of zero would be a verdict nobody reached.
 *
 * `coverage` is the one number a `not-assessed` domain still gets to keep, and
 * `null` is reserved for a domain with no checks to count at all. A domain that
 * ran one check in five was measured; printing a dash for it would throw away
 * the number that says how thin the evidence was, which is the only defence
 * against reading the empty findings column as a clean one.
 */
export function toPdfScorecard(card: Scorecard): PdfScorecardInput {
  const domains = card.domains.map((domain) => ({
    domain: domain.domain,
    score: domain.score ?? 0,
    band: domain.band ?? "",
    status: domain.status,
    // `assessedRatio`, not the check ratio: the column has to answer "how much of
    // this domain does the number speak for", and a single planned check that ran
    // over units nobody examined answers 100% to the other question.
    coverage:
      domain.coverage.unitsTotal === 0 && !domain.evidence.applies ? null : domain.assessedRatio,
    confidence: card.confidence.level,
    ...(bindingCeiling(domain) === undefined ? {} : { ceilingReason: bindingCeiling(domain) }),
    ...(evidenceLimited(domain) ? { evidenceNote: domain.statement } : {}),
  }));
  const overall = card.overall;
  return overall.score === null || overall.band === null
    ? { domains }
    : {
        domains,
        overall: { score: overall.score, band: overall.band, confidence: card.confidence.level },
      };
}

/**
 * Phase 6's scorecard in the shape `report.md` reads.
 *
 * Undefined when no domain earned a number: the markdown prints "not scored"
 * from the absence, which is the honest rendering of a run that could not be
 * scored, and is different from a score of zero.
 */
export function toDossierScore(card: Scorecard): DossierScore | undefined {
  const overall = card.overall;
  if (overall.score === null || overall.band === null) return undefined;
  const ceilings = card.domains.flatMap((domain) =>
    domain.ceilings
      .filter((ceiling) => ceiling.binding)
      .map((ceiling) => ({ reason: ceiling.reason, cap: ceiling.cap })),
  );
  return {
    overall: overall.score,
    band: overall.band,
    confidence: card.confidence.level,
    domains: card.domains
      .filter(
        (domain): domain is ScoredDomain & { score: number; band: string } =>
          domain.score !== null && domain.band !== null,
      )
      .map((domain) => ({ domain: domain.domain, score: domain.score, band: domain.band })),
    // The domains that earned no number, in phase 6's own words. Without this
    // the score table is five rows of a possible eight and says nothing about
    // the missing three, which reads as if they had been left out for being
    // uninteresting rather than for being unmeasured.
    ...(overall.unscored.length === 0
      ? {}
      : {
          unscored: overall.unscored.map((domain) => ({
            domain: domain.domain,
            reason: domain.reason,
          })),
        }),
    ...(ceilings.length === 0 ? {} : { ceilings }),
  };
}

/**
 * Phase 6 over one version of a run's findings.
 *
 * Takes the document separately from the artifacts it came with, because a
 * reviewed run is scored twice — once as the model left it, once as the reviewer
 * corrected it — and both numbers have to come out of the same phase, fed the
 * same audit, inventory and scope, or the before/after comparison in the report
 * would be a comparison of two different scorers.
 *
 * The inventory is the whole repository's, always. A `--path` run narrows what
 * is *audited*, never the denominator it is judged against, and the difference
 * is not cosmetic: scoring a scoped run against its own subtree empties the
 * denominator of every domain whose units live elsewhere — in a workspace whose
 * deployables sit under `apps/`, `--path apps/api` leaves the data layer with
 * zero units — and a domain with no
 * units to examine is scored as "nothing wrong here", which is how a bounded run
 * earns an A for code it never opened. Keeping the repository's counts makes a
 * scoped run conservative by construction: it can read worse than it is, never
 * better, and `analysis-scope.json` — printed on the cover, in the scope section
 * and under the scorecard — is what says which part of it was analysed.
 */
export function scoreRun(artifacts: RunArtifacts, document: FindingsDocument): Scorecard {
  const scope = artifacts.scope?.decision.enabledDomains as readonly Domain[] | undefined;
  const inventory = artifacts.inventory;
  return buildScorecardFromArtifacts({
    document,
    ...(artifacts.audit === null ? {} : { audit: artifacts.audit }),
    ...(artifacts.scan === null ? {} : { scan: artifacts.scan }),
    // `inventory.json` is the denominator of the evidence gate: it is what knows
    // how many migrations exist for nobody to have audited. Without it a `--no-ai`
    // run has no units to miss and scores as though its one analyzer step had
    // looked at the whole data layer.
    ...(inventory === null ? {} : { inventory }),
    ...(scope === undefined ? {} : { scope }),
  });
}

/** Everything one render produced, in memory. */
export interface RenderedDossier {
  readonly scorecard: Scorecard;
  readonly files: readonly { readonly file: string; readonly data: string | Uint8Array }[];
  /**
   * What the brief detailed and what it only counted, when one was rendered.
   *
   * Carried out of the render so the terminal and `--json` can repeat the brief's
   * own disclosure instead of restating it from the findings: an operator who
   * hands a 25-page summary to a client should be told, on the same line that
   * names the file, how much of the dossier it does not contain.
   */
  readonly brief?: BriefOmissions | undefined;
}

/**
 * Which of the three files to produce.
 *
 * A set rather than a {@link ReportFormat}, because `--format` and `--no-pdf`
 * are different questions. `--format` picks one file; `--no-pdf` drops one and
 * keeps the rest, which no single member of the union can say. Both collapse to
 * this before the renderers are called, so there is one answer to "what is
 * being written" and not two.
 */
export interface DossierSelection {
  readonly pdf: boolean;
  readonly markdown: boolean;
  readonly issues: boolean;
  /** `report-brief.pdf` and `report-brief.md`: the two files `--brief` adds. */
  readonly brief: boolean;
}

/** A `--format` value as a selection; `all` is the dossier's three files. */
export function selectionFor(format: ReportFormat, brief = false): DossierSelection {
  return {
    pdf: format === "all" || format === "pdf",
    markdown: format === "all" || format === "md",
    issues: format === "all" || format === "issues",
    // `--brief` never subtracts: it is the one flag whose job is to produce a
    // second document, so it turns the brief on and leaves the rest of the
    // selection exactly as `--format` set it.
    brief: brief || format === "brief",
  };
}

/**
 * Scores the run and renders whichever files were asked for.
 *
 * Nothing is written here and nothing is read: this is the whole of phases 6
 * and 7 as a function of the artifacts, which is what lets `resume` reuse it and
 * a test assert on the bytes.
 */
export async function renderDossier(
  artifacts: RunArtifacts,
  options: {
    readonly select: DossierSelection;
    readonly sentinelVersion?: string | undefined;
    /** What a human verified, when `--triage` was applied. */
    readonly triage?: TriageSummary | undefined;
  },
): Promise<RenderedDossier> {
  const document = requireFindings(artifacts);
  const inventory = artifacts.inventory;
  const scorecard = scoreRun(artifacts, document);

  // One set of issues for both files: `report.md` links to the same tickets
  // `issues.md` spells out, and building them twice could produce two of them.
  const issues = buildIssues(document.findings);
  const score = toDossierScore(scorecard);
  const dossier: DossierInput = {
    findings: document,
    issues,
    ...(artifacts.profile === null ? {} : { profile: artifacts.profile }),
    ...(inventory === null ? {} : { inventory }),
    ...(artifacts.scan === null ? {} : { scan: artifacts.scan }),
    ...(artifacts.audit === null ? {} : { audit: artifacts.audit }),
    ...(artifacts.scope === null ? {} : { scope: artifacts.scope.decision }),
    ...(artifacts.analysisScope === null ? {} : { analysisScope: artifacts.analysisScope }),
    ...(score === undefined ? {} : { score }),
    ...(options.triage === undefined ? {} : { triage: options.triage }),
  };

  const files: { file: string; data: string | Uint8Array }[] = [];
  if (options.select.markdown) {
    files.push({ file: REPORT_MARKDOWN_FILE, data: renderReportMarkdown(dossier) });
  }
  if (options.select.issues) {
    files.push({
      file: ISSUES_FILE,
      data: renderIssuesMarkdown(issues, { runId: artifacts.runId, target: document.target }),
    });
  }
  // One input for both PDF documents. The brief is a view of the dossier's own
  // model, so handing it a second, separately-built input is the one way the two
  // files could come to report different counts for the same run.
  const pdfInput =
    options.select.pdf || options.select.brief
      ? reportInputFromRunArtifacts(artifacts, {
          scorecard: toPdfScorecard(scorecard),
          ...(options.sentinelVersion === undefined
            ? {}
            : { sentinelVersion: options.sentinelVersion }),
          ...(options.triage === undefined ? {} : { triage: options.triage }),
        })
      : undefined;
  if (options.select.pdf && pdfInput !== undefined) {
    files.push({ file: REPORT_PDF_FILE, data: await renderReportPdf(pdfInput) });
  }
  let omissions: BriefOmissions | undefined;
  if (options.select.brief && pdfInput !== undefined) {
    const brief = buildBriefModel(buildReportModel(pdfInput));
    omissions = brief.omissions;
    files.push({ file: REPORT_BRIEF_MARKDOWN_FILE, data: renderBriefMarkdown(brief) });
    files.push({ file: REPORT_BRIEF_PDF_FILE, data: await renderBriefDocument(brief) });
  }
  return { scorecard, files, ...(omissions === undefined ? {} : { brief: omissions }) };
}

/**
 * Phase 6's verdict as a block of terminal lines.
 *
 * Lives here rather than in `analyze` because both verbs end by showing it and
 * a client reading one and an operator reading the other must not be given two
 * different tables. Every domain appears, scored or not: a scorecard that
 * listed only the domains it could score would be the same silence the coverage
 * table exists to prevent.
 */
export function renderScorecardLines(card: Scorecard, scope?: AnalysisScope | undefined): string {
  const overall = card.overall;
  const bounded = scope !== undefined && !scope.wholeRepository;
  const head =
    overall.score === null || overall.band === null
      ? `Scorecard${bounded ? ` for ${renderScopePaths(scope.paths)}` : ""} — not assessed: no domain earned a number`
      : `Scorecard${bounded ? ` for ${renderScopePaths(scope.paths)}` : ""} — overall ${overall.score}/100 (${overall.band}), confidence ${card.confidence.level}`;

  // Every number below is about the analysed subtree and nothing else. The
  // sentence sits directly under the headline score, because that number is the
  // one a reader quotes and it is the one most easily mistaken for a grade for
  // the whole repository.
  const scopeLine = bounded ? ["", `  ${scope.statement}`] : [];

  const width = Math.max(...card.domains.map((domain) => domain.domain.length));
  const rows = card.domains.map((domain, index) => {
    const code = `D${index + 1}`;
    const verdict =
      domain.score === null
        ? "not assessed".padEnd(12)
        : `${domain.score} (${domain.band})`.padEnd(12);
    // The column already says "not assessed", so the statement does not repeat
    // it; what is left is the reason, which is the part worth reading.
    const detail = domain.statement.replace(/^not assessed: /, "");
    return `  ${code}  ${domain.domain.padEnd(width)}  ${verdict}  ${detail}`;
  });

  const unscored = card.overall.unscored.map((entry) => entry.domain);
  const footer =
    unscored.length === 0
      ? []
      : [
          "",
          `  Not scored: ${unscored.join(", ")}. A domain without a number was not checked enough to earn one, which is not the same as a clean one.`,
        ];
  return [head, ...scopeLine, "", ...rows, ...footer].join("\n");
}

/** Writes one JSON artifact into `dir`; returns what landed where. */
async function writeArtifact(
  fs: Pick<ReportFileSystem, "writeFile" | "mkdirp">,
  dir: string,
  file: string,
  value: unknown,
): Promise<RenderedFile> {
  await fs.mkdirp(dir);
  const path = join(dir, file);
  const data = serialise(value);
  await fs.writeFile(path, data);
  return { file, path, bytes: new TextEncoder().encode(data).length };
}

/** Writes a rendered dossier into `outDir`; returns what landed where. */
export async function writeDossier(
  fs: Pick<ReportFileSystem, "writeFile" | "mkdirp">,
  outDir: string,
  rendered: RenderedDossier,
): Promise<RenderedFile[]> {
  await fs.mkdirp(outDir);
  const written: RenderedFile[] = [];
  for (const entry of rendered.files) {
    const path = join(outDir, entry.file);
    await fs.writeFile(path, entry.data);
    written.push({
      file: entry.file,
      path,
      bytes:
        typeof entry.data === "string"
          ? new TextEncoder().encode(entry.data).length
          : entry.data.length,
    });
  }
  return written;
}

/** The verdict, adjusted for what this render just produced. */
function verdictAfterRender(
  artifacts: RunArtifacts,
  options: { readonly renderedAll: boolean; readonly intoRunDir: boolean },
): RunVerdict {
  const verdict = assessRun(artifacts, describeRunPhases(artifacts));
  if (!options.renderedAll || !options.intoRunDir) return verdict;
  // The verdict was computed from the artifacts as they were a moment ago, when
  // the dossier was not rendered. It is now — but only in the run directory, and
  // only when every file was asked for.
  const blockers = verdict.blockers.filter(
    (blocker) => !blocker.startsWith("the dossier is not rendered"),
  );
  return { shareable: blockers.length === 0, blockers, warnings: verdict.warnings };
}

// ---------------------------------------------------------------------------
// --triage
// ---------------------------------------------------------------------------

/** A path as typed, resolved against the working directory when it is relative. */
function absolutePath(path: string, cwd: string): string {
  return isAbsolute(path) ? path : resolve(cwd, path);
}

/** A triage file that was read and validated, or the sentence that says why not. */
type TriageOutcome =
  | { readonly ok: true; readonly document: TriageDocument }
  | { readonly ok: false; readonly message: string };

/**
 * Reads the reviewer's verdicts off disk.
 *
 * Validated against its own schema like every other document Sentinel reads,
 * and refused by name when it does not parse: a triage that is half-understood
 * would quietly withhold the wrong findings, which is worse than not applying
 * one at all.
 */
async function readTriage(
  fs: Pick<ReportFileSystem, "readFile" | "exists">,
  path: string,
): Promise<TriageOutcome> {
  if (!(await fs.exists(path))) {
    return { ok: false, message: `${path} does not exist, so there are no verdicts to apply` };
  }
  let raw: string;
  try {
    raw = await fs.readFile(path);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, message: `${path} could not be read (${detail})` };
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, message: `${path} is not valid JSON: ${detail}` };
  }
  const parsed = TriageDocumentSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue === undefined ? "(root)" : issue.path.map(String).join(".");
    return {
      ok: false,
      message: `${path} is not a valid triage document — ${where}: ${issue?.message ?? "invalid"}`,
    };
  }
  return { ok: true, document: parsed.data };
}

/** Phase 6's per-domain numbers for any version of this run's findings. */
function domainScorer(artifacts: RunArtifacts): DomainScorer {
  return (document) =>
    scoreRun(artifacts, document).domains.map((domain) => ({
      domain: domain.domain,
      score: domain.score,
    }));
}

/** What applying a review produced: the run to render, and the review to print. */
interface ReviewedRun {
  readonly artifacts: RunArtifacts;
  readonly summary: TriageSummary;
  /** The adjusted document, written beside `findings.json` rather than over it. */
  readonly document: FindingsDocument;
}

/**
 * Applies a triage to a loaded run.
 *
 * The returned artifacts are the loaded ones with the adjusted findings in place
 * of the originals, so every consumer downstream — phase 6, both renderers, the
 * issues — works from the corrected document without being told a review
 * happened. What they are told separately is the {@link TriageSummary}, because
 * a document that silently rendered the corrected findings and said nothing
 * about the correction is the failure this feature exists to prevent.
 */
function reviewRun(artifacts: RunArtifacts, triage: TriageDocument): ReviewedRun {
  const applied = applyTriage(requireFindings(artifacts), triage, {
    score: domainScorer(artifacts),
  });
  return {
    artifacts: { ...artifacts, findings: applied.document },
    summary: applied.summary,
    document: applied.document,
  };
}

/** Renders a run's artifacts into `report.pdf`, `report.md` and `issues.md`. */
export async function reportCommand(
  context: CliContext,
  invocation: ReportInvocation,
  deps: ReportDeps,
): Promise<number> {
  const resolution = await resolveRunDir(deps.fs, invocation.runDir, invocation.cwd);
  if (!resolution.ok) {
    context.writeError(`sentinel: ${describeRunDirFailure(resolution, invocation.runDir)}\n`);
    return EXIT.preflight;
  }
  const runDir = resolution.runDir.dir;
  const artifacts = await loadRunArtifacts(deps.fs, runDir);

  let triage: TriageDocument | undefined;
  if (invocation.triage !== undefined) {
    const triagePath = absolutePath(invocation.triage, invocation.cwd);
    const loaded = await readTriage(deps.fs, triagePath);
    if (!loaded.ok) {
      context.writeError(`sentinel: ${loaded.message}\n`);
      return EXIT.preflight;
    }
    triage = loaded.document;
  }

  let rendered: RenderedDossier;
  let review: ReviewedRun | undefined;
  try {
    if (triage !== undefined) review = reviewRun(artifacts, triage);
    rendered = await renderDossier(review?.artifacts ?? artifacts, {
      select: selectionFor(invocation.format, invocation.brief === true),
      sentinelVersion: context.version,
      ...(review === undefined ? {} : { triage: review.summary }),
    });
  } catch (error) {
    // A missing artifact is a precondition, not a crash: it is named and the
    // command stops without writing a partial document.
    if (error instanceof MissingArtifactError) {
      context.writeError(`sentinel: ${error.message}\n`);
      return EXIT.preflight;
    }
    // A triage that is not about this run is the same kind of failure: reported
    // by id, and nothing is written. Applying it would withhold findings the
    // reviewer never looked at.
    if (error instanceof StaleTriageError) {
      context.writeError(`sentinel: ${error.message}\n`);
      return EXIT.preflight;
    }
    throw error;
  }

  const outDir =
    invocation.out === undefined ? runDir : absolutePath(invocation.out, invocation.cwd);
  const written: RenderedFile[] = [];

  // Beside `findings.json`, never over it, and in the run directory even when
  // `--out` sends the rendered files elsewhere: the raw model output and the
  // reviewed version of it belong together, and a reader who wants to know what
  // the review changed diffs the two.
  if (review !== undefined) {
    written.push(await writeArtifact(deps.fs, runDir, TRIAGED_FINDINGS_FILE, review.document));
  }
  written.push(...(await writeDossier(deps.fs, outDir, rendered)));

  const degraded = degradations(artifacts);
  const elsewhere = outDir !== runDir;
  const verdict = verdictAfterRender(artifacts, {
    renderedAll: invocation.format === "all",
    intoRunDir: !elsewhere,
  });
  const card = rendered.scorecard;
  const speaks = !invocation.output.json && !invocation.output.quiet;
  // The document that was rendered, which on a reviewed run is the adjusted one:
  // the counts printed below are the counts in the dossier, never the raw ones.
  const document = review?.document ?? artifacts.findings;

  if (invocation.output.json) {
    const payload: ReportJson = {
      runId: artifacts.runId,
      runDir,
      outDir,
      format: invocation.format,
      written,
      findings: document?.findings.length ?? 0,
      assurances: document?.assurances.length ?? 0,
      score: card.overall.score,
      band: card.overall.band,
      confidence: card.confidence.level,
      shareable: verdict.shareable,
      blockers: verdict.blockers,
      degraded,
      ...(review === undefined || invocation.triage === undefined
        ? {}
        : {
            triage: {
              reviewer: review.summary.reviewer,
              file: absolutePath(invocation.triage, invocation.cwd),
              findingsFile: join(runDir, TRIAGED_FINDINGS_FILE),
              reviewed: review.summary.reviewed,
              confirmed: review.summary.confirmed.length,
              corrected: review.summary.corrected.length,
              withheld: review.summary.withheld.length,
              contested: review.summary.contested.length,
              unreviewed: review.summary.unreviewed,
            },
          }),
      ...(rendered.brief === undefined
        ? {}
        : {
            brief: {
              detailed: rendered.brief.detailed,
              counted: rendered.brief.counted,
              groups: rendered.brief.groups,
              detailedUnreviewed: rendered.brief.detailedUnreviewed,
              countedUnreviewed: rendered.brief.countedUnreviewed,
            },
          }),
    };
    context.write(serialise(payload));
  } else if (speaks) {
    const width = written.reduce((max, entry) => Math.max(max, entry.file.length), 0);
    context.write(
      [
        `Rendered ${artifacts.runId} from ${runDir}`,
        `  ${document?.findings.length ?? 0} finding(s), ${document?.assurances.length ?? 0} assurance(s), score ${
          card.overall.score === null
            ? "not assessed"
            : `${card.overall.score} (${card.overall.band})`
        }, confidence ${card.confidence.level}`,
        // A re-render of a scoped run says so too: this verb is how a dossier is
        // regenerated weeks later, and the person running it may not be the one
        // who chose the scope.
        ...(artifacts.analysisScope === null || artifacts.analysisScope.wholeRepository
          ? []
          : [`  ${artifacts.analysisScope.statement}`]),
        // Both sentences, on the terminal too: the operator applying a triage is
        // usually the person who will send the dossier on, and the limit of the
        // review is the thing they have to be able to repeat.
        ...(review === undefined
          ? []
          : [`  ${review.summary.statement}`, `  ${review.summary.unreviewedStatement}`]),
        "",
        ...written.map(
          (entry) =>
            `  ${entry.file.padEnd(width)}  ${formatBytes(entry.bytes).padStart(9)}  ${entry.path}`,
        ),
        "",
      ].join("\n"),
    );
    if (degraded.length > 0) {
      context.write(
        ["What this render could not include:", ...degraded.map((note) => `  - ${note}`), ""].join(
          "\n",
        ),
      );
    }
    // The brief's own disclosure, on the terminal, beside the file names. The
    // person who runs this command is usually the one who forwards the short
    // document, and they should not have to open it to learn what it leaves out.
    if (rendered.brief !== undefined) {
      const brief = rendered.brief;
      context.write(
        [
          `${REPORT_BRIEF_PDF_FILE} details ${brief.detailed} of ${brief.total} finding(s) in full — every critical and high — and states the other ${brief.counted} as ${brief.groups} counted row(s).`,
          // "Examined", not "verified": a contested verdict means a person
          // looked and could not decide, and the document itself prints which
          // of the four verdicts each finding got.
          brief.detailedUnreviewed === 0 && brief.detailed > 0
            ? "  Every finding it details was examined by hand; the brief states each verdict."
            : `  ${brief.detailedUnreviewed} of the finding(s) it details carry no human review.`,
          `  ${brief.countedUnreviewed} of the ${brief.counted} it only counts carry no human review. It is a summary, not the audit; its last page says so in numbers.`,
          "",
        ].join("\n"),
      );
    }
    if (elsewhere) {
      context.write(
        `These files are outside the run directory, so \`sentinel status ${runDir}\` still reports the dossier as unrendered.\n`,
      );
    }
    context.write(
      `${
        verdict.shareable
          ? "This run is complete enough to share as a dossier."
          : `This run is not complete enough to share as a finished dossier; run \`sentinel status ${runDir}\` for the list.`
      }\n`,
    );
  }

  // Free, and worth saying once: nothing here read the repository or dispatched
  // an agent, so this command can be re-run after every renderer change.
  if (invocation.output.verbose) {
    context.writeError("sentinel: report spent no AI budget; it read only the run directory.\n");
  }
  return EXIT.ok;
}
