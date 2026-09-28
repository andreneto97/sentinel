/**
 * `report.pdf`, end to end.
 *
 * The renderer is a pure function of the artifacts it is handed: it reads no
 * files — every snippet it prints was already extracted and verified by
 * `src/verify` and stored in `findings.json` — and it returns bytes. That is
 * what lets a test render a whole set of artifacts and assert on the result
 * without a repository on disk, and it keeps this module clear of the
 * filesystem port entirely. Writing the bytes is the caller's business, or
 * {@link writeReportPdf}'s, which takes the port as an argument.
 *
 * Section order is the plan's, and it is not negotiable: what is protected
 * comes before what is broken, coverage comes before both of them, and a human
 * review — when the run had one — comes before the findings it judged.
 */

import { type ReportCanvas, createCanvas } from "./layout.ts";
import { type ReportInput, type ReportModel, buildReportModel } from "./model.ts";
import { renderAppendix } from "./section-appendix.ts";
import { renderAssurances } from "./section-assurances.ts";
import { renderCover } from "./section-cover.ts";
import { renderCoverage } from "./section-coverage.ts";
import { renderFindings } from "./section-findings.ts";
import { renderPlan } from "./section-plan.ts";
import { renderExecutiveSummary } from "./section-summary.ts";
import { renderTriage } from "./section-triage.ts";

/** File name of the rendered dossier inside a run directory. */
export const REPORT_PDF_FILE = "report.pdf";

/** The write surface the PDF needs; `src/ports/file-system.ts` satisfies it. */
export interface ReportFileSystem {
  /** Atomic in the real port: a reader sees the old document or the new one. */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
}

/** Draws every section onto a canvas, in the plan's order. */
export function renderSections(canvas: ReportCanvas, model: ReportModel): void {
  renderCover(canvas, model);
  renderExecutiveSummary(canvas, model);
  renderAssurances(canvas, model);
  renderCoverage(canvas, model);
  // Before the findings: it says which of them a person checked, and — the part
  // that decides how the whole section is read — which of them nobody did.
  renderTriage(canvas, model);
  renderFindings(canvas, model);
  renderPlan(canvas, model);
  renderAppendix(canvas, model);
}

/** Renders the dossier and returns the PDF bytes. */
export async function renderReportPdf(input: ReportInput): Promise<Uint8Array> {
  const model = buildReportModel(input);
  const canvas = createCanvas({
    title: model.title,
    subject: model.repository,
    runId: model.runId,
    createdAt: model.generatedAt,
  });
  renderSections(canvas, model);
  return await canvas.finish();
}

/** Renders the dossier and writes it to `<runDir>/report.pdf`; returns the path. */
export async function writeReportPdf(
  fs: ReportFileSystem,
  runDir: string,
  input: ReportInput,
): Promise<string> {
  const bytes = await renderReportPdf(input);
  // Joined by hand: this module takes no dependency on the platform's path
  // module for one separator, and run directories are always absolute POSIX
  // paths produced by `src/cli/_shared/run-dir.ts`.
  const path = `${runDir.replace(/\/+$/, "")}/${REPORT_PDF_FILE}`;
  await fs.writeFile(path, bytes);
  return path;
}
