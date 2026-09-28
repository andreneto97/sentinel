/**
 * `report-brief.pdf`, end to end.
 *
 * Same shape as `render.ts` and for the same reasons: a pure function of the
 * artifacts, reading no files, returning bytes. It shares the canvas, the
 * components, the tables and the charts with the dossier, and it shares the view
 * model — {@link buildReportModel} runs once and both documents are drawn from
 * it, so the brief cannot print a count the dossier disagrees with.
 *
 * Four sections, in the only order that keeps the document honest: what this is,
 * the numbers, what to act on, what the rest is, and — last, where a reader
 * cannot finish without it — what was left out.
 */

import { type BriefModel, buildBriefModel } from "../brief.ts";
import { type ReportCanvas, createCanvas } from "./layout.ts";
import { type ReportInput, buildReportModel } from "./model.ts";
import { renderBriefCover, renderBriefSummary } from "./section-brief-cover.ts";
import { renderBriefDetail } from "./section-brief-detail.ts";
import { renderBriefGroups } from "./section-brief-groups.ts";
import { renderBriefOmissions } from "./section-brief-omissions.ts";

/** File name of the rendered brief inside a run directory. */
export const REPORT_BRIEF_PDF_FILE = "report-brief.pdf";

/** The write surface the brief needs; `src/ports/file-system.ts` satisfies it. */
export interface BriefFileSystem {
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
}

/** Draws every brief section onto a canvas, in order. */
export function renderBriefSections(canvas: ReportCanvas, brief: BriefModel): void {
  renderBriefCover(canvas, brief);
  renderBriefSummary(canvas, brief);
  renderBriefDetail(canvas, brief);
  renderBriefGroups(canvas, brief);
  // Last, deliberately: the reader who reaches the end of a summary is the one
  // most likely to act on it, and this is the page that bounds what they may.
  renderBriefOmissions(canvas, brief);
}

/**
 * Renders a brief that is already computed, and returns the PDF bytes.
 *
 * Split from {@link renderBriefPdf} so a caller rendering both brief files
 * builds the model once: `report-brief.md` needs the same {@link BriefModel},
 * and computing it twice is how two documents about one run start disagreeing.
 */
export async function renderBriefDocument(brief: BriefModel): Promise<Uint8Array> {
  const canvas = createCanvas({
    title: "Executive Brief",
    subject: brief.report.repository,
    runId: brief.report.runId,
    createdAt: brief.report.generatedAt,
  });
  renderBriefSections(canvas, brief);
  return await canvas.finish();
}

/** Builds the brief from a run's artifacts and returns the PDF bytes. */
export async function renderBriefPdf(input: ReportInput): Promise<Uint8Array> {
  return await renderBriefDocument(buildBriefModel(buildReportModel(input)));
}

/** Renders the brief and writes it to `<runDir>/report-brief.pdf`; returns the path. */
export async function writeBriefPdf(
  fs: BriefFileSystem,
  runDir: string,
  input: ReportInput,
): Promise<string> {
  const bytes = await renderBriefPdf(input);
  const path = `${runDir.replace(/\/+$/, "")}/${REPORT_BRIEF_PDF_FILE}`;
  await fs.writeFile(path, bytes);
  return path;
}
