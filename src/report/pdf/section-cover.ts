/**
 * Section 1 — the cover, and the methodology note behind it.
 *
 * The cover page carries the five things a reader checks before reading
 * anything: what this is, which repository, when, which commit, and what was in
 * scope. It carries no page chrome, because a cover with a page number on it is
 * a title page someone forgot to finish.
 *
 * The methodology note does not fit on a cover and does not belong in an
 * appendix — a client who cannot see how "application security" was turned into
 * *their* 37 handlers has no way to judge the rest — so it follows on its own
 * page, still part of section 1.
 */

import type { BudgetStop } from "../../audit/budget.ts";
import { callout, fillRect, hairline, labelled, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import type { ReportModel } from "./model.ts";
import { renderTable } from "./table.ts";
import { formatDate, shortenPath, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/**
 * The cover's headline for an audit that stopped early, by what stopped it.
 *
 * `bound.statement` already says it in full; this is the three-word version a
 * reader sees first, and it has to name the same cause. Calling a usage limit a
 * budget sends someone to raise a ceiling that was never set.
 */
const STOP_TITLE: Readonly<Record<BudgetStop, string>> = {
  complete: "The audit did not finish",
  "batch-budget": "The audit stopped at its batch budget",
  "unit-budget": "The audit stopped at its unit budget",
  "wall-clock": "The audit stopped at its time limit",
  quota: "The subscription's usage limit stopped the audit",
  cancelled: "The audit was cancelled before it finished",
};

/** Ends a sentence that a machine composed, so the next one does not run into it. */
function sentence(text: string): string {
  const trimmed = text.trim();
  return trimmed === "" || /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

/** Draws the cover page and the methodology page that belongs with it. */
export function renderCover(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginCover();

  // A band of the severity palette, in order: the document's own key, printed
  // before any chart uses it.
  const bandWidth = canvas.width / 5;
  const severities = [
    SEVERITY_COLOR.critical,
    SEVERITY_COLOR.high,
    SEVERITY_COLOR.medium,
    SEVERITY_COLOR.low,
    SEVERITY_COLOR.info,
  ];
  severities.forEach((color, index) => {
    fillRect(canvas, canvas.left + index * bandWidth, canvas.y, bandWidth, 5, color);
  });
  // The title block sits below the optical centre of the upper half, which is
  // where a cover reads best; the facts and the note fill the rest.
  canvas.moveDown(5 + 92);

  canvas.use(FONT.regular, SIZE.subtitle, COLOR.muted);
  canvas.doc.text("SENTINEL", canvas.left, canvas.y, { characterSpacing: 3 });
  canvas.moveDown(10);

  canvas.use(FONT.bold, SIZE.title, COLOR.ink);
  canvas.doc.text(toWinAnsi(model.title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(4);

  canvas.use(FONT.regular, SIZE.h1, COLOR.body);
  canvas.doc.text(toWinAnsi(model.repository), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(SPACE.block);
  hairline(canvas, canvas.y);
  canvas.moveDown(SPACE.block);

  const labelWidth = 118;
  labelled(canvas, "Repository", `${model.repository} - ${shortenPath(model.target)}`, {
    labelWidth,
  });
  labelled(canvas, "Commit", model.commitLabel, { labelWidth });
  labelled(canvas, "Report date", formatDate(model.generatedAt), { labelWidth });
  labelled(canvas, "Run id", model.runId, { labelWidth });
  labelled(canvas, "Scope", model.scopeSummary, { labelWidth });
  labelled(canvas, "Stack", model.stack.summary, { labelWidth });

  canvas.moveDown(SPACE.block);
  callout(
    canvas,
    "Every finding in this dossier cites a file and a line that Sentinel opened on disk; the code shown was extracted from the repository, never written by a model, and a claim whose citation did not resolve was dropped before this document was rendered. Coverage is enumerated rather than sampled: the units of audit were listed first, and each section states how many of them were actually judged.",
    COLOR.ink,
    { title: "How to read this document" },
  );

  if (model.analysisScope !== null) {
    // Before the synthetic warning and before any number: a dossier about one
    // subtree of a repository has to say so on its first page, or every figure
    // after it is read as a claim about the whole repository.
    callout(
      canvas,
      `${model.analysisScope} Nothing in this document is evidence about the parts of the repository it does not name: they were counted, and they were not analysed. The dependency scan, the git-history secret scan and the delivery checks did read the whole repository, so a finding may cite a file outside the scope; the scope section of report.md lists which phases those are.`,
      SEVERITY_COLOR.high,
      { title: "This run analysed part of the repository" },
    );
  }

  if (model.auditBound !== null && model.auditStoppedEarly) {
    // Only when a ceiling actually stopped the audit. On a complete run the
    // bound is still printed in the coverage section, where it reads as the
    // reassurance it is; on the cover it would be a warning about nothing.
    callout(
      canvas,
      `${sentence(model.auditBound)} The units that were not audited are counted in the coverage section with the reason, and \`sentinel resume\` continues this run from where it stopped. An absence of findings about them is not evidence that they are sound.`,
      SEVERITY_COLOR.high,
      { title: STOP_TITLE[model.auditStop ?? "complete"] },
    );
  }

  if (model.triage !== null) {
    // The cover's one line about the review, and it carries the limit in the
    // same breath as the claim. A client reading only this page has to leave it
    // knowing both that a person checked part of this dossier and how small that
    // part was; "reviewed" alone on a cover is the most expensive word in the
    // document.
    callout(
      canvas,
      `${model.triage.statement} ${model.triage.unreviewedStatement} The section "Human verification" lists every finding the review withheld, corrected and confirmed.`,
      STRENGTH_COLOR,
      { title: "Part of this run was verified by hand" },
    );
  }

  if (model.synthetic) {
    callout(
      canvas,
      "The audit phase of this run replayed a recorded transcript instead of consulting a live model. Treat the findings below as a wiring check, not as evidence about this repository.",
      SEVERITY_COLOR.critical,
      { title: "This run is synthetic" },
    );
  }

  renderMethodology(canvas, model);
}

/** The methodology page: the detected stack, then the mapping, domain by domain. */
function renderMethodology(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Methodology");
  sectionTitle(
    canvas,
    "Methodology",
    "What was detected in the repository, and what each of the eight domains was taken to mean for this stack.",
  );

  paragraph(canvas, model.stack.summary);

  if (model.stack.rows.length > 0) {
    renderTable(canvas, {
      columns: [
        { header: "Detected", width: 150 },
        { header: "Value", width: 332 },
      ],
      rows: model.stack.rows.map((row) => [
        { kind: "text" as const, text: row.label, bold: true },
        { kind: "text" as const, text: row.value },
      ]),
      emptyMessage: "Phase 0 left no stack profile in this run directory.",
    });
  } else {
    paragraph(
      canvas,
      "No stack profile was found in this run directory, so the domain mappings below are the generic ones rather than this repository's.",
      { color: COLOR.muted },
    );
  }

  for (const warning of model.stack.warnings) {
    callout(canvas, warning, SEVERITY_COLOR.medium, { title: "Detection warning" });
  }

  paragraph(canvas, "How each domain was mapped onto that stack:", { font: FONT.bold });
  renderTable(canvas, {
    columns: [
      { header: "Domain", width: 118 },
      { header: "What it meant here", width: 364 },
    ],
    rows: model.domains.map((domain) => [
      { kind: "text" as const, text: `${domain.code} ${domain.label}`, bold: true },
      { kind: "text" as const, text: domain.mapping },
    ]),
  });
}
