/**
 * Section 3 — what is protected.
 *
 * This section precedes the findings on purpose, and the ordering is an
 * argument, not a courtesy: a document that lists only defects is a complaint,
 * and a reader has no way to tell a codebase with nine weaknesses and twenty
 * working controls from one with nine weaknesses and nothing else. An assurance
 * is a check that ran, passed, and can be pointed at — so each row carries the
 * units it covers and the lines that prove it.
 *
 * The fraction in an assurance's scope (`20/37 route handlers`) is the audit's
 * own wording and is printed verbatim. It is never rounded up: an assurance over
 * 20 of 37 handlers says 20 of 37, because the other 17 are where a reader
 * should be suspicious.
 */

import type { Assurance } from "../../contracts/findings.ts";
import { callout, heading, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import type { DomainView, ReportModel } from "./model.ts";
import { type TableCell, renderTable } from "./table.ts";
import { citation, plural } from "./text.ts";
import { COLOR, STRENGTH_COLOR } from "./theme.ts";

/** How many evidence pointers a row prints before it starts counting. */
const EVIDENCE_SHOWN = 3;

/** The evidence cell: a few real citations, then the count of the rest. */
function evidenceCell(assurance: Assurance): TableCell {
  if (assurance.evidence.length === 0) {
    return { kind: "text", text: "no pointer recorded", color: COLOR.muted };
  }
  const shown = assurance.evidence
    .slice(0, EVIDENCE_SHOWN)
    .map((ref) => citation(ref.file, ref.line, ref.endLine));
  const rest = assurance.evidence.length - shown.length;
  const lines = rest > 0 ? [...shown, `+${rest} more ${plural(rest, "pointer")}`] : shown;
  return { kind: "mono", text: lines.join("\n") };
}

/** Draws section 3. */
export function renderAssurances(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("What is protected");
  sectionTitle(
    canvas,
    "What is protected",
    "Checks that ran, passed, and can be pointed at. This section comes before the findings deliberately.",
  );

  if (model.assurances.length === 0) {
    callout(
      canvas,
      "This run produced no assurances. Either the audit phase did not run, or no check passed with evidence Sentinel could verify — in both cases the findings that follow are not the whole picture, because nothing here states what was found to be correct.",
      COLOR.muted,
      { title: "No assurances" },
    );
    return;
  }

  paragraph(
    canvas,
    [
      `${model.assurances.length} ${plural(model.assurances.length, "check")} passed with verified evidence, covering ${model.unitsAssured} unit ${plural(model.unitsAssured, "check")} in total.`,
      "Each row names the control that was looked for, the units it was confirmed on, and the lines that prove it.",
      "A fraction below 100% is not a failure: it is the audit saying how far its evidence reaches.",
    ].join(" "),
  );

  for (const domain of model.domains) {
    if (domain.assurances.length === 0) continue;
    renderDomainAssurances(canvas, domain);
  }
}

/** One domain's assurances, as a bordered table. */
function renderDomainAssurances(canvas: ReportCanvas, domain: DomainView): void {
  const units = domain.assurances.reduce((sum, assurance) => sum + assurance.unitsChecked, 0);
  heading(canvas, `${domain.code} ${domain.label}`, STRENGTH_COLOR);
  paragraph(
    canvas,
    `${domain.assurances.length} ${plural(domain.assurances.length, "assurance")}, ${units} unit ${plural(units, "check")}.`,
    { color: COLOR.muted, size: 8 },
  );

  renderTable(canvas, {
    columns: [
      { header: "Check that passed", width: 196 },
      { header: "Units covered", width: 116 },
      { header: "Evidence", width: 170 },
    ],
    rows: domain.assurances.map((assurance) => [
      { kind: "text" as const, text: assurance.check, bold: true },
      { kind: "text" as const, text: assurance.scope },
      evidenceCell(assurance),
    ]),
  });
}
