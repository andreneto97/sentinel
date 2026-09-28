/**
 * The last page of the brief: what it leaves out, counted.
 *
 * This page is the reason the brief is allowed to exist. A summary that hides its
 * own omissions is the failure mode this whole tool is built to refuse, so the
 * page states every omission as a number, adds those numbers up in front of the
 * reader, and names the files that hold everything it did not print.
 *
 * It is last on purpose. A reader who stops early has read the findings; a reader
 * who reaches the end cannot leave without the limits. It is also the one page
 * whose paragraphs come from the brief model rather than from this file, so the
 * PDF and `report-brief.md` make exactly the same admissions.
 */

import type { BriefModel } from "../brief.ts";
import { REPORT_MARKDOWN_FILE } from "../markdown.ts";
import { callout, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { REPORT_PDF_FILE } from "./render.ts";
import { renderTable } from "./table.ts";
import { plural } from "./text.ts";
import { COLOR, SEVERITY_COLOR, SIZE } from "./theme.ts";

/** `1,234`, matching every other count in the brief. */
function group(count: number): string {
  return count.toLocaleString("en-US");
}

/** Draws the omission page. */
export function renderBriefOmissions(canvas: ReportCanvas, brief: BriefModel): void {
  const omissions = brief.omissions;
  canvas.beginSection("What this brief omits");
  sectionTitle(
    canvas,
    "What this brief omits",
    "Stated in numbers, so a reader can check that the parts add up to the whole.",
  );

  // First on the page and in a frame, because it is the sentence a reader who
  // skims one line must not be able to miss.
  callout(
    canvas,
    `${group(omissions.counted)} of this run's ${group(omissions.total)} ${plural(omissions.total, "finding")} ${omissions.counted === 1 ? "is" : "are"} not detailed in this document. This brief is a summary of \`${REPORT_PDF_FILE}\`; it is not the audit, and it must not be read as one.`,
    SEVERITY_COLOR.high,
    { title: "This document is not the audit" },
  );

  renderTable(canvas, {
    columns: [
      { header: "", width: 300 },
      { header: "Findings", width: 80, align: "right" },
      { header: "Where they are", width: 102 },
    ],
    rows: [
      [
        { kind: "text" as const, text: "Printed in full here (critical and high)", bold: true },
        { kind: "text" as const, text: group(omissions.detailed) },
        { kind: "text" as const, text: "this document, and the full dossier" },
      ],
      [
        { kind: "text" as const, text: "Counted here, not printed (medium and below)" },
        { kind: "text" as const, text: group(omissions.counted) },
        {
          kind: "text" as const,
          text: `${REPORT_PDF_FILE}, ${REPORT_MARKDOWN_FILE}, findings.json`,
        },
      ],
      [
        { kind: "text" as const, text: "Total in the dossier this brief summarises", bold: true },
        { kind: "text" as const, text: group(omissions.total) },
        { kind: "text" as const, text: "findings.json" },
      ],
      [
        { kind: "text" as const, text: "Detailed here and carrying no human review" },
        {
          kind: "text" as const,
          text: group(omissions.detailedUnreviewed),
          color: omissions.detailedUnreviewed === 0 ? COLOR.muted : COLOR.ink,
        },
        { kind: "text" as const, text: "—" },
      ],
      [
        { kind: "text" as const, text: "Counted here and carrying no human review" },
        { kind: "text" as const, text: group(omissions.countedUnreviewed) },
        { kind: "text" as const, text: "—" },
      ],
      [
        { kind: "text" as const, text: "Withheld by review: in neither document's counts" },
        { kind: "text" as const, text: group(omissions.withheld) },
        { kind: "text" as const, text: `${REPORT_PDF_FILE}, human verification` },
      ],
      [
        { kind: "text" as const, text: "Assurances (checks that passed, with evidence)" },
        { kind: "text" as const, text: group(omissions.assurances) },
        { kind: "text" as const, text: `${REPORT_PDF_FILE}, section 3` },
      ],
    ],
  });

  for (const text of omissions.paragraphs) paragraph(canvas, text);

  paragraph(
    canvas,
    `Everything named above is in the same run directory as this file. \`findings.json\` is the machine-readable record and the only artifact that is complete by construction; \`${REPORT_PDF_FILE}\` and \`${REPORT_MARKDOWN_FILE}\` are the audit in prose.`,
    { color: COLOR.muted, size: SIZE.small },
  );
}
