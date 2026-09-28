/**
 * Section 6 — the prioritised plan.
 *
 * Three tiers, and the rule that puts a finding in one is printed above it.
 * Severity is the only input: a plan that secretly re-ranked by "effort" or
 * "confidence" would be this report's opinion dressed as the audit's, and the
 * reader cannot check an opinion against the sections above.
 *
 * An empty tier is still printed. `P1: nothing in this tier` is a result; a
 * missing P1 heading looks like a formatting accident.
 */

import { fillRect, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { DOMAIN_LABEL, type PriorityGroup, type ReportModel } from "./model.ts";
import { renderTable } from "./table.ts";
import { citation, plural, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE } from "./theme.ts";

/** Draws section 6. */
export function renderPlan(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Prioritised plan");
  sectionTitle(
    canvas,
    "Prioritised plan",
    "The same findings as section 5, ordered by what the severity rubric says to do first.",
  );

  paragraph(
    canvas,
    "Tiers follow severity and nothing else, so this page can be checked against section 5 line by line. Within a tier the order is severity, then file, then line. Every entry keeps its `file:line`, so the plan can be worked straight from this page.",
  );

  for (const group of model.priorities) {
    renderGroup(canvas, group);
  }
}

/** One tier: a coloured header band, the rule, and the findings in it. */
function renderGroup(canvas: ReportCanvas, group: PriorityGroup): void {
  const bandHeight = 22;
  canvas.ensure(bandHeight + 60);
  canvas.moveDown(SPACE.paragraph);

  const top = canvas.y;
  fillRect(canvas, canvas.left, top, canvas.width, bandHeight, group.color);
  canvas.use(FONT.bold, SIZE.h2, COLOR.onColor);
  canvas.doc.text(toWinAnsi(`${group.id} - ${group.title}`), canvas.left + 8, top + 5.5, {
    lineBreak: false,
  });
  // The band states the whole tier, not the printed rows: this number is what a
  // reader checks against the severity table on the summary page.
  const total = group.findings.length + group.hidden;
  const count = `${total} ${plural(total, "finding")}`;
  canvas.use(FONT.bold, SIZE.h3, COLOR.onColor);
  const width = canvas.widthOf(count);
  canvas.doc.text(toWinAnsi(count), canvas.right - 8 - width, top + 7, { lineBreak: false });
  canvas.y = top + bandHeight + 5;

  paragraph(canvas, group.rule, { color: COLOR.muted, size: SIZE.small });

  // A tier is a worklist. The members of a counted group are counted here
  // rather than listed, for the same reason section 5 collapses them, and the
  // count is printed so the tier still reconciles with the severity table.
  if (group.hidden > 0) {
    paragraph(
      canvas,
      `${group.hidden} further ${plural(group.hidden, "finding")} in this tier ${group.hidden === 1 ? "belongs" : "belong"} to a rule section 5 renders as a counted group, so ${group.hidden === 1 ? "it is" : "they are"} not listed again here. ${group.findings.length} + ${group.hidden} = ${group.findings.length + group.hidden}, and all of them are in findings.json.`,
      { color: COLOR.muted, size: SIZE.small },
    );
  }

  renderTable(canvas, {
    columns: [
      { header: "Severity", width: 58 },
      { header: "Domain", width: 96 },
      { header: "File:line", width: 152 },
      { header: "What to do", width: 176 },
    ],
    rows: group.findings.map((finding) => [
      { kind: "chip" as const, label: finding.severity, color: SEVERITY_COLOR[finding.severity] },
      { kind: "text" as const, text: DOMAIN_LABEL[finding.domain] },
      { kind: "mono" as const, text: citation(finding.location.file, finding.location.line) },
      { kind: "text" as const, text: finding.title },
    ]),
    emptyMessage: "Nothing in this tier.",
    zebra: true,
  });
}
