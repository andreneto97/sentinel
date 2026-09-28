/**
 * The brief's counted section: everything at medium and below, as counts.
 *
 * One row per (domain, rule), never one row per finding. The row carries the
 * count, the worst severity, the mix, the files it spans and one representative
 * citation — enough for a reader to see that the debt is "85 locking migrations,
 * 71 migrations without a rollback path, 57 foreign keys without an index" and
 * understand its shape without reading three hundred pages of it.
 *
 * Every table is followed by the sentence that says where its members are
 * printed in full. A count without that sentence would be a summary pretending
 * to be a list.
 */

import type { BriefDomainGroups, BriefGroup, BriefModel } from "../brief.ts";
import { severityMix } from "../brief.ts";
import { heading, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { type TableCell, renderTable } from "./table.ts";
import { citation, plural } from "./text.ts";
import { COLOR, SEVERITY_COLOR, SIZE } from "./theme.ts";

/** `1,234`, matching every other count in the brief. */
function group(count: number): string {
  return count.toLocaleString("en-US");
}

/** Draws the brief's counted section. */
export function renderBriefGroups(canvas: ReportCanvas, brief: BriefModel): void {
  canvas.beginSection("Medium and below");
  sectionTitle(
    canvas,
    `Medium and below — ${group(brief.omissions.counted)} ${plural(brief.omissions.counted, "finding")}, counted`,
    "One row per rule, not per finding: the count, the severity mix, the files it spans and one representative citation.",
  );

  if (brief.omissions.counted === 0) {
    paragraph(
      canvas,
      "This run produced no finding below high severity, so there is nothing to count here.",
    );
    return;
  }

  paragraph(
    canvas,
    `${group(brief.omissions.counted)} ${plural(brief.omissions.counted, "finding")} sit at medium or lower, in ${brief.groups.length} ${plural(brief.groups.length, "rule")} across ${brief.domains.length} ${plural(brief.domains.length, "domain")}. None of them is printed in full in this document. A row stands for every member of its rule: the description, preconditions, impact, fix and verified snippet of each member are in the full dossier, and each member has its own id and citation in \`findings.json\`.`,
  );
  paragraph(
    canvas,
    brief.omissions.countedUnreviewed === brief.omissions.counted
      ? `None of these ${group(brief.omissions.counted)} findings carries a human verdict. The counts are this run's own output: reliable about the shape of the debt, unverified one finding at a time.`
      : `${group(brief.omissions.countedReviewed)} of these ${group(brief.omissions.counted)} findings ${brief.omissions.countedReviewed === 1 ? "carries" : "carry"} a human verdict; ${group(brief.omissions.countedUnreviewed)} ${brief.omissions.countedUnreviewed === 1 ? "carries" : "carry"} none.`,
    { color: COLOR.muted, size: SIZE.small },
  );

  for (const domain of brief.domains) renderDomainGroups(canvas, domain);
}

/** One domain: its totals, its counted rows, and where they can be read in full. */
function renderDomainGroups(canvas: ReportCanvas, domain: BriefDomainGroups): void {
  canvas.ensure(110);
  heading(
    canvas,
    `${domain.code} ${domain.label} — ${group(domain.count)} ${plural(domain.count, "finding")} in ${domain.groups.length} ${plural(domain.groups.length, "rule")}`,
  );
  paragraph(canvas, severityMix(domain.severities), { color: COLOR.muted, size: SIZE.small });

  renderTable(canvas, {
    columns: [
      { header: "Count", width: 32, align: "right" },
      { header: "Worst", width: 46 },
      { header: "What it is", width: 146 },
      { header: "Rule", width: 116 },
      // The widest column that is not prose: a citation wrapped over four
      // monospace lines makes every row in the table twice as tall as it needs
      // to be, and the path is what a reader copies into an editor.
      { header: "Representative example", width: 142 },
    ],
    rows: domain.groups.map((entry) => rowCells(entry)),
  });

  paragraph(canvas, domain.fullListSentence, { color: COLOR.muted, size: SIZE.small });
}

/** One counted row. The count leads, because it is what the reader came for. */
function rowCells(entry: BriefGroup): readonly TableCell[] {
  return [
    { kind: "text" as const, text: group(entry.count), bold: true },
    { kind: "chip" as const, label: entry.severity, color: SEVERITY_COLOR[entry.severity] },
    { kind: "text" as const, text: `${entry.label}\n${entry.mix}` },
    { kind: "mono" as const, text: entry.rule },
    {
      kind: "mono" as const,
      text: citation(entry.example.location.file, entry.example.location.line),
    },
  ];
}
