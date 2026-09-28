/**
 * The brief's cover, and the one page of executive summary behind it.
 *
 * The dossier's cover establishes what the document is about; this one has a
 * second job the long document does not: it has to make it impossible to mistake
 * the brief for the audit. So the title says so, the facts table prints both
 * counts — detailed here, counted only — and the first callout a reader meets is
 * the one that names the other document by file name.
 *
 * The summary page carries what a busy reader would otherwise go looking for in
 * the dossier: the severity strip, the two charts, the scorecard, and the
 * human-verification sentence. Those numbers are the dossier's own, computed from
 * the full findings set, which is why the brief can print them without a caveat.
 */

import type { BriefModel } from "../brief.ts";
import { REPORT_MARKDOWN_FILE } from "../markdown.ts";
import { drawBars, drawDonut } from "./charts.ts";
import {
  callout,
  chip,
  fillRect,
  hairline,
  heading,
  labelled,
  legendEntry,
  paragraph,
  sectionTitle,
  severityChip,
} from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { DOMAIN_LABEL, type ReportModel, isUnscored, severityChartData } from "./model.ts";
import { REPORT_PDF_FILE } from "./render.ts";
import { type TableOptions, renderTable } from "./table.ts";
import { formatDate, plural, shortenPath, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/** `1,234`, matching every other count in the brief. */
function group(count: number): string {
  return count.toLocaleString("en-US");
}

/** Draws the brief's cover page. */
export function renderBriefCover(canvas: ReportCanvas, brief: BriefModel): void {
  const model = brief.report;
  canvas.beginCover();

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
  canvas.moveDown(5 + 70);

  canvas.use(FONT.regular, SIZE.subtitle, COLOR.muted);
  canvas.doc.text("SENTINEL", canvas.left, canvas.y, { characterSpacing: 3 });
  canvas.moveDown(10);

  canvas.use(FONT.bold, SIZE.title, COLOR.ink);
  canvas.doc.text("Executive Brief", canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(4);

  canvas.use(FONT.regular, SIZE.h1, COLOR.body);
  canvas.doc.text(toWinAnsi(model.repository), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(SPACE.block);
  hairline(canvas, canvas.y);
  canvas.moveDown(SPACE.block);

  const labelWidth = 150;
  labelled(canvas, "Repository", `${model.repository} - ${shortenPath(model.target)}`, {
    labelWidth,
  });
  labelled(canvas, "Commit", model.commitLabel, { labelWidth });
  labelled(canvas, "Report date", formatDate(model.generatedAt), { labelWidth });
  labelled(canvas, "Run id", model.runId, { labelWidth });
  labelled(
    canvas,
    "Findings in the dossier",
    `${group(brief.omissions.total)} ${plural(brief.omissions.total, "finding")}`,
    { labelWidth },
  );
  labelled(
    canvas,
    "Detailed in full here",
    `${group(brief.omissions.detailed)} critical and high`,
    { labelWidth },
  );
  labelled(
    canvas,
    "Counted, not detailed",
    `${group(brief.omissions.counted)} at medium and below`,
    { labelWidth },
  );
  // Without this row the page carries two totals that do not match: the dossier's
  // count is after the review, and the review's own sentence below quotes the
  // count before it. The difference is exactly the withheld claims, so it is
  // named rather than left for the reader to work out.
  if (brief.omissions.withheld > 0) {
    labelled(
      canvas,
      "Withheld by review",
      `${group(brief.omissions.withheld)} ${plural(brief.omissions.withheld, "claim")}, in none of the counts above`,
      { labelWidth },
    );
  }

  canvas.moveDown(SPACE.block);
  callout(
    canvas,
    `This is a summary. The audit is \`${REPORT_PDF_FILE}\` and \`${REPORT_MARKDOWN_FILE}\` beside it, and \`findings.json\` carries every finding with its id, citation and verified snippet. This document prints ${group(brief.omissions.detailed)} of the dossier's ${group(brief.omissions.total)} findings in full — every critical and high — and states the other ${group(brief.omissions.counted)} as counts per domain and rule. The last page lists what that leaves out, in numbers. Do not sign anything off from this page alone.`,
    SEVERITY_COLOR.high,
    { title: "What this document is, and what it is not" },
  );

  callout(
    canvas,
    "Every finding printed in full below cites a file and a line Sentinel opened on disk; the code shown was extracted from the repository, never written by a model. The counts are the dossier's own, computed from the complete findings set rather than from the part reproduced here.",
    COLOR.ink,
    { title: "How to read this document" },
  );

  if (model.analysisScope !== null) {
    callout(
      canvas,
      `${model.analysisScope} Nothing here is evidence about the parts of the repository it does not name: they were counted, and they were not analysed.`,
      SEVERITY_COLOR.high,
      { title: "This run analysed part of the repository" },
    );
  }

  if (brief.verification !== null) {
    callout(
      canvas,
      `${brief.verification}${brief.detailedVerificationSentence === null ? "" : ` ${brief.detailedVerificationSentence}`}`,
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
}

/** Draws the brief's one-page executive summary. */
export function renderBriefSummary(canvas: ReportCanvas, brief: BriefModel): void {
  const model = brief.report;
  canvas.beginSection("Executive summary");
  sectionTitle(canvas, "Executive summary");

  const notAssessed = model.domains.filter((domain) => isUnscored(domain.assessment));
  const headline = [
    `${group(model.severity.total)} ${plural(model.severity.total, "finding")} came out of this run: ${group(brief.omissions.detailed)} at critical or high severity, ${group(brief.omissions.counted)} at medium and below.`,
    brief.omissions.detailed === 0
      ? "Nothing reached critical or high, so this brief has no detail section; the counted tables are the whole of its findings content."
      : `The ${group(brief.omissions.detailed)} are printed in full in the next section and are the part of this run someone has to act on.`,
    notAssessed.length === 0
      ? "Every domain earned a score."
      : `${notAssessed.length} of ${model.domains.length} ${plural(notAssessed.length, "domain")} earned no score — ${notAssessed.map((domain) => domain.label.toLowerCase()).join(", ")} — because nothing was checked there or too little was. An absent score is not a clean one, and the full dossier's coverage section says why for each.`,
  ];
  if (brief.verification !== null) headline.push(brief.verification);
  else
    headline.push(
      "No human review was applied to this run, so every finding in this document is unreviewed output.",
    );
  paragraph(canvas, headline.join(" "));

  renderSeverityStrip(canvas, model);
  renderCharts(canvas, model);
  renderScorecard(canvas, brief);
}

/** A row of severity chips with their counts: the headline numbers, in colour. */
function renderSeverityStrip(canvas: ReportCanvas, model: ReportModel): void {
  const cellWidth = canvas.width / 5;
  canvas.ensure(34);
  const top = canvas.y;
  severityChartData(model.severity).forEach((datum, index) => {
    const x = canvas.left + index * cellWidth;
    severityChip(canvas, x, top, datum.key as Parameters<typeof severityChip>[3]);
    canvas.use(FONT.bold, SIZE.h1, datum.value === 0 ? COLOR.muted : COLOR.ink);
    canvas.doc.text(String(datum.value), x, top + 14, { lineBreak: false });
  });
  canvas.y = top + 34;
  canvas.moveDown(SPACE.paragraph);
}

/** The donut by severity beside its legend, and the stacked bars by domain below. */
function renderCharts(canvas: ReportCanvas, model: ReportModel): void {
  const data = severityChartData(model.severity);
  const donutRadius = 46;
  const blockHeight = Math.max(donutRadius * 2 + 8, data.length * 15 + 6);

  heading(canvas, "By severity", COLOR.ink);
  canvas.ensure(blockHeight + 6);
  const top = canvas.y + 4;
  drawDonut(canvas.doc, {
    cx: canvas.left + donutRadius + 10,
    cy: top + donutRadius,
    outerRadius: donutRadius,
    innerRadius: donutRadius - 16,
    data,
    centerLabel: plural(model.severity.total, "finding"),
  });
  canvas.restore();

  const legendLeft = canvas.left + donutRadius * 2 + 40;
  data.forEach((datum, index) => {
    const percent =
      model.severity.total === 0
        ? "—"
        : `${Math.round((datum.value / model.severity.total) * 100)}%`;
    legendEntry(
      canvas,
      legendLeft,
      top + index * 15,
      datum.color,
      datum.label,
      datum.value === 0 ? "none" : `${datum.value}  (${percent})`,
    );
  });
  canvas.y = top + blockHeight;

  heading(canvas, "By domain", COLOR.ink);
  const rowHeight = 10;
  const rowGap = 4;
  canvas.ensure(model.domains.length * (rowHeight + rowGap) + 4);
  const barsTop = canvas.y + 2;
  const labelWidth = 118;
  const valueWidth = 60;
  drawBars(canvas.doc, {
    x: canvas.left,
    y: barsTop,
    labelWidth,
    barWidth: canvas.width - labelWidth - valueWidth - 12,
    valueWidth,
    rowHeight,
    rowGap,
    groups: model.domains.map((domain) => ({
      key: domain.domain,
      label: domain.label,
      data: severityChartData(domain.severity).filter((datum) => datum.value > 0),
      ...(isUnscored(domain.assessment) ? { note: "not assessed" } : {}),
    })),
  });
  canvas.restore();
  canvas.y = barsTop + model.domains.length * (rowHeight + rowGap);
  canvas.moveDown(SPACE.paragraph);

  canvas.use(FONT.italic, SIZE.tiny, COLOR.muted);
  canvas.ensure(SIZE.tiny * 3);
  canvas.doc.text(
    toWinAnsi(
      "Each bar is stacked by severity in the palette above. An empty track is a domain with no findings; a domain marked “not assessed” earned no score, and its empty track is not a result.",
    ),
    canvas.left,
    canvas.y,
    { width: canvas.width },
  );
  canvas.moveDown(SPACE.paragraph);
}

/** The per-domain scorecard, with the detailed/counted split beside each row. */
function renderScorecard(canvas: ReportCanvas, brief: BriefModel): void {
  const model = brief.report;
  const card = model.scorecard;
  heading(canvas, "Scorecard");

  if (!card.present) {
    paragraph(
      canvas,
      "No scorecard was produced for this run, so this brief reports counts and coverage instead of a score. An absent score is not a passing score.",
      { color: COLOR.muted },
    );
  } else {
    canvas.ensure(30);
    const top = canvas.y;
    const overall = `${card.overall.score}${card.overall.band === "—" ? "" : ` / band ${card.overall.band}`}`;
    chip(canvas, canvas.left, top, `overall ${overall}`, card.overall.color);
    canvas.use(FONT.regular, SIZE.small, COLOR.muted);
    canvas.doc.text(
      toWinAnsi(
        card.overall.derived
          ? "Derived as the unweighted mean of the domains that were scored; phase 6 published no run-level verdict."
          : `Run-level verdict from phase 6, computed from every finding in the dossier. Confidence: ${card.overall.confidence}.`,
      ),
      canvas.left + 150,
      top + 1,
      { width: canvas.width - 150 },
    );
    canvas.y = Math.max(canvas.y, top + 16);
    canvas.moveDown(SPACE.paragraph);
  }

  for (const ceiling of card.ceilings) {
    callout(canvas, ceiling.reason, SEVERITY_COLOR.critical, {
      title: `Score ceiling applied to ${DOMAIN_LABEL[ceiling.domain].toLowerCase()}`,
    });
  }

  renderTable(canvas, scorecardTable(brief));
  paragraph(
    canvas,
    "The last two columns are this brief's own split: which of a domain's findings are printed in full below, and which appear only as a counted row. A domain with no score was not checked enough to earn one, which is not the same as a clean one; the full dossier states the reason for each.",
    { color: COLOR.muted, size: SIZE.tiny },
  );
}

/** The scorecard table: phase 6's numbers, plus the brief's detailed/counted split. */
function scorecardTable(brief: BriefModel): TableOptions {
  const model = brief.report;
  return {
    columns: [
      { header: "Domain", width: 150 },
      { header: "Score", width: 66, align: "right" },
      { header: "Band", width: 34 },
      { header: "Coverage", width: 52, align: "right" },
      { header: "Detailed", width: 52, align: "right" },
      { header: "Counted", width: 52, align: "right" },
      { header: "Severities", width: 108 },
    ],
    rows: model.domains.map((domain) => {
      const row = model.scorecard.domains.find((entry) => entry.domain === domain.domain);
      const detailed = domain.findings.filter(
        (finding) => finding.severity === "critical" || finding.severity === "high",
      ).length;
      const counted = domain.findings.length - detailed;
      const unscored = isUnscored(domain.assessment);
      return [
        { kind: "text" as const, text: `${domain.code} ${domain.label}`, bold: true },
        {
          kind: "text" as const,
          text: row?.score ?? "not assessed",
          color: row?.status === "not-assessed" ? COLOR.muted : COLOR.ink,
        },
        row === undefined || row.band === "—"
          ? { kind: "text" as const, text: "—", color: COLOR.muted }
          : { kind: "chip" as const, label: row.band, color: row.bandColor },
        { kind: "text" as const, text: row?.coverage ?? "—" },
        { kind: "text" as const, text: group(detailed) },
        { kind: "text" as const, text: group(counted) },
        {
          kind: "text" as const,
          text:
            domain.severity.total === 0
              ? unscored
                ? "not assessed"
                : "none"
              : severityChartData(domain.severity)
                  .filter((datum) => datum.value > 0)
                  .map((datum) => `${datum.value} ${datum.label.toLowerCase()}`)
                  .join(", "),
          color: unscored ? COLOR.muted : COLOR.body,
        },
      ];
    }),
  };
}
