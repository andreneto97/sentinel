/**
 * Section 2 — the executive summary: the one page a busy reader will read.
 *
 * It answers four questions and nothing else: how much was found, how bad, in
 * which parts of the system, and how much of the system the run can actually
 * speak to. The last one is why the scorecard and the coverage column sit on
 * this page instead of only in section 4 — a headline count without a coverage
 * figure beside it invites the reader to treat silence as safety.
 */

import { drawBars, drawDonut } from "./charts.ts";
import {
  callout,
  chip,
  heading,
  labelled,
  legendEntry,
  paragraph,
  sectionTitle,
  severityChip,
} from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import {
  DOMAIN_LABEL,
  type ReportModel,
  coverageFraction,
  isUnscored,
  listSentence,
  severityChartData,
} from "./model.ts";
import { type TableOptions, measureTable, renderTable } from "./table.ts";
import { plural, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/** Draws the executive summary, both charts included. */
export function renderExecutiveSummary(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Executive summary");
  sectionTitle(canvas, "Executive summary");

  const assessed = model.domains.filter(
    (domain) => domain.assessment === "assessed" || domain.assessment === "partial",
  );
  const notAssessed = model.domains.filter((domain) => domain.assessment === "not-assessed");
  const insufficient = model.domains.filter((domain) => domain.assessment === "insufficient");
  const outOfScope = model.domains.filter((domain) => domain.assessment === "out-of-scope");

  // Built as parts rather than one sentence: each clause is a separate claim,
  // and the three about coverage only exist when there is something to admit.
  const headline = [
    `${model.severity.total} ${plural(model.severity.total, "finding")} and ${model.assurances.length} ${plural(model.assurances.length, "assurance")} came out of this run, across ${assessed.length} of ${model.domains.length} domains.`,
    `The assurances cover ${model.unitsAssured} unit checks that passed with evidence, and they are reported first, in section 3.`,
    notAssessed.length === 0
      ? ""
      : `${notAssessed.length} ${plural(notAssessed.length, "domain")} ${notAssessed.length === 1 ? "was" : "were"} not assessed at all: ${notAssessed.map((domain) => domain.label).join(", ")}. Nothing was checked there, which is not the same as nothing being wrong.`,
  ].filter((part) => part !== "");
  // A domain can miss a number for two unrelated reasons, and they must not be
  // worded alike: too few of its checks ran, or all of them ran and nothing
  // examined a unit. Saying "checked too thinly — data layer, where 1 of 1
  // planned check completed (100%)" contradicts itself inside one clause.
  const thinChecks = insufficient.filter((domain) => !domain.heldBackByEvidence);
  const unexamined = insufficient.filter((domain) => domain.heldBackByEvidence);
  if (thinChecks.length > 0) {
    // It names the fraction, because "not assessed" on its own invites the
    // reader to assume there was nothing there to check in the first place.
    const thin = thinChecks.map((domain) => {
      const ran =
        domain.checksCompleted === undefined
          ? "too few checks ran"
          : coverageFraction(domain.checksCompleted);
      return `${domain.label.toLowerCase()}, where ${ran}`;
    });
    headline.push(
      `${thinChecks.length === 1 ? "One domain was" : `${thinChecks.length} domains were`} checked too thinly to score — ${listSentence(thin)} — so ${thinChecks.length === 1 ? "it is" : "they are"} reported as not assessed rather than as clean.`,
    );
  }
  if (unexamined.length > 0) {
    headline.push(
      `${unexamined.length === 1 ? "One domain ran its checks and still earned no number" : `${unexamined.length} domains ran their checks and still earned no number`} — ${listSentence(unexamined.map((domain) => domain.label.toLowerCase()))} — because nothing examined the units ${unexamined.length === 1 ? "it has" : "they have"}: a check that ran is not a unit that was looked at, and a linter finding nothing is not evidence of health. The per-domain reasons are under the scorecard.`,
    );
  }
  if (outOfScope.length > 0) {
    headline.push(
      `${listSentence(outOfScope.map((domain) => domain.label))} ${outOfScope.length === 1 ? "was" : "were"} outside this run's scope, yet still produced findings while another domain was being audited; those findings are reported, the domain is not claimed as reviewed.`,
    );
  }
  if (notAssessed.length === 0 && insufficient.length === 0 && outOfScope.length === 0) {
    headline.push("Every domain was assessed.");
  }
  // Last clause of the headline, and the only one a human made: how much of
  // this output a person checked, and what the rest therefore is.
  if (model.triage !== null) {
    headline.push(model.triage.statement, model.triage.unreviewedStatement);
  }
  paragraph(canvas, headline.join(" "));

  renderSeverityStrip(canvas, model);
  renderCharts(canvas, model);
  renderScorecard(canvas, model);
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

/** The donut by severity and the stacked bars by domain, side by side and below. */
function renderCharts(canvas: ReportCanvas, model: ReportModel): void {
  const data = severityChartData(model.severity);
  const donutRadius = 52;
  const donutHeight = donutRadius * 2 + 8;
  const legendHeight = (data.length + 1) * 15 + 6;
  const blockHeight = Math.max(donutHeight, legendHeight);

  // The heading is drawn through the normal flow first, so a page break lands
  // before the chart rather than between the chart and its title. Only then is
  // the block's own top read: absolute coordinates computed before a possible
  // break would paint the donut onto the previous page's geometry.
  heading(canvas, "By severity", COLOR.ink);
  canvas.ensure(blockHeight + 6);
  const top = canvas.y + 4;
  const cx = canvas.left + donutRadius + 10;

  drawDonut(canvas.doc, {
    cx,
    cy: top + donutRadius,
    outerRadius: donutRadius,
    innerRadius: donutRadius - 17,
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

  // The strengths counterpart, in the palette's green, so the page cannot be
  // read as "colour means broken".
  legendEntry(
    canvas,
    legendLeft,
    top + data.length * 15 + 6,
    STRENGTH_COLOR,
    "Assurances (section 3)",
    String(model.assurances.length),
  );

  canvas.y = top + blockHeight;

  heading(canvas, "By domain", COLOR.ink);
  const rowHeight = 11;
  const rowGap = 5;
  canvas.ensure(model.domains.length * (rowHeight + rowGap) + 4);
  const barsTop = canvas.y + 2;
  const groups = model.domains.map((domain) => ({
    key: domain.domain,
    label: domain.label,
    data: severityChartData(domain.severity).filter((datum) => datum.value > 0),
    // An unscored domain never shows a count, not even a zero: an empty track
    // next to `0` is the one cell on this page that reads as a clean result.
    ...(isUnscored(domain.assessment) ? { note: "not assessed" } : {}),
  }));
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
    groups,
  });
  canvas.restore();
  canvas.y = barsTop + groups.length * (rowHeight + rowGap);
  canvas.moveDown(SPACE.paragraph);

  canvas.use(FONT.italic, SIZE.tiny, COLOR.muted);
  canvas.doc.text(
    toWinAnsi(
      "Each bar is stacked by severity in the palette above. An empty track is a domain with no findings; a domain marked “not assessed” earned no score — because nothing was checked, or because too little was — and its empty track is not a result.",
    ),
    canvas.left,
    canvas.y,
    { width: canvas.width },
  );
  canvas.moveDown(SPACE.block);
}

/** The per-domain scorecard, plus whatever capped it. */
function renderScorecard(canvas: ReportCanvas, model: ReportModel): void {
  const card = model.scorecard;
  const table = scorecardTable(model);
  const tableHeight = measureTable(canvas, table);

  // The scorecard moves as one block. Its whole purpose is comparison — D2
  // against D4, a score against the coverage beside it — and a reader holding
  // five domains on one sheet and three on the next is doing the arithmetic the
  // table was supposed to do for them. Asking for the room first also keeps the
  // heading, the overall chip and the ceiling that explains it together.
  canvas.ensure(SIZE.h2 * 2.4 + SPACE.paragraph + 30 + ceilingsHeight(canvas, card) + tableHeight);
  heading(canvas, "Scorecard");

  if (!card.present) {
    paragraph(
      canvas,
      "No scorecard was produced for this run, so this dossier reports counts, coverage and evidence instead of a score. An absent score is not a passing score.",
      { color: COLOR.muted },
    );
  } else {
    const overall = `${card.overall.score}${card.overall.band === "—" ? "" : ` / band ${card.overall.band}`}`;
    canvas.ensure(30);
    const top = canvas.y;
    chip(canvas, canvas.left, top, `overall ${overall}`, card.overall.color);
    canvas.use(FONT.regular, SIZE.small, COLOR.muted);
    canvas.doc.text(
      toWinAnsi(
        card.overall.derived
          ? "Derived by this report as the unweighted mean of the domains that were scored; phase 6 published no run-level verdict."
          : `Run-level verdict from phase 6. Confidence: ${card.overall.confidence}.`,
      ),
      canvas.left + 150,
      top + 1,
      { width: canvas.width - 150 },
    );
    canvas.y = Math.max(canvas.y, top + 16);
    canvas.moveDown(SPACE.paragraph);
  }

  // Above the table, not below it. A ceiling is the explanation of the number
  // in the chip immediately above, so this is where it reads; and it keeps the
  // last block on the page a table, which is the one thing here that can break
  // across pages and take its header with it. Below the table, a callout that
  // did not fit became a page holding nothing but a callout.
  for (const ceiling of card.ceilings) {
    callout(canvas, ceiling.reason, SEVERITY_COLOR.critical, {
      title: `Score ceiling applied to ${DOMAIN_LABEL[ceiling.domain].toLowerCase()}`,
    });
  }

  renderTable(canvas, table);
  renderUnscoredNotes(canvas, model);
}

/**
 * Why each dash in the table is a dash.
 *
 * Without this, the only thing the scorecard says about three of eight domains
 * is `—`, and a reader who does not turn to section 4 is left to guess whether
 * that means "nothing to report" or "nobody looked". It is the same sentence
 * section 4 prints, on the page the client actually reads.
 */
function renderUnscoredNotes(canvas: ReportCanvas, model: ReportModel): void {
  const unscored = model.domains.filter(
    (domain) => isUnscored(domain.assessment) || domain.assessment === "out-of-scope",
  );
  if (unscored.length === 0) return;

  canvas.moveDown(SPACE.paragraph);
  paragraph(
    canvas,
    `Why ${unscored.length} ${plural(unscored.length, "domain")} ${unscored.length === 1 ? "has" : "have"} no score:`,
    { font: FONT.bold, size: SIZE.small },
  );
  for (const domain of unscored) {
    labelled(canvas, `${domain.code} ${domain.label}`, domain.statusSentence, {
      labelWidth: 160,
      color: COLOR.muted,
    });
  }
}

/** Room the ceiling callouts need, so the block above can be reserved whole. */
function ceilingsHeight(canvas: ReportCanvas, card: ReportModel["scorecard"]): number {
  const padding = 7;
  const innerWidth = canvas.width - padding * 2 - 3;
  canvas.use(FONT.regular, SIZE.small, COLOR.body);
  return card.ceilings.reduce(
    (sum, ceiling) =>
      sum +
      canvas.measure(ceiling.reason, innerWidth) +
      padding * 2 +
      SIZE.h3 +
      3 +
      SPACE.paragraph,
    0,
  );
}

/** The scorecard table, described once so it can be measured before it is drawn. */
function scorecardTable(model: ReportModel): TableOptions {
  return {
    columns: [
      // "not assessed" is two words this column has to fit on one line: broken
      // over two, the only cell that says a domain has no score is the hardest
      // one on the page to read.
      { header: "Domain", width: 146 },
      { header: "Score", width: 74, align: "right" },
      { header: "Band", width: 38 },
      { header: "Coverage", width: 54, align: "right" },
      { header: "Confidence", width: 58, align: "right" },
      { header: "Findings", width: 112 },
    ],
    rows: model.domains.map((domain) => {
      const row = model.scorecard.domains.find((entry) => entry.domain === domain.domain);
      const counts = severityChartData(domain.severity)
        .filter((datum) => datum.value > 0)
        .map((datum) => `${datum.value} ${datum.label.toLowerCase()}`);
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
        { kind: "text" as const, text: row?.confidence ?? "—" },
        {
          // `none` is a claim — it says the domain was looked at and was clean
          // — so it is reserved for a domain that actually earned a score.
          kind: "text" as const,
          text: isUnscored(domain.assessment)
            ? counts.length === 0
              ? "not assessed"
              : `${counts.join(", ")} (domain not assessed)`
            : counts.length === 0
              ? "none"
              : counts.join(", "),
          color: isUnscored(domain.assessment) ? COLOR.muted : COLOR.body,
        },
      ];
    }),
  };
}
