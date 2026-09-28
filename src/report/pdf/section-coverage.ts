/**
 * Section 4 — coverage and exclusions.
 *
 * The section exists to make one sentence impossible: "the report found nothing
 * there, so it is fine". For every domain it states what ran, what did not run
 * and why, what the operator declined when Sentinel offered it, what cannot
 * apply to this stack at all, and how many enumerated units came back without a
 * verdict.
 *
 * A domain with no score is rendered as words in every place a number could go.
 * A scorecard cell, a bar in a chart and a row in this table all say "not
 * assessed", never `0`, because a zero in a findings column is a claim. That
 * covers both ways a domain can end up without a score: nothing ran, and too
 * little ran. The chip is the same for both; the sentence under it is not, and
 * the "checks completed" column keeps showing the real fraction either way —
 * hiding `1 of 5` behind a dash would lose the measure of how thin it was.
 */

import { bullet, callout, chip, heading, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import {
  type DomainAssessment,
  type DomainView,
  type ReportModel,
  coverageFraction,
  isUnscored,
} from "./model.ts";
import { renderTable } from "./table.ts";
import { capitalise, formatCount, plural } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/** The colour each assessment earns; grey is reserved for "no score came out". */
const ASSESSMENT_COLOR: Readonly<Record<DomainAssessment, string>> = {
  assessed: STRENGTH_COLOR,
  partial: SEVERITY_COLOR.medium,
  insufficient: COLOR.muted,
  "out-of-scope": SEVERITY_COLOR.low,
  "not-assessed": COLOR.muted,
};

/**
 * The words each assessment prints; none of them is a number.
 *
 * `insufficient` and `not-assessed` deliberately print the same two words. The
 * reader's question at a glance is "can I lean on this domain", and the answer
 * is the same for both; the sentence under the chip is where they differ.
 */
const ASSESSMENT_LABEL: Readonly<Record<DomainAssessment, string>> = {
  assessed: "assessed",
  partial: "partial",
  insufficient: "not assessed",
  "out-of-scope": "out of scope",
  "not-assessed": "not assessed",
};

/** Draws section 4. */
export function renderCoverage(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Coverage and exclusions");
  sectionTitle(
    canvas,
    "Coverage and exclusions",
    "What ran, what did not, what was declined, and what cannot apply to this stack.",
  );

  paragraph(
    canvas,
    "Coverage is counted in units that were enumerated before they were audited: route handlers, data-access call sites, migrations, crons, webhooks, role gates and sinks, each with a file and a line in `inventory.json`. A fraction below 1 means named units came back without a verdict, and they are listed with the reason. A domain that was never in scope says so; it is not reported as clean.",
  );

  if (model.auditBound !== null) {
    // `**...**` printed the asterisks: this is a PDF canvas, not markdown. The
    // sentence is the one that says how much of the repository the run did not
    // reach, so it is set in bold type rather than wrapped in literal syntax.
    paragraph(canvas, model.auditBound, { font: FONT.bold, color: COLOR.ink });
  }

  renderOverview(canvas, model);

  for (const domain of model.domains) {
    renderDomain(canvas, domain);
  }
}

/** The one table that shows all eight domains at once. */
function renderOverview(canvas: ReportCanvas, model: ReportModel): void {
  renderTable(canvas, {
    columns: [
      { header: "Domain", width: 150 },
      { header: "Status", width: 74 },
      { header: "Checks completed", width: 88, align: "right" },
      { header: "Findings", width: 56, align: "right" },
      { header: "Assurances", width: 64, align: "right" },
      { header: "Un-audited", width: 74, align: "right" },
    ],
    rows: model.domains.map((domain) => {
      const unscored = isUnscored(domain.assessment);
      // What ran is a fact and is always printed. What was *found* is a result,
      // and a result column for an unscored domain is a dash: a `0` there is
      // the claim this whole section exists to prevent. The two differ, and a
      // domain that ran 1 of 5 checks has to show both halves of that.
      const checks = domain.checksCompleted;
      const result = (value: number): string => (unscored ? "—" : String(value));
      const color = unscored ? COLOR.muted : COLOR.body;
      return [
        { kind: "text" as const, text: `${domain.code} ${domain.label}`, bold: true },
        {
          kind: "chip" as const,
          label: ASSESSMENT_LABEL[domain.assessment],
          color: ASSESSMENT_COLOR[domain.assessment],
        },
        {
          kind: "text" as const,
          text: checks === undefined ? "—" : `${checks.done} of ${checks.total}`,
          color,
        },
        { kind: "text" as const, text: result(domain.findings.length), color },
        { kind: "text" as const, text: result(domain.assurances.length), color },
        {
          kind: "text" as const,
          text: domain.coverage === undefined ? "—" : String(domain.coverage.skipped.length),
          color,
        },
      ];
    }),
  });

  const note = overlapNote(model);
  if (note !== null) {
    canvas.moveDown(SPACE.paragraph);
    paragraph(canvas, note, { size: SIZE.small, color: COLOR.muted });
  }
}

/**
 * Why the `un-audited` column adds up to more than the run's own figure.
 *
 * One unit is evidence for several domains — a route handler is audited for
 * `appsec`, for `api` and for `reliability` — so a unit that came back without a
 * verdict is un-audited in each domain that wanted it, and the column counts it
 * once per domain. The section headline counts units, once each. Both are
 * right, and a reader who sums the column and gets a bigger number is entitled
 * to know why before concluding the document contradicts itself.
 *
 * `null` when there is nothing to reconcile: no audit, or a run where the two
 * happen to agree, in which case the sentence would only invite the doubt it
 * exists to answer.
 */
export function overlapNote(model: ReportModel): string | null {
  const units = model.auditUnits;
  if (units === null) return null;
  const perDomain = model.domains.reduce(
    (sum, domain) => sum + (domain.coverage?.skipped.length ?? 0),
    0,
  );
  const runWide = units.total - units.audited;
  if (perDomain <= runWide) return null;
  return `The un-audited column is counted per domain: a unit that several domains rely on — one route handler is evidence for application security, for the API surface and for reliability — is counted once in each of them, so this column sums to ${formatCount(perDomain)} while ${formatCount(runWide)} of the run's ${formatCount(units.total)} units went unexamined in total. The ${formatCount(runWide)} is how many distinct units nobody returned a verdict for; the column is what each domain was missing.`;
}

/** One domain's coverage block. */
function renderDomain(canvas: ReportCanvas, domain: DomainView): void {
  canvas.moveDown(SPACE.paragraph);
  heading(canvas, `${domain.code} ${domain.label}`);

  // The status chip sits on the line under the heading rather than beside it:
  // the heading may itself break to a new page, and a chip placed from a
  // coordinate captured before that break would be painted on the wrong sheet.
  // Room for the chip *and* its sentence is taken in one go, so they cannot be
  // separated by a break either.
  canvas.ensure(34);
  const top = canvas.y;
  const width = chip(
    canvas,
    canvas.left,
    top,
    ASSESSMENT_LABEL[domain.assessment],
    ASSESSMENT_COLOR[domain.assessment],
  );
  canvas.y = top;
  paragraph(canvas, domain.statusSentence, {
    size: SIZE.small,
    indent: width + 8,
    gapAfter: SPACE.paragraph,
  });
  canvas.y = Math.max(canvas.y, top + 16);

  if (domain.steps.length > 0) {
    renderTable(canvas, {
      columns: [
        { header: "Analyzer", width: 100 },
        { header: "Status", width: 56 },
        { header: "Findings", width: 48, align: "right" },
        { header: "What it could and could not see", width: 278 },
      ],
      rows: domain.steps.map((step) => [
        { kind: "mono" as const, text: step.step },
        {
          kind: "text" as const,
          text: step.status,
          color:
            step.status === "ok"
              ? COLOR.body
              : step.status === "skipped"
                ? COLOR.muted
                : SEVERITY_COLOR.medium,
        },
        { kind: "text" as const, text: String(step.findings) },
        {
          kind: "text" as const,
          text: step.reason ?? "ran with everything it needs",
          color: step.reason === undefined ? COLOR.muted : COLOR.body,
        },
      ]),
      fontSize: 7.5,
    });
  }

  if (domain.units.length > 0) {
    renderTable(canvas, {
      columns: [
        { header: "Units of audit", width: 150 },
        { header: "Audited", width: 60, align: "right" },
        { header: "Un-audited, and why", width: 272 },
      ],
      rows: domain.units.map((unit) => [
        { kind: "text" as const, text: unit.label, bold: true },
        {
          kind: "text" as const,
          text: `${unit.audited} of ${unit.total}`,
          color: unit.audited < unit.total ? SEVERITY_COLOR.medium : COLOR.body,
        },
        unit.skipped.length === 0
          ? { kind: "text" as const, text: "none", color: COLOR.muted }
          : {
              kind: "text" as const,
              text: unit.skipped.map((entry) => `${entry.units} x ${entry.reason}`).join("\n"),
            },
      ]),
      fontSize: 7.5,
    });
  }

  for (const declined of domain.declined) {
    bullet(canvas, `Declined at scope negotiation: ${declined.title} - ${declined.reason}.`, {
      color: SEVERITY_COLOR.low,
      size: SIZE.small,
    });
  }

  for (const reason of domain.notApplicable) {
    bullet(canvas, `Not applicable to this stack: ${reason}`, {
      color: COLOR.muted,
      size: SIZE.small,
    });
  }

  if (domain.assessment === "not-assessed") {
    callout(
      canvas,
      `Nothing in ${domain.label.toLowerCase()} was examined in this run. Read every empty cell for this domain as "unknown", not as "clean".`,
      COLOR.muted,
    );
  }

  if (domain.assessment === "insufficient") {
    callout(
      canvas,
      `${domain.checksCompleted === undefined ? "Too few checks completed" : capitalise(coverageFraction(domain.checksCompleted))} for ${domain.label.toLowerCase()}, which is below the coverage this report requires before it will publish a score. The checks that did not run are named in the table above, with the reason each one had nothing to read. No score is given for this domain, and the findings and assurances columns are left empty on purpose: read them as "unknown", not as "clean".`,
      COLOR.muted,
    );
  }

  if (domain.assessment === "out-of-scope" && domain.findings.length > 0) {
    callout(
      canvas,
      `This domain was not part of the run's scope, so it has no coverage figure. ${domain.findings.length} ${plural(domain.findings.length, "finding")} still reached the report because another domain's audit found ${domain.findings.length === 1 ? "it" : "them"}; they are reported in section 5, and they are not evidence that the domain as a whole was reviewed.`,
      SEVERITY_COLOR.low,
    );
  }
}
