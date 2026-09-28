/**
 * Human verification — what a person checked, and what that changed.
 *
 * It sits between the coverage and the findings because it is a coverage
 * statement of its own: the sections before it say how much of the repository
 * the run examined, and this one says how much of the run's *output* a human
 * examined. Those are different numbers, and a dossier that prints the first
 * without the second invites "reviewed" to be read as "all reviewed".
 *
 * Which is why the page is ordered the way it is. The reach of the review
 * first, the part it did not reach immediately after — in a callout, because
 * when the verified findings are a small fraction of the whole that sentence is
 * the most load-bearing one in the document — and only then the tables. The withheld
 * findings lead them: a claim that was made and taken back is the one thing a
 * reader cannot reconstruct from anywhere else in the dossier, and printing it
 * here is what makes a corrected dossier different from a quietly edited one.
 */

import type { ReviewedFinding, TriageSummary } from "../triage.ts";
import { callout, heading, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { DOMAIN_CODE, DOMAIN_LABEL, type ReportModel } from "./model.ts";
import { type TableCell, type TableColumn, renderTable } from "./table.ts";
import { citation, plural } from "./text.ts";
import { COLOR, SEVERITY_COLOR, SIZE, STRENGTH_COLOR } from "./theme.ts";

/** Draws the human verification section, or nothing when no review was applied. */
export function renderTriage(canvas: ReportCanvas, model: ReportModel): void {
  const triage = model.triage;
  if (triage === null) return;

  canvas.beginSection("Human verification");
  sectionTitle(
    canvas,
    "Human verification",
    "Findings a person checked against the real code, and what that review changed. Everything it withheld is named here.",
  );

  paragraph(canvas, triage.statement);

  // The one sentence of this section that has to survive skim-reading, in the
  // one shape on the page a reader cannot skip past. Coloured as a warning on
  // purpose: an unreviewed majority is a limit of the document, not a detail.
  callout(canvas, triage.unreviewedStatement, SEVERITY_COLOR.high, {
    title: "What this review does not cover",
  });

  paragraph(
    canvas,
    `This dossier reports ${triage.findingsAfter} ${plural(triage.findingsAfter, "finding")}: the ${triage.findingsBefore} the run produced, less the ${triage.withheld.length} the review withheld. Every score in it is recomputed from the findings as corrected below, so a severity the reviewer lowered is a severity the scores were computed with.`,
    { color: COLOR.muted, size: SIZE.small },
  );

  renderDomainChanges(canvas, triage);
  renderWithheld(canvas, triage);
  renderCorrected(canvas, triage);
  renderConfirmed(canvas, triage);
  renderContested(canvas, triage);
}

/** What the review changed, domain by domain, with the score on both sides. */
function renderDomainChanges(canvas: ReportCanvas, triage: TriageSummary): void {
  if (triage.domains.length === 0) return;
  const scored = triage.domains.some((row) => row.scoreAfter !== undefined);
  heading(canvas, "What the review changed");

  const columns: TableColumn[] = [
    { header: "Domain", width: 132 },
    { header: "Reviewed", width: 52, align: "right" },
    { header: "Confirmed", width: 56, align: "right" },
    { header: "Corrected", width: 54, align: "right" },
    { header: "Withheld", width: 50, align: "right" },
    { header: "Contested", width: 54, align: "right" },
    { header: "Findings", width: 62, align: "right" },
    ...(scored ? [{ header: "Score", width: 62, align: "right" as const }] : []),
  ];

  renderTable(canvas, {
    columns,
    rows: triage.domains.map((row) => [
      {
        kind: "text" as const,
        text: `${DOMAIN_CODE[row.domain]} ${DOMAIN_LABEL[row.domain]}`,
        bold: true,
      },
      { kind: "text" as const, text: String(row.reviewed) },
      { kind: "text" as const, text: String(row.confirmed) },
      { kind: "text" as const, text: String(row.corrected) },
      { kind: "text" as const, text: String(row.withheld) },
      { kind: "text" as const, text: String(row.contested) },
      { kind: "text" as const, text: `${row.findingsBefore} -> ${row.findingsAfter}` },
      ...(scored
        ? [
            {
              kind: "text" as const,
              text: `${scoreLabel(row.scoreBefore)} -> ${scoreLabel(row.scoreAfter)}`,
            },
          ]
        : []),
    ]),
    emptyMessage: "The review touched no domain.",
  });

  paragraph(
    canvas,
    "The two numbers in the last columns are before the review and after it. A domain with no number was not scored by phase 6, which is not a zero.",
    { color: COLOR.muted, size: SIZE.tiny },
  );
}

/** A domain score, or the words phase 6 uses when it published no number. */
function scoreLabel(score: number | null | undefined): string {
  return score === null || score === undefined ? "n/a" : String(score);
}

/** The reason column, which is the reviewer's own text and is never trimmed. */
function noteCell(entry: ReviewedFinding): TableCell {
  return { kind: "text", text: entry.note };
}

/** The finding column: the title over its citation, so the row stands alone. */
function findingCell(entry: ReviewedFinding): TableCell {
  return { kind: "text", text: entry.title, bold: true };
}

/** Where it is, in the monospace the rest of the document cites in. */
function locationCell(entry: ReviewedFinding): TableCell {
  return { kind: "mono", text: `${citation(entry.file, entry.line)}\n${entry.rule}` };
}

/** The withheld table: what was claimed, and why it did not survive. */
function renderWithheld(canvas: ReportCanvas, triage: TriageSummary): void {
  if (triage.withheld.length === 0) return;
  heading(canvas, `Withheld by review (${triage.withheld.length})`, SEVERITY_COLOR.critical);
  paragraph(
    canvas,
    `${triage.withheld.length} ${plural(triage.withheld.length, "finding")} below ${triage.withheld.length === 1 ? "was" : "were"} reported by this run and did not survive verification. ${triage.withheld.length === 1 ? "It is" : "They are"} not in the findings section, not in any count and not in the scores. ${triage.withheld.length === 1 ? "It is" : "They are"} printed here because a reader cannot otherwise tell a claim that was withdrawn from one that was never made.`,
  );
  renderTable(canvas, {
    columns: [
      { header: "Reported as", width: 54 },
      { header: "Finding", width: 132 },
      { header: "Where", width: 120 },
      { header: "Why it was withheld", width: 176 },
    ],
    rows: triage.withheld.map((entry) => [
      {
        kind: "chip" as const,
        label: entry.reportedSeverity,
        color: SEVERITY_COLOR[entry.reportedSeverity],
      },
      findingCell(entry),
      locationCell(entry),
      noteCell(entry),
    ]),
  });
}

/** The corrections: both severities, so the reader can see what moved. */
function renderCorrected(canvas: ReportCanvas, triage: TriageSummary): void {
  if (triage.corrected.length === 0) return;
  heading(
    canvas,
    `Severity corrected by review (${triage.corrected.length})`,
    SEVERITY_COLOR.medium,
  );
  paragraph(
    canvas,
    "Real findings at the wrong severity. Both numbers are kept: the scores above were computed from the corrected one, and the original is printed so a reader can see the size of the correction.",
  );
  renderTable(canvas, {
    columns: [
      { header: "Reported", width: 50 },
      { header: "Corrected", width: 52 },
      { header: "Finding", width: 126 },
      { header: "Where", width: 116 },
      { header: "Why", width: 138 },
    ],
    rows: triage.corrected.map((entry) => [
      {
        kind: "chip" as const,
        label: entry.reportedSeverity,
        color: SEVERITY_COLOR[entry.reportedSeverity],
      },
      { kind: "chip" as const, label: entry.severity, color: SEVERITY_COLOR[entry.severity] },
      findingCell(entry),
      locationCell(entry),
      noteCell(entry),
    ]),
  });
}

/** The confirmed table, in the palette's green: these are the ones that held. */
function renderConfirmed(canvas: ReportCanvas, triage: TriageSummary): void {
  if (triage.confirmed.length === 0) return;
  heading(canvas, `Confirmed by review (${triage.confirmed.length})`, STRENGTH_COLOR);
  paragraph(
    canvas,
    "Checked against the real code, at the severity reported. This is the strongest statement in the dossier — not a model's claim about the code, but a person's, with the reasoning they used printed beside it — and these are the findings to act on first.",
  );
  renderTable(canvas, {
    columns: [
      { header: "Severity", width: 54 },
      { header: "Finding", width: 132 },
      { header: "Where", width: 120 },
      { header: "What the reviewer checked", width: 176 },
    ],
    rows: triage.confirmed.map((entry) => [
      { kind: "chip" as const, label: entry.severity, color: SEVERITY_COLOR[entry.severity] },
      findingCell(entry),
      locationCell(entry),
      noteCell(entry),
    ]),
  });
}

/** The undecided ones, which are neither confirmed nor withdrawn. */
function renderContested(canvas: ReportCanvas, triage: TriageSummary): void {
  if (triage.contested.length === 0) return;
  heading(canvas, `Contested (${triage.contested.length})`);
  paragraph(
    canvas,
    "The review could not decide these. They are kept at the severity this run reported, because an undecided finding is neither confirmed nor withdrawn — and they are marked so that the confirmed ones are not read as covering them.",
  );
  renderTable(canvas, {
    columns: [
      { header: "Severity", width: 54 },
      { header: "Finding", width: 132 },
      { header: "Where", width: 120 },
      { header: "What is unresolved", width: 176 },
    ],
    rows: triage.contested.map((entry) => [
      { kind: "chip" as const, label: entry.severity, color: SEVERITY_COLOR[entry.severity] },
      findingCell(entry),
      locationCell(entry),
      noteCell(entry),
    ]),
  });
}
