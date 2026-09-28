/**
 * The brief's detail section: every critical and high, in full.
 *
 * "In full" is the contract. Same verified snippet, same preconditions, same
 * impact, same fix, same human verdict as the dossier prints — the brief is
 * shorter because it omits *other* findings, never because it abridges these.
 * A block here that summarised its finding would leave the reader acting on a
 * paraphrase, which is the one thing a short document must not tempt anybody to
 * do.
 *
 * The blocks are preceded by a table of all of them, so a reader can see the
 * whole worklist on one page before reading any of it, and each block states
 * where in the dossier the same finding can be found.
 */

import type { Finding } from "../../contracts/findings.ts";
import type { BriefModel } from "../brief.ts";
import type { ReviewedFinding } from "../triage.ts";
import { reviewLabel } from "../triage.ts";
import {
  callout,
  codeBox,
  hairline,
  labelled,
  monoLine,
  paragraph,
  sectionTitle,
  severityChip,
} from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { DOMAIN_CODE, DOMAIN_LABEL } from "./model.ts";
import { renderTable } from "./table.ts";
import { citation, plural, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/** Width of the inline labels in a detail block; the dossier's own. */
const LABEL_WIDTH = 92;

/** Draws the brief's detail section. */
export function renderBriefDetail(canvas: ReportCanvas, brief: BriefModel): void {
  canvas.beginSection("Critical and high");
  sectionTitle(
    canvas,
    `Critical and high — ${brief.detailed.length} ${plural(brief.detailed.length, "finding")}, in full`,
    "Reproduced from the dossier without abridgement: the same verified snippet, preconditions, impact, fix and human verdict.",
  );

  if (brief.detailed.length === 0) {
    paragraph(
      canvas,
      "No finding in this run is critical or high, so there is nothing to detail here. Read that against coverage rather than as a clean bill of health: a domain that was not assessed cannot produce a critical, and the full dossier's coverage section states how many enumerated units a verdict actually examined.",
    );
    return;
  }

  paragraph(
    canvas,
    `${brief.detailed.length} of this run's ${brief.omissions.total.toLocaleString("en-US")} findings are critical or high.${
      brief.detailedVerificationSentence === null
        ? " No human review was applied to this run, so every block below is unreviewed output."
        : ` ${brief.detailedVerificationSentence} The reviewer's own reasoning is printed with the finding it decided.`
    } Everything at medium and below is counted in the next section instead.`,
  );

  renderTable(canvas, {
    columns: [
      { header: "Severity", width: 54 },
      // Wide enough for the word "Domain" on one line: a header broken over two
      // lines is the column a reader stops trusting first.
      { header: "Domain", width: 44 },
      { header: "File:line", width: 160 },
      { header: "Finding", width: 166 },
      { header: "Verified", width: 58 },
    ],
    rows: brief.detailed.map((finding) => {
      const review = brief.reviews.get(finding.id);
      return [
        { kind: "chip" as const, label: finding.severity, color: SEVERITY_COLOR[finding.severity] },
        { kind: "text" as const, text: DOMAIN_CODE[finding.domain] },
        { kind: "mono" as const, text: citation(finding.location.file, finding.location.line) },
        { kind: "text" as const, text: finding.title },
        {
          kind: "text" as const,
          text: review === undefined ? "no" : verifiedWord(review),
          color: review === undefined ? COLOR.muted : COLOR.body,
        },
      ];
    }),
  });

  brief.detailed.forEach((finding, index) => {
    renderBriefFinding(
      canvas,
      finding,
      index + 1,
      brief.detailed.length,
      brief.reviews.get(finding.id),
    );
  });
}

/** The one word the table's `Verified` column carries for a verdict. */
function verifiedWord(review: ReviewedFinding): string {
  switch (review.verdict) {
    case "true":
      return "confirmed";
    case "overstated":
      return "corrected";
    case "unclear":
      return "contested";
    case "false":
      return "withheld";
  }
}

/** The colour a verdict is printed in: green held, amber moved, grey undecided. */
function reviewColor(review: ReviewedFinding): string {
  switch (review.verdict) {
    case "true":
      return STRENGTH_COLOR;
    case "overstated":
      return SEVERITY_COLOR.medium;
    default:
      return COLOR.muted;
  }
}

/** One finding's detail block, identical in content to the dossier's. */
function renderBriefFinding(
  canvas: ReportCanvas,
  finding: Finding,
  index: number,
  total: number,
  review: ReviewedFinding | undefined,
): void {
  // A block of this section is the whole reason the document exists, so it never
  // opens with its header stranded at the foot of a page.
  canvas.ensure(150);
  canvas.moveDown(SPACE.paragraph);
  hairline(canvas, canvas.y);
  canvas.moveDown(SPACE.paragraph);

  const top = canvas.y;
  const chipWidth = severityChip(canvas, canvas.left, top, finding.severity);
  canvas.use(FONT.mono, SIZE.tiny, COLOR.muted);
  canvas.doc.text(toWinAnsi(finding.rule), canvas.left + chipWidth + 8, top + 3, {
    lineBreak: false,
  });
  canvas.use(FONT.regular, SIZE.tiny, COLOR.muted);
  const meta = `${index} of ${total}  -  ${DOMAIN_CODE[finding.domain]} ${DOMAIN_LABEL[finding.domain]}  -  confidence ${finding.confidence}  -  id ${finding.id}`;
  const metaWidth = canvas.widthOf(meta);
  canvas.doc.text(toWinAnsi(meta), canvas.right - metaWidth, top + 3, { lineBreak: false });
  canvas.y = top + 15;

  canvas.use(FONT.bold, SIZE.h2, COLOR.ink);
  canvas.doc.text(toWinAnsi(finding.title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(3);

  monoLine(
    canvas,
    citation(finding.location.file, finding.location.line, finding.location.endLine),
    {
      color: COLOR.body,
    },
  );
  canvas.moveDown(3);

  paragraph(canvas, finding.description);

  if (review !== undefined) {
    callout(canvas, review.note, reviewColor(review), {
      title: `Human review: ${reviewLabel(review)}`,
    });
  }

  if (finding.location.snippet !== undefined && finding.location.snippet !== "") {
    codeBox(canvas, finding.location.snippet, { firstLine: finding.location.line });
  } else {
    paragraph(canvas, "No snippet was extracted for this citation.", {
      color: COLOR.muted,
      size: SIZE.small,
    });
  }

  // The four labels, the evidence list and the tags are one block: they are the
  // answer to the snippet above them, and two of them stranded at the top of the
  // next sheet is the worst page in the document. Room for the whole tail is
  // taken here, in one go; a tail taller than a page is left to flow, because
  // `ensure` refuses a block that can never fit.
  canvas.ensure(detailTailHeight(canvas, finding));

  labelled(
    canvas,
    "Preconditions",
    finding.exploitability ?? "Not stated for this finding; treat the impact below as conditional.",
    {
      labelWidth: LABEL_WIDTH,
      ...(finding.exploitability === undefined ? { color: COLOR.muted } : {}),
    },
  );
  labelled(canvas, "Impact", finding.impact, { labelWidth: LABEL_WIDTH });
  labelled(canvas, "Fix", finding.recommendation, { labelWidth: LABEL_WIDTH });

  if (finding.acceptanceCriteria.length > 0) {
    labelled(
      canvas,
      "Done when",
      finding.acceptanceCriteria.map((line) => `- ${line}`).join("\n"),
      {
        labelWidth: LABEL_WIDTH,
      },
    );
  }

  if (finding.evidence.length > 0) {
    const lines = finding.evidence.map((ref) => {
      const note = ref.note === undefined || ref.note === "" ? "" : `  ${ref.note}`;
      return `${citation(ref.file, ref.line, ref.endLine)}${note}`;
    });
    // The label and the citations under it move as one block, which is not only
    // about typography: `canvas.y` is an absolute page coordinate, so the
    // baseline correction below would *raise* the cursor to the foot of the
    // previous page if the list had broken in the middle of it, and the rest of
    // the new page would be skipped. Keeping the block whole is what makes that
    // impossible.
    canvas.ensure(evidenceHeight(canvas, lines));
    const labelTop = canvas.y;
    canvas.use(FONT.bold, SIZE.body, COLOR.ink);
    canvas.doc.text("Also at", canvas.left, labelTop, { width: LABEL_WIDTH, lineBreak: false });
    canvas.y = labelTop + (SIZE.body - SIZE.code) * 0.8;
    for (const line of lines) {
      monoLine(canvas, line, { indent: LABEL_WIDTH, color: COLOR.body });
    }
    // Only when the list stayed on the label's page. On a page it did break, the
    // cursor is already above `labelTop` in absolute terms and must be left alone.
    if (canvas.y >= labelTop) canvas.y = Math.max(canvas.y, labelTop + SIZE.body * 1.2);
    canvas.moveDown(2);
  }

  const tags = [...finding.cwe, ...finding.owasp];
  if (tags.length > 0) {
    canvas.use(FONT.regular, SIZE.tiny, COLOR.muted);
    canvas.ensure(SIZE.tiny * 2.4);
    canvas.doc.text(toWinAnsi(tags.join("   ")), canvas.left, canvas.y, { width: canvas.width });
    canvas.moveDown(SPACE.paragraph);
  }
}

/** How tall the `Also at` label and its citations are together. */
function evidenceHeight(canvas: ReportCanvas, lines: readonly string[]): number {
  canvas.use(FONT.mono, SIZE.code, COLOR.body);
  const width = canvas.width - LABEL_WIDTH;
  return lines.reduce((sum, line) => sum + canvas.measure(line, width, 1) + 1, SIZE.body * 0.8 + 2);
}

/**
 * How tall the prose tail of a finding is: the four labels, the evidence list
 * and the tags, measured the same way they are drawn.
 *
 * Approximate by a line or two, deliberately, and always upward. Over-reserving
 * pushes a block to the next page one line early, which costs a little
 * whitespace; under-reserving is the orphan this measurement exists to prevent.
 */
function detailTailHeight(canvas: ReportCanvas, finding: Finding): number {
  const valueWidth = canvas.width - LABEL_WIDTH;
  const row = (value: string): number => {
    canvas.use(FONT.regular, SIZE.body, COLOR.body);
    return canvas.measure(value, valueWidth) + 2;
  };

  let height = row(
    finding.exploitability ?? "Not stated for this finding; treat the impact below as conditional.",
  );
  height += row(finding.impact);
  height += row(finding.recommendation);
  if (finding.acceptanceCriteria.length > 0) {
    height += row(finding.acceptanceCriteria.map((line) => `- ${line}`).join("\n"));
  }
  if (finding.evidence.length > 0) {
    height += evidenceHeight(
      canvas,
      finding.evidence.map((ref) => {
        const note = ref.note === undefined || ref.note === "" ? "" : `  ${ref.note}`;
        return `${citation(ref.file, ref.line, ref.endLine)}${note}`;
      }),
    );
  }
  if (finding.cwe.length + finding.owasp.length > 0) height += SIZE.tiny * 2.4 + SPACE.paragraph;
  return height;
}
