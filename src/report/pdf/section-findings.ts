/**
 * Section 5 — the findings, by domain.
 *
 * Each domain opens with a real table — severity chip, `file:line`, title — so a
 * reader can see the shape of the domain before reading a word of prose, and
 * then every finding gets a detail block: the verified snippet with its own line
 * numbers, what an attacker needs before it matters, what happens if it does,
 * and the fix.
 *
 * The four prose fields are printed under fixed labels and in a fixed order, and
 * a finding that is missing one says so. `exploitability` in particular is the
 * field that separates a real finding from a lint warning, and leaving it blank
 * silently would let the weakest claim in the document look like the strongest.
 */

import type { Finding } from "../../contracts/findings.ts";
import type { VolumeGroup } from "../../scan/_volume.ts";
import { volumeDisclosure } from "../../scan/_volume.ts";
import type { ReviewedFinding } from "../triage.ts";
import { reviewIndex, reviewLabel } from "../triage.ts";
import {
  callout,
  codeBox,
  hairline,
  heading,
  labelled,
  monoLine,
  paragraph,
  sectionTitle,
  severityChip,
} from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import type { DomainView, ReportModel } from "./model.ts";
import { renderTable } from "./table.ts";
import { citation, plural, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE, STRENGTH_COLOR } from "./theme.ts";

/** Reviewed findings by id; empty when nobody reviewed this run. */
type ReviewLookup = ReadonlyMap<string, ReviewedFinding>;

/** Width of the inline labels in a detail block. */
const LABEL_WIDTH = 92;

/** Draws section 5. */
export function renderFindings(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Findings");
  sectionTitle(
    canvas,
    "Findings by domain",
    "Every finding cites a line Sentinel opened on disk; the snippet was extracted from the repository, not written by a model.",
  );

  if (model.findings.length === 0) {
    paragraph(
      canvas,
      "This run produced no findings. Read that against section 4: a domain that was not assessed cannot produce findings, and this page is only as strong as the coverage behind it.",
    );
    return;
  }

  paragraph(
    canvas,
    `${model.findings.length} ${plural(model.findings.length, "finding")}, grouped by domain and ordered worst first. ${model.droppedFindings > 0 ? `${model.droppedFindings} further ${plural(model.droppedFindings, "claim")} was dropped before this section because its citation did not resolve on disk.` : "No claim was dropped for an unresolvable citation."}`,
  );

  // What the reader is owed before the first block: which rules are printed as
  // a count rather than one block each, and where the rest can be read.
  paragraph(canvas, volumeDisclosure(model.volume), { color: COLOR.muted, size: SIZE.small });

  const reviews: ReviewLookup = model.triage === null ? new Map() : reviewIndex(model.triage);
  if (model.triage !== null) {
    const verdicts =
      model.triage.confirmed.length + model.triage.corrected.length + model.triage.contested.length;
    paragraph(
      canvas,
      // "wherever it has a block of its own", not "on the finding": a reviewed
      // finding inside a counted group has no block to print the verdict on, and
      // its verdict is in the human verification section with all the others.
      `${verdicts} of the ${model.findings.length} findings in this section carry a human verdict, printed on the finding wherever it has a block of its own; the other ${model.triage.unreviewed} carry none. A finding without a verdict was not examined by a person.`,
      { color: COLOR.muted, size: SIZE.small },
    );
  }

  for (const domain of model.domains) {
    if (domain.findings.length === 0) continue;
    renderDomainFindings(canvas, domain, reviews);
  }
}

/** One domain: the table, the detail blocks, then the counted groups. */
function renderDomainFindings(
  canvas: ReportCanvas,
  domain: DomainView,
  reviews: ReviewLookup,
): void {
  canvas.ensure(120);
  heading(canvas, `${domain.code} ${domain.label}`);
  paragraph(canvas, domain.statusSentence, { color: COLOR.muted, size: SIZE.small });

  if (domain.volumeGroups.length > 0) {
    const grouped = domain.findings.length - domain.ungrouped.length;
    paragraph(
      canvas,
      `${domain.ungrouped.length} of this domain's ${domain.findings.length} findings are printed on their own below; the other ${grouped} are in ${domain.volumeGroups.length} counted ${plural(domain.volumeGroups.length, "group")} at the end of this domain, and every one of them is still in findings.json.`,
      { color: COLOR.muted, size: SIZE.small },
    );
  }

  renderTable(canvas, {
    columns: [
      { header: "Severity", width: 58 },
      { header: "File:line", width: 174 },
      { header: "Finding", width: 250 },
    ],
    rows: [
      ...domain.ungrouped.map((finding) => [
        { kind: "chip" as const, label: finding.severity, color: SEVERITY_COLOR[finding.severity] },
        { kind: "mono" as const, text: citation(finding.location.file, finding.location.line) },
        { kind: "text" as const, text: finding.title },
      ]),
      ...domain.volumeGroups.map((group) => [
        { kind: "chip" as const, label: group.severity, color: SEVERITY_COLOR[group.severity] },
        {
          kind: "mono" as const,
          text: `${group.fileCount} ${plural(group.fileCount, "file")}`,
        },
        { kind: "text" as const, text: `${group.title} (counted group)` },
      ]),
    ],
  });

  domain.ungrouped.forEach((finding, index) => {
    renderFinding(canvas, finding, index + 1, domain.ungrouped.length, reviews.get(finding.id));
  });

  for (const group of domain.volumeGroups) renderVolumeGroup(canvas, group);
}

/**
 * One collapsed group, rendered as the count it is.
 *
 * It carries what every member's block would have carried once — the rule's
 * impact and its fix are the same sentence in all of them — plus a few examples
 * and the sentence that states how many members are not printed and where they
 * can be read. Nothing here summarises a *finding*: every member is in
 * `findings.json` in full, under the id the example rows cite.
 */
function renderVolumeGroup(canvas: ReportCanvas, group: VolumeGroup): void {
  canvas.ensure(150);
  canvas.moveDown(SPACE.paragraph);
  hairline(canvas, canvas.y);
  canvas.moveDown(SPACE.paragraph);

  const top = canvas.y;
  const chipWidth = severityChip(canvas, canvas.left, top, group.severity);
  canvas.use(FONT.mono, SIZE.tiny, COLOR.muted);
  canvas.doc.text(toWinAnsi(group.rule), canvas.left + chipWidth + 8, top + 3, {
    lineBreak: false,
  });
  canvas.use(FONT.regular, SIZE.tiny, COLOR.muted);
  const meta = `counted group  -  confidence ${group.confidence}`;
  const metaWidth = canvas.widthOf(meta);
  canvas.doc.text(toWinAnsi(meta), canvas.right - metaWidth, top + 3, { lineBreak: false });
  canvas.y = top + 15;

  canvas.use(FONT.bold, SIZE.h2, COLOR.ink);
  canvas.doc.text(toWinAnsi(group.title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(3);

  paragraph(canvas, group.summary);

  if (group.examples.length > 0) {
    paragraph(
      canvas,
      `The ${group.examples.length} shown here are the ones in the files carrying the most of this rule.`,
      { color: COLOR.muted, size: SIZE.small },
    );
    renderTable(canvas, {
      columns: [
        { header: "File:line", width: 232 },
        { header: "Finding", width: 174 },
        { header: "Finding id", width: 76 },
      ],
      rows: group.examples.map((finding) => [
        { kind: "mono" as const, text: citation(finding.location.file, finding.location.line) },
        { kind: "text" as const, text: finding.title },
        { kind: "mono" as const, text: finding.id },
      ]),
    });
  }

  const [first] = group.examples;
  if (first !== undefined) {
    labelled(canvas, "Impact", first.impact, { labelWidth: LABEL_WIDTH });
    labelled(canvas, "Fix", first.recommendation, { labelWidth: LABEL_WIDTH });
  }
  if (group.rawLocation !== null) {
    labelled(canvas, "Raw output", group.rawLocation, { labelWidth: LABEL_WIDTH });
  }
  canvas.moveDown(SPACE.paragraph);
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

/** One finding's detail block. */
function renderFinding(
  canvas: ReportCanvas,
  finding: Finding,
  index: number,
  total: number,
  review?: ReviewedFinding | undefined,
): void {
  // The header of a block must not be the last thing on a page: a severity chip
  // with its finding on the next sheet is worse than a page break.
  canvas.ensure(96);
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
  const meta = `${index} of ${total}  -  confidence ${finding.confidence}  -  ${finding.source.kind}:${finding.source.name}`;
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

  // The reviewer's voice, before the evidence and in its own frame, because it
  // is the one paragraph in this block that no model wrote.
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

  // The four prose labels, the evidence list and the tags are one block: they
  // are the answer to the snippet above them, and two of them stranded alone at
  // the top of the next sheet is the worst page in the document. Room for the
  // whole tail is taken here, in one go. A tail taller than a page is left to
  // flow — `ensure` refuses a block that can never fit, which is the right
  // answer for a finding with twenty pieces of evidence.
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
    // The label sits on the same baseline as the first citation, exactly like
    // the `labelled` rows above it: room for both is taken first, then the
    // label is stamped and the cursor is put back so the mono lines start on
    // that same line. Advancing between the two would leave the label floating
    // a line above its own list.
    canvas.ensure(SIZE.body + SIZE.code * 1.6);
    const top = canvas.y;
    canvas.use(FONT.bold, SIZE.body, COLOR.ink);
    canvas.doc.text("Also at", canvas.left, top, { width: LABEL_WIDTH, lineBreak: false });
    // The mono line is smaller than the label, so it is nudged down by the
    // difference in cap height to sit optically on the label's baseline.
    canvas.y = top + (SIZE.body - SIZE.code) * 0.8;
    for (const ref of finding.evidence) {
      const note = ref.note === undefined || ref.note === "" ? "" : `  ${ref.note}`;
      monoLine(canvas, `${citation(ref.file, ref.line, ref.endLine)}${note}`, {
        indent: LABEL_WIDTH,
        color: COLOR.body,
      });
    }
    canvas.y = Math.max(canvas.y, top + SIZE.body * 1.2);
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

/**
 * How tall the prose tail of a finding is: the four labels, the evidence list
 * and the tags, measured the same way they are drawn.
 *
 * Approximate by a line or two, deliberately. Over-reserving pushes a block to
 * the next page one line early, which costs nothing; under-reserving is the
 * orphan this measurement exists to prevent, so every rounding here is upward.
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
    canvas.use(FONT.mono, SIZE.code, COLOR.body);
    const monoWidth = canvas.width - LABEL_WIDTH;
    height += finding.evidence.reduce(
      (sum, ref) => {
        const note = ref.note === undefined || ref.note === "" ? "" : `  ${ref.note}`;
        return (
          sum +
          canvas.measure(`${citation(ref.file, ref.line, ref.endLine)}${note}`, monoWidth, 1) +
          1
        );
      },
      SIZE.body * 0.8 + 2,
    );
  }

  const tags = [...finding.cwe, ...finding.owasp];
  if (tags.length > 0) height += SIZE.tiny * 2.4 + SPACE.paragraph;
  return height;
}
