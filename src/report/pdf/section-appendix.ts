/**
 * Section 7 — the appendix.
 *
 * Everything a reader needs to reproduce the run, or to decide not to trust it:
 * the run's own identifiers, the versions of the tools that produced the
 * findings, every phase 1 step with the reason it did or did not run, every
 * audit batch with how many units it answered about, and the verification
 * accounting — how many claims Sentinel threw away before this document existed.
 *
 * A dossier that hides its own failure counts is asking to be believed. This
 * page is where the report earns it instead.
 */

import { heading, labelled, paragraph, sectionTitle } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import type { ReportModel } from "./model.ts";
import { renderTable } from "./table.ts";
import { formatDuration, formatTimestamp, plural } from "./text.ts";
import { COLOR, SEVERITY_COLOR, SIZE } from "./theme.ts";

/** Draws section 7. */
export function renderAppendix(canvas: ReportCanvas, model: ReportModel): void {
  canvas.beginSection("Appendix");
  sectionTitle(canvas, "Appendix", "Run metadata, tool versions, and the status of every step.");

  heading(canvas, "Run");
  labelled(canvas, "Generated", formatTimestamp(model.generatedAt), { labelWidth: 132 });
  labelled(canvas, "Commit", model.commitLabel, { labelWidth: 132 });
  for (const row of model.appendix.run) {
    labelled(canvas, row.label, row.value, { labelWidth: 132 });
  }

  if (model.appendix.agent.length > 0) {
    heading(canvas, "Audit runtime");
    for (const row of model.appendix.agent) {
      labelled(canvas, row.label, row.value, { labelWidth: 132 });
    }
  }

  heading(canvas, "Verification");
  paragraph(
    canvas,
    "Sentinel opens every cited file before a claim reaches this report. These are the claims that did not survive that check.",
    { color: COLOR.muted, size: SIZE.small },
  );
  for (const row of model.appendix.verification) {
    labelled(canvas, row.label, row.value, { labelWidth: 132 });
  }

  heading(canvas, "Tool versions");
  renderTable(canvas, {
    columns: [
      { header: "Tool", width: 110 },
      { header: "Version", width: 90 },
      { header: "Status", width: 62 },
      { header: "Detail", width: 220 },
    ],
    rows: model.appendix.tools.map((tool) => [
      { kind: "mono" as const, text: tool.name },
      { kind: "mono" as const, text: tool.version ?? "—" },
      {
        kind: "text" as const,
        text: tool.status,
        color: tool.status === "ok" ? COLOR.body : SEVERITY_COLOR.medium,
      },
      { kind: "text" as const, text: tool.detail ?? "" },
    ]),
    emptyMessage:
      "No tool inventory was supplied with this run, so the versions behind these findings are not recorded here.",
  });

  heading(canvas, "Phase 1 steps");
  renderTable(canvas, {
    columns: [
      { header: "Step", width: 100 },
      { header: "Status", width: 56 },
      { header: "Findings", width: 48, align: "right" },
      { header: "Reason", width: 278 },
    ],
    rows: model.appendix.steps.map((step) => [
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
      { kind: "text" as const, text: step.reason ?? "" },
    ]),
    emptyMessage: "No scan report was found in this run directory.",
    fontSize: 7.5,
  });

  heading(canvas, "Phase 4 batches");
  renderTable(canvas, {
    columns: [
      { header: "Batch", width: 106 },
      { header: "Kinds", width: 80 },
      { header: "Units", width: 40, align: "right" },
      { header: "Verdicts", width: 46, align: "right" },
      { header: "Findings", width: 44, align: "right" },
      { header: "Status", width: 46 },
      { header: "Time", width: 40, align: "right" },
      { header: "Reason", width: 80 },
    ],
    rows: model.appendix.batches.map((batch) => [
      { kind: "mono" as const, text: batch.batchId },
      { kind: "text" as const, text: batch.kinds.join(", ") },
      { kind: "text" as const, text: String(batch.units) },
      { kind: "text" as const, text: String(batch.verdicts) },
      { kind: "text" as const, text: String(batch.findings) },
      {
        kind: "text" as const,
        text: batch.status,
        color: batch.status === "audited" ? COLOR.body : SEVERITY_COLOR.medium,
      },
      { kind: "text" as const, text: formatDuration(batch.durationMs) },
      { kind: "text" as const, text: batch.reason ?? "" },
    ]),
    emptyMessage: "The audit phase did not run for this run.",
    fontSize: 7,
  });

  const partial = model.appendix.batches.filter((batch) => batch.status !== "audited");
  if (partial.length > 0) {
    paragraph(
      canvas,
      `${partial.length} of ${model.appendix.batches.length} ${plural(model.appendix.batches.length, "batch")} answered about only some of their units. Those units are counted as un-audited in section 4, never as clean.`,
      { color: COLOR.muted, size: SIZE.small },
    );
  }
}
