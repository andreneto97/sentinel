/**
 * The PDF dossier: `src/report/pdf`'s public surface.
 *
 * A caller needs three things — a way to turn a run directory into input, the
 * renderer, and the file name it writes under — and nothing else here is part of
 * the contract. The section modules, the canvas and the chart geometry are
 * exported for tests and for a caller that wants to compose its own document;
 * they are not the way to render a report.
 */

export { REPORT_PDF_FILE, renderReportPdf, renderSections, writeReportPdf } from "./render.ts";
export type { ReportFileSystem } from "./render.ts";

export {
  REPORT_BRIEF_PDF_FILE,
  renderBriefDocument,
  renderBriefPdf,
  renderBriefSections,
  writeBriefPdf,
} from "./brief.ts";
export type { BriefFileSystem } from "./brief.ts";

export { buildReportModel, DOMAIN_LABEL, DOMAIN_CODE, UNIT_LABEL } from "./model.ts";
export type {
  CommitInfo,
  DomainAssessment,
  DomainView,
  PriorityGroup,
  ReportInput,
  ReportModel,
  RunMetadata,
  SeverityCounts,
  ToolVersion,
} from "./model.ts";

export { reportInputFromRunArtifacts, runIdTimestamp } from "./from-artifacts.ts";
export type { RenderContext } from "./from-artifacts.ts";

export { adaptScorecard } from "./scorecard.ts";
export type {
  DomainScore,
  OverallScore,
  ScorecardInput,
  ScorecardView,
  ScoreStatus,
} from "./scorecard.ts";

export { createCanvas, ReportCanvas } from "./layout.ts";
export type { CanvasOptions } from "./layout.ts";

export { drawBars, drawDonut } from "./charts.ts";
export { barLayout, donutLayout } from "./geometry.ts";
export { SEVERITY_COLOR, STRENGTH_COLOR } from "./theme.ts";
