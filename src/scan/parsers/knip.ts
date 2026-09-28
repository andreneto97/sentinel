/**
 * Parser for knip's JSON reporter (`knip --reporter json`).
 *
 * The report is an array of per-file issue groups; this module validates it and
 * flattens it into one candidate per unused item. Everything knip reports is a
 * *candidate*: phase 5 verifies it with an agent before it reaches the reader,
 * which is why nothing here claims more than "unreferenced".
 */

import { z } from "zod";
import { type ParseOutcome, parseJsonWith } from "./_parse-outcome.ts";

/**
 * One unused item. knip omits `line`/`col` for whole-file and unresolved
 * entries, so both are optional.
 */
const KnipIssueLocationSchema = z.object({
  name: z.string(),
  line: z.number().int().positive().optional(),
  col: z.number().int().positive().optional(),
});

/**
 * One file's issues. Every category defaults to an empty array so a knip
 * version that drops a category degrades to "nothing found" instead of
 * failing the whole step.
 */
const KnipIssueGroupSchema = z.object({
  file: z.string(),
  files: z.array(KnipIssueLocationSchema).default([]),
  dependencies: z.array(KnipIssueLocationSchema).default([]),
  devDependencies: z.array(KnipIssueLocationSchema).default([]),
  optionalPeerDependencies: z.array(KnipIssueLocationSchema).default([]),
  unlisted: z.array(KnipIssueLocationSchema).default([]),
  unresolved: z.array(KnipIssueLocationSchema).default([]),
  exports: z.array(KnipIssueLocationSchema).default([]),
  types: z.array(KnipIssueLocationSchema).default([]),
});

/** The issue categories Sentinel reads; knip reports several more it ignores. */
type KnipCategory =
  | "files"
  | "exports"
  | "types"
  | "dependencies"
  | "devDependencies"
  | "unlisted"
  | "unresolved";

/** The whole `knip --reporter json` document. */
export const KnipReportSchema = z.object({
  issues: z.array(KnipIssueGroupSchema).default([]),
});
/** A validated knip report. */
export type KnipReport = z.infer<typeof KnipReportSchema>;

/** The kinds of candidate Sentinel takes from knip. */
export type KnipCandidateKind =
  | "unused-file"
  | "unused-export"
  | "unused-type-export"
  | "unused-dependency"
  | "unused-dev-dependency"
  | "unlisted-dependency"
  | "unresolved-import";

/** One unused item, flattened out of the per-file grouping knip reports. */
export interface KnipCandidate {
  readonly kind: KnipCandidateKind;
  /** Repo-relative path of the file the citation points at. */
  readonly file: string;
  /** 1-based line, defaulting to 1 when knip reports no position. */
  readonly line: number;
  /** The export, type, package or specifier the candidate is about. */
  readonly name: string;
}

/**
 * Isolates knip's JSON document inside its stdout.
 *
 * knip loads the target's own toolchain to find entry points, and a framework
 * plugin that prints while doing so lands on stdout ahead of the report: a
 * Next.js repository opens with `\u25c7 injected env (7) from .env.local`,
 * braces and all. Treating stdout as the document fails the whole step over
 * someone else's log line, and stripping "everything before the first brace"
 * would swallow that banner's own `{ debug: true }` and produce garbage.
 *
 * So every line that could *begin* a JSON document is tried as the start of
 * one, in order, and the first suffix that parses wins. A report that is
 * genuinely malformed still has no parsing suffix, and still fails.
 */
export function extractKnipDocument(stdout: string): string {
  const trimmed = stdout.trim();
  if (trimmed.startsWith("{")) return trimmed;

  const lines = trimmed.split("\n");
  for (const [index, line] of lines.entries()) {
    if (!line.trimStart().startsWith("{")) continue;
    const candidate = lines.slice(index).join("\n");
    try {
      JSON.parse(candidate);
      return candidate;
    } catch {
      // Not the start of the document: a banner can contain a brace too.
    }
  }
  return trimmed;
}

/** Validate raw knip stdout; never throws, even on a truncated payload. */
export function parseKnipReport(raw: string): ParseOutcome<KnipReport> {
  return parseJsonWith(extractKnipDocument(raw), KnipReportSchema, "knip");
}

/** Category-to-kind mapping, in the order candidates are emitted. */
const CATEGORIES: readonly (readonly [KnipCategory, KnipCandidateKind])[] = [
  ["files", "unused-file"],
  ["exports", "unused-export"],
  ["types", "unused-type-export"],
  ["dependencies", "unused-dependency"],
  ["devDependencies", "unused-dev-dependency"],
  ["unlisted", "unlisted-dependency"],
  ["unresolved", "unresolved-import"],
];

/** Sorts candidates by file, then line, then name, so a run is diffable. */
function byLocation(a: KnipCandidate, b: KnipCandidate): number {
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  if (a.line !== b.line) return a.line - b.line;
  if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * Flattens a report into candidates. A whole-file entry cites the unused file
 * itself rather than the group it was reported under, so the citation resolves
 * to the file a reader has to delete.
 */
export function knipCandidates(report: KnipReport): KnipCandidate[] {
  const candidates: KnipCandidate[] = [];
  for (const group of report.issues) {
    for (const [category, kind] of CATEGORIES) {
      for (const entry of group[category]) {
        candidates.push({
          kind,
          file: kind === "unused-file" ? entry.name : group.file,
          line: kind === "unused-file" ? 1 : (entry.line ?? 1),
          name: entry.name,
        });
      }
    }
  }
  return candidates.sort(byLocation);
}
