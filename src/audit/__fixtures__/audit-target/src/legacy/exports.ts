/**
 * The file no batch ever slices.
 *
 * It exists on disk, so a citation pointing at it *verifies* — the line is
 * there and a snippet can be extracted. No prompt ever contains it, so a
 * citation pointing at it must still be dropped, as out-of-slice rather than as
 * unresolvable. That distinction is what the audit phase's slice gate is for,
 * and this file is how the tests prove the two counters are not the same
 * counter.
 */

/** Renders rows into a legacy CSV export. */
export function renderLegacyExport(rows: readonly string[]): string {
  return rows.join("\n");
}

/** Escapes a cell the way the legacy exporter always has. */
export function escapeCell(value: string): string {
  return value.includes(",") ? `"${value.replace(/"/g, '""')}"` : value;
}
