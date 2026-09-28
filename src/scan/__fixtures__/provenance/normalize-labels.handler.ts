// Pins two closed shapes in one file: a parameter typed `(typeof X)[number]` over
// an `as const` array, which cannot escape that array, and a module-level
// template constant that interpolates nothing of its own.

import DataSource from "@fleet/db/client";
import z from "zod";

const LABEL_TABLES = ["stations", "docks", "bikes", "rides", "riders"] as const;
type LabelTable = (typeof LABEL_TABLES)[number];

const DEFAULT_BATCH_SIZE = 500;

const argsSchema = z.object({
  batchSize: z.number().int().positive().catch(DEFAULT_BATCH_SIZE),
  tables: z.array(z.enum(LABEL_TABLES)).nonempty().optional(),
});

// Rows that need normalizing: any uppercase/whitespace char, an empty label, a
// whitespace-only label, or a duplicate.
const MESSY_LABELS = `
  labels IS NOT NULL
  AND cardinality(labels) > 0
  AND (
    array_to_string(labels, chr(1)) ~ '[A-Z ]'
    OR '' = ANY(labels)
  )
`;

export class NormalizeLabelsHandler {
  async handle(raw: unknown): Promise<void> {
    const args = argsSchema.parse(raw);
    const tables: readonly LabelTable[] = args.tables ?? LABEL_TABLES;
    for (const table of tables) {
      const ids = await this.collectMessyIds(table, args.batchSize);
      await this.runBatch(table, ids, "job-1");
    }
  }

  private async collectMessyIds(table: LabelTable, limit: number): Promise<number[]> {
    const rows = (await DataSource.query(
      `
        SELECT id FROM "${table}"
         WHERE ${MESSY_LABELS}
         LIMIT $1
      `,
      [limit],
    )) as Array<{ id: number }>;
    return rows.map((row) => row.id);
  }

  private async runBatch(
    table: LabelTable,
    ids: readonly number[],
    jobId: string,
  ): Promise<number> {
    const result = (await DataSource.query(
      `
        UPDATE "${table}"
           SET last_job_id = $2
         WHERE id IN (
           SELECT id FROM "${table}"
            WHERE id = ANY($1)
            FOR UPDATE SKIP LOCKED
         )
      `,
      [ids, jobId],
    )) as [unknown[], number];
    return result[1] ?? 0;
  }
}
