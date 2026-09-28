/** Fixture data layer, so the audited handlers have something to read and write. */

interface Table {
  findFirst(args: unknown): Promise<unknown>;
  findUnique(args: unknown): Promise<unknown>;
  findMany(args?: unknown): Promise<unknown[]>;
  update(args: unknown): Promise<unknown>;
}

/** The fixture client. */
export const db: { order: Table; invoice: Table } = {
  order: {} as Table,
  invoice: {} as Table,
};
