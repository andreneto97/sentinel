/** Fixture data layer, so handlers have something to read and write. */

interface Table {
  findUnique(args: unknown): Promise<unknown>;
  findMany(args?: unknown): Promise<unknown[]>;
  create(args: unknown): Promise<unknown>;
  update(args: unknown): Promise<unknown>;
  delete(args: unknown): Promise<unknown>;
}

/** The fixture client. */
export const db: { user: Table; post: Table } = {
  user: {} as Table,
  post: {} as Table,
};
