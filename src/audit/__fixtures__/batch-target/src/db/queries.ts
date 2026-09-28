/**
 * The fixture repository's data access, with one scoped query and one that is
 * not — which is what a data-access batch is for.
 */

/** A row as the fake driver returns it. */
export interface Row {
  readonly id: string;
  readonly org_id: string;
  readonly total: number;
}

/** The narrow slice of a query builder these functions use. */
export interface Db {
  query(sql: string, params: readonly unknown[]): Promise<Row[]>;
}

/** Scoped by the caller's organisation: the assurance case. */
export async function listOrders(db: Db, orgId: string): Promise<Row[]> {
  return db.query("select id, org_id, total from orders where org_id = $1 limit 50", [orgId]);
}

/** Unscoped and unbounded: the finding case. */
export async function allInvoices(db: Db): Promise<Row[]> {
  return db.query("select * from invoices", []);
}

/** One query per row of another: the N+1 case. */
export async function ordersPerCustomer(db: Db, customerIds: readonly string[]): Promise<Row[]> {
  const found: Row[] = [];
  for (const customerId of customerIds) {
    const rows = await db.query("select * from orders where customer_id = $1", [customerId]);
    found.push(...rows);
  }
  return found;
}
