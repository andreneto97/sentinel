/**
 * A handler that returns every invoice in the database, with no projection and no
 * scope — the other half of the route batch.
 */

import { type Db, allInvoices } from "../db/queries.ts";
import type { Request, Response } from "./orders.ts";

/** Returns every invoice, unfiltered. */
export async function GET(_request: Request, db: Db): Promise<Response> {
  const rows = await allInvoices(db);
  return { status: 200, body: rows };
}
