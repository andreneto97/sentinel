/**
 * Two route handlers: one that scopes its read to the caller's organisation, and
 * one that deletes by an id taken straight from the path.
 *
 * The second is the finding an audit of this batch has to produce, and the first
 * is the assurance it has to publish — which is why both are here.
 */

import { type Db, listOrders } from "../db/queries.ts";
import { requireSession } from "../lib/auth.ts";
import { narrow } from "../lib/validate.ts";

/** The request shape the fixture's fake framework hands a handler. */
export interface Request {
  readonly headers: Record<string, string>;
  readonly params: Record<string, string>;
  readonly body: Record<string, unknown>;
}

/** The response shape the fixture's fake framework expects back. */
export interface Response {
  readonly status: number;
  readonly body: unknown;
}

/** Lists the caller's own orders. Scoped by the session's organisation. */
export async function GET(request: Request, db: Db): Promise<Response> {
  const session = requireSession(request.headers);
  const rows = await listOrders(db, session.orgId);
  return {
    status: 200,
    body: rows.map((row) => ({ id: row.id, total: row.total })),
  };
}

/** Updates an order. Validates its input and writes an explicit field list. */
export async function PATCH(request: Request, db: Db): Promise<Response> {
  const session = requireSession(request.headers);
  const id = request.params.id;
  if (id === undefined) return { status: 400, body: { error: "id is required" } };
  const fields = narrow(request.body, [{ field: "total", kind: "number" }]);
  await db.query("update orders set total = $1 where id = $2 and org_id = $3", [
    fields.total,
    id,
    session.orgId,
  ]);
  return { status: 200, body: { ok: true } };
}

/**
 * Deletes an order by the id in the path.
 *
 * The session is resolved and then ignored: any signed-in caller can delete any
 * order in any organisation.
 */
export async function DELETE(request: Request, db: Db): Promise<Response> {
  requireSession(request.headers);
  const id = request.params.id;
  await db.query("delete from orders where id = $1", [id]);
  return { status: 204, body: null };
}
