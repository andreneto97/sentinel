import { db } from "../lib/db.ts";

/**
 * POST /api/invoices/:id/void — the broken handler: it takes an object id from
 * the path and mutates the row without resolving a principal or constraining by
 * one, which is the IDOR an agent auditing it should flag.
 */
export async function voidInvoice(_request: Request, params: { id: string }): Promise<Response> {
  const invoice = await db.invoice.findUnique({ where: { id: params.id } });
  if (invoice === null) return new Response("not found", { status: 404 });
  await db.invoice.update({ where: { id: params.id }, data: { voidedAt: new Date() } });
  return Response.json({ id: params.id, voided: true });
}
