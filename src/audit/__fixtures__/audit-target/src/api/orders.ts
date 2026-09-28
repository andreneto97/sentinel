import { requireSession } from "../lib/auth.ts";
import { db } from "../lib/db.ts";

/**
 * POST /api/orders/:id/cancel — the clean handler: it resolves the principal
 * and constrains every query by it, so an agent auditing it should return a
 * `clean` verdict with the ownership check asserted.
 */
export async function cancelOrder(request: Request, params: { id: string }): Promise<Response> {
  const session = await requireSession(request);
  const order = await db.order.findFirst({
    where: { id: params.id, ownerId: session.userId },
  });
  if (order === null) return new Response("not found", { status: 404 });
  await db.order.update({
    where: { id: params.id, ownerId: session.userId },
    data: { status: "cancelled" },
  });
  return Response.json({ id: params.id, status: "cancelled" });
}
