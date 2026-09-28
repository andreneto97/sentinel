/**
 * A handler that lives in its own file and is default-exported anonymously —
 * the dominant Express layout in a large codebase, and the one where the
 * registration line carries no code at all.
 */

import { getSession } from "../../lib/auth.ts";
import { db } from "../../lib/db.ts";
import type { Req, Res } from "../../lib/http.ts";

export default async (request: Req, response: Res): Promise<void> => {
  const session = await getSession();
  await db.post.delete({ where: { id: request.params.orderId, userId: session?.userId } });
  response.json({ deleted: request.params.orderId });
};
