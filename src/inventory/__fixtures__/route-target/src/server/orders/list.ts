/** A handler declared with a name and default-exported on its own line: the alias form. */

import { db } from "../../lib/db.ts";
import type { Req, Res } from "../../lib/http.ts";

async function listOrders(_request: Req, response: Res): Promise<void> {
  response.json(await db.post.findMany({ take: 20 }));
}

export default listOrders;
