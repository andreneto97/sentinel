import { EndpointRegistry } from "../../../support/endpoint-registry.ts";
import type { Next, Req, Res } from "../../../support/http.ts";
import { resolveActingMemberId } from "../../../support/principal.ts";

/** Lists the caller's own delivery endpoints. */
export default async (req: Req, res: Res, next: Next) => {
  try {
    const registry = new EndpointRegistry();
    res.json(await registry.listFor(resolveActingMemberId(req)));
  } catch (error) {
    next(error);
  }
};
