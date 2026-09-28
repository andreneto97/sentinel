import { EndpointRegistry } from "../../../support/endpoint-registry.ts";
import type { Next, Req, Res } from "../../../support/http.ts";
import { resolveActingMemberId } from "../../../support/principal.ts";

/** Rotates the signing secret on one of the caller's own endpoints. */
export default async (req: Req, res: Res, next: Next) => {
  try {
    const registry = new EndpointRegistry();
    const data = await registry.rotateSecret(req.params.id ?? "", resolveActingMemberId(req));
    res.json(data);
  } catch (error) {
    next(error);
  }
};
