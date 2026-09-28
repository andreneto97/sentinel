import { EndpointRegistry } from "../../../support/endpoint-registry.ts";
import type { Next, Req, Res } from "../../../support/http.ts";
import { hasOperatorPermissions, resolveActingMemberId } from "../../../support/principal.ts";

/** Registers one of the caller's own delivery endpoints. */
export default async (req: Req, res: Res, next: Next) => {
  try {
    if (!hasOperatorPermissions(req.auth) && req.auth?.user?.type !== "standard") {
      throw new Error("only standard members may register an endpoint");
    }
    const registry = new EndpointRegistry();
    const data = await registry.create(req.body, { memberId: resolveActingMemberId(req) });
    res.status(201).json(data);
  } catch (error) {
    next(error);
  }
};
