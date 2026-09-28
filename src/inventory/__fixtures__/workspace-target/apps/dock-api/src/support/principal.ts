import type { Req } from "./http.ts";

/** The id the request acts as, which is what makes a handler a management endpoint. */
export function resolveActingMemberId(req: Req): number {
  return req.auth?.user?.type === "standard" ? 1 : 0;
}

/** True when the caller holds an operator-wide permission. */
export function hasOperatorPermissions(auth: Req["auth"]): boolean {
  return (auth?.permissions ?? []).includes("operator");
}
