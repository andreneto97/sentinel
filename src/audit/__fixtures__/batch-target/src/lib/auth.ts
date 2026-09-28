/**
 * The fixture repository's authentication helper.
 *
 * Deliberately shaped like the real thing the batching phase has to quote: it
 * resolves a session and says nothing about roles, which is exactly the case an
 * audit has to notice when a privileged handler treats it as an authorization
 * check.
 */

/** A resolved caller. */
export interface Session {
  readonly userId: string;
  readonly orgId: string;
  readonly role: "viewer" | "editor" | "admin";
}

/** Reads the session cookie and returns the caller, or null when there is none. */
export function getSession(headers: Record<string, string>): Session | null {
  const cookie = headers.cookie;
  if (cookie === undefined || !cookie.startsWith("sid=")) return null;
  const [userId, orgId, role] = cookie.slice(4).split(":");
  if (userId === undefined || orgId === undefined) return null;
  return {
    userId,
    orgId,
    role: role === "admin" ? "admin" : role === "editor" ? "editor" : "viewer",
  };
}

/** Rejects a caller that is not signed in. No role is asserted here. */
export function requireSession(headers: Record<string, string>): Session {
  const session = getSession(headers);
  if (session === null) throw new Error("unauthenticated");
  return session;
}
