/** Fixture authentication, so a handler can have a principal to constrain by. */

/** The authenticated caller. */
export interface Session {
  readonly userId: string;
}

/** Resolves the caller's session, or throws when the request carries none. */
export async function requireSession(request: Request): Promise<Session> {
  const userId = request.headers.get("x-user-id");
  if (userId === null) throw new Error("unauthenticated");
  return { userId };
}
