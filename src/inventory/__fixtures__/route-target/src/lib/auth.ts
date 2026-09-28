/** Fixture auth helpers, imported by the handlers the inventory enumerates. */

/** Returns the signed-in principal, or throws. */
export async function requireUser(): Promise<{ id: string; role: string }> {
  return { id: "u_1", role: "member" };
}

/** Returns the signed-in principal, or null. */
export async function getSession(): Promise<{ userId: string } | null> {
  return { userId: "u_1" };
}

/** A guard whose name says nothing; only phase 0 can prove what it is. */
export async function gate(): Promise<boolean> {
  return true;
}
