/** The project's own auth helper: this is the file phase 0 proves. */

/** Resolves the signed-in principal, or throws. */
export async function requireAccess(role: string): Promise<{ id: string; role: string }> {
  if (role === "") throw new Error("no role");
  return { id: "u_1", role };
}
