import { getServerSession } from "next-auth";

/** Throws unless the request carries a valid session. */
export async function requireSession(): Promise<unknown> {
  const session = await getServerSession();
  if (session === null) {
    throw new Error("unauthorized");
  }
  return session;
}
