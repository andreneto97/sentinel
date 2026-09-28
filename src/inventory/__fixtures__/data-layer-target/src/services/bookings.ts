import { and, eq } from "drizzle-orm";
import { db } from "../db/client.ts";
import { bookings, users } from "../db/schema.ts";

/** Reads one organisation's bookings, bounded and constrained by the tenant. */
export async function listForOrganisation(organizationId: string) {
  return await db
    .select()
    .from(bookings)
    .where(eq(bookings.organizationId, organizationId))
    .limit(50);
}

/** Reads every booking in the database, with no predicate and no bound. */
export async function listEverything() {
  return await db.select().from(bookings);
}

/** Loads the creator of every booking, one query per row. */
export async function withCreators(rows: Array<{ creatorId: string }>) {
  const creators: unknown[] = [];
  for (const row of rows) {
    const creator = await db
      .select({ name: users.name })
      .from(users)
      .where(eq(users.id, row.creatorId));
    creators.push(creator);
  }
  return creators;
}

/** Two independent reads, one after the other. */
export async function dashboard(organizationId: string) {
  const open = await db.select().from(bookings).where(eq(bookings.status, "open"));
  const staff = await db.select().from(users).where(eq(users.organizationId, organizationId));
  return { open, staff };
}

/** Cancels a booking the actor owns, inside a transaction. */
export async function cancel(bookingId: string, actorId: string) {
  return await db.transaction(async (tx: typeof db) => {
    await tx
      .update(bookings)
      .set({ status: "cancelled" })
      .where(and(eq(bookings.id, bookingId), eq(bookings.creatorId, actorId)));
    return bookingId;
  });
}
