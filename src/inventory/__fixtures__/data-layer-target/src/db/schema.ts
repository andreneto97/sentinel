import { index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

/** Staff and customers of an organisation. */
export const users = pgTable("users", {
  id: uuid("id").primaryKey(),
  organizationId: uuid("organization_id").notNull(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
});

/** A reservation, owned by the user who created it. */
export const bookings = pgTable(
  "bookings",
  {
    id: uuid("id").primaryKey(),
    organizationId: uuid("organization_id").notNull(),
    creatorId: uuid("creator_id")
      .notNull()
      .references(() => users.id),
    status: text("status").notNull().default("open"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table: Record<string, unknown>) => ({
    byOrganisation: index("bookings_organization_id_idx").on(table.organizationId),
  }),
);
