/** The slice of Knex's table builder this migration uses. */
interface TableBuilder {
  boolean(name: string): { notNullable(): { defaultTo(value: boolean): void } };
  index(columns: string[]): void;
  dropColumn(name: string): void;
}

/** The slice of the Knex instance this migration uses. */
interface KnexLike {
  schema: { alterTable(table: string, build: (table: TableBuilder) => void): Promise<void> };
}

/** Adds a required flag to an existing table. */
export async function up(knex: KnexLike): Promise<void> {
  await knex.schema.alterTable("audit_log", (table) => {
    table.boolean("reviewed").notNullable().defaultTo(false);
    table.index(["tenant_id"]);
  });
}

/** Removes it again. */
export async function down(knex: KnexLike): Promise<void> {
  await knex.schema.alterTable("audit_log", (table) => {
    table.dropColumn("reviewed");
  });
}
