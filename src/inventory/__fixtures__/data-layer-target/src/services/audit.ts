import knexFactory from "knex";

const knex = knexFactory({ client: "pg" });

/** One tenant's audit rows, projected and bounded. */
export async function tenantAudit(tenantId: string) {
  return await knex("audit_log").where({ tenant_id: tenantId }).select("id", "action").limit(100);
}

/** Deletes every audit row. */
export async function purge() {
  return await knex("audit_log").del();
}
