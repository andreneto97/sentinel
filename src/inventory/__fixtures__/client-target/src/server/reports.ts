// biome-ignore lint/nursery/noRestrictedImports: the fixture is enumerated as a command sink, never executed.
import { execSync } from "node:child_process";
import { Client } from "pg";

const client = new Client();

/** Server-side authorization: a role check that is not a client gate. */
export function assertAdmin(user: { role: string }): void {
  if (user.role !== "admin") throw new Error("forbidden");
}

/** Interpolates the caller's filter straight into SQL. */
export async function search(term: string): Promise<unknown> {
  return await client.query(`SELECT * FROM reports WHERE title ILIKE '%${term}%'`);
}

/** A parameterised query, which is not a sink worth tracing. */
export async function byId(id: string): Promise<unknown> {
  return await client.query("SELECT * FROM reports WHERE id = $1", [id]);
}

/** Shells out with a caller-supplied name. */
export function archive(name: string): string {
  return execSync(`tar -czf /tmp/${name}.tgz /var/reports`).toString();
}
