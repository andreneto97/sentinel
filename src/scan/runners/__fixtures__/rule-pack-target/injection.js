// Intentionally vulnerable corpus for the Sentinel opengrep rule pack.

// biome-ignore lint/nursery/noRestrictedImports: an intentionally vulnerable fixture, never loaded by Sentinel
import { exec } from "node:child_process";
import path from "node:path";

/** appsec.injection.sql-built-from-variables */
export async function findUser(db, email) {
  return db.query(`SELECT * FROM users WHERE email = '${email}'`);
}

/** appsec.injection.sql-built-from-variables */
export async function countOrders(db, status) {
  // biome-ignore lint/style/useTemplate: concatenation is what this fixture tests
  return db.execute("SELECT count(*) FROM orders WHERE status = '" + status + "'");
}

/** SAFE: the value travels as a bound parameter. */
export async function findUserSafely(db, email) {
  return db.query("SELECT * FROM users WHERE email = $1", [email]);
}

/** appsec.injection.raw-query-unsafe */
export async function searchPosts(prisma, term) {
  return prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE title LIKE '%${term}%'`);
}

/** appsec.injection.raw-query-unsafe */
export async function rankUsers(knex, column) {
  return knex.raw(`SELECT * FROM users ORDER BY ${column}`);
}

/** appsec.injection.command-interpolation */
export function convertFile(name, done) {
  exec(`convert ${name} /tmp/out.png`, done);
}

/** appsec.injection.nosql-where-operator */
export async function findExpensive(collection, threshold) {
  return collection.find({ $where: `this.total > ${threshold}` });
}

/** appsec.injection.path-from-request-input */
export function downloadHandler(req, res) {
  return res.sendFile(path.join("/srv/uploads", req.params.filename));
}

/** SAFE: the name is chosen from a fixed table, not taken from the request. */
const ALLOWED = { invoice: "invoice.pdf", receipt: "receipt.pdf" };
export function downloadAllowedHandler(req, res) {
  const name = ALLOWED[req.params.kind];
  return name === undefined ? res.status(404).end() : res.sendFile(path.join("/srv", name));
}

/** appsec.injection.sql-built-from-variables */
export function sortedPostsHandler(req, res, db) {
  // The value is read from the request on the line above the sink, so
  // provenance resolves it and the finding keeps its full severity.
  return res.json(db.query(`SELECT * FROM posts ORDER BY ${req.query.sort}`));
}
