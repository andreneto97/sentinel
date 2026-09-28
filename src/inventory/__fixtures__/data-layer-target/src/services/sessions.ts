import { Pool } from "pg";

const pool = new Pool();

/** Loads a session row with a bound parameter. */
export async function sessionFor(userId: string) {
  return await pool.query("SELECT * FROM sessions WHERE user_id = $1 LIMIT 1", [userId]);
}

/** Deletes expired sessions with an interpolated statement. */
export async function purgeExpired(before: string) {
  return await pool.query(`DELETE FROM sessions WHERE expires_at < '${before}'`);
}
