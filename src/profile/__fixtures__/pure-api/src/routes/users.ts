import Fastify from "fastify";
import { Pool } from "pg";
import { env } from "../config.ts";

const pool = new Pool({ connectionString: env.DATABASE_URL });

/** Builds an app exposing the user endpoints. */
export function buildUsersApp(): unknown {
  const app = Fastify();
  app.get("/users", async () => {
    const result = await pool.query("select id, email from users limit 50");
    return result.rows;
  });
  return app;
}
