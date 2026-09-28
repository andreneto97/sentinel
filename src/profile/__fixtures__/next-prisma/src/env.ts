import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  NEXTAUTH_SECRET: z.string().min(1),
});

/** Validated environment; a missing variable fails at startup, not at use. */
export const env = EnvSchema.parse(process.env);
