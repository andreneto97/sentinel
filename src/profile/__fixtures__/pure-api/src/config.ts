import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  PORT: z.coerce.number().default(3000),
});

/** Validated environment for the API process. */
export const env = EnvSchema.parse(process.env);
