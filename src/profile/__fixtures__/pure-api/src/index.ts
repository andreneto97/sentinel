import Fastify from "fastify";
import { env } from "./config.ts";

const app = Fastify();

app.get("/health", async () => ({ status: "ok" }));

await app.listen({ port: env.PORT });
