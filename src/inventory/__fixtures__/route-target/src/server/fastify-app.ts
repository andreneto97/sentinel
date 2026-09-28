import Fastify from "fastify";
import { db } from "../lib/db.ts";
import type { Req, Res } from "../lib/http.ts";

const server = Fastify({ logger: true });

server.route({
  method: "PUT",
  url: "/things/:thingId",
  preHandler: [server.authenticate],
  schema: { body: { type: "object" } },
  handler: async (request: Req, reply: Res) => {
    const updated = await db.post.update({ where: { id: request.params.thingId } });
    reply.send(updated);
  },
});

server.get("/things", async (request: Req) => {
  return await db.post.findMany({ cursor: request.query.cursor, take: 25 });
});

/** A plugin mounted under a prefix; its own routes inherit it. */
async function billingRoutes(instance: typeof server): Promise<void> {
  instance.post("/charge", async (request: Req, reply: Res) => {
    reply.send(await db.post.create({ data: request.body }));
  });
}

server.register(billingRoutes, { prefix: "/api/billing" });

export { server };
