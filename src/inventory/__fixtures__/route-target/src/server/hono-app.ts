import { Hono } from "hono";
import { requireUser } from "../lib/auth.ts";
import { db } from "../lib/db.ts";
import type { Ctx } from "../lib/http.ts";

const api = new Hono().basePath("/api/v2");

api
  .get("/posts", async (context: Ctx) => {
    return context.json(await db.post.findMany({ take: Number(context.req.query("limit")) }));
  })
  .post("/posts", requireUser, async (context: Ctx) => {
    const body = await context.req.json();
    return context.json(await db.post.create({ data: body }));
  });

api.on("DELETE", "/posts/:postId", async (context: Ctx) => {
  await db.post.delete({ where: { id: context.req.param("postId") } });
  return context.json({ ok: true });
});

export { api };
