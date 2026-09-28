import Router from "@koa/router";
import Koa from "koa";
import { getSession } from "../lib/auth.ts";
import { db } from "../lib/db.ts";
import type { KoaCtx } from "../lib/http.ts";

const app = new Koa();
const router = new Router({ prefix: "/api/koa" });

router.get("/teams/:teamId", async (context: KoaCtx) => {
  const session = await getSession();
  if (session === null) {
    context.status = 401;
    return;
  }
  context.body = await db.post.findMany({ where: { teamId: context.params.teamId } });
});

router.del("/teams/:teamId", async (context: KoaCtx) => {
  await db.post.delete({ where: { id: context.params.teamId } });
  context.status = 204;
});

app.use(router.routes());

export { app };
