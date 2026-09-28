import express from "express";
import { gate, requireUser } from "../lib/auth.ts";
import { db } from "../lib/db.ts";
import type { Req, Res } from "../lib/http.ts";

const app = express();
const users = express.Router();
const admin = express.Router();

users.get("/:userId", requireUser, async (request: Req, response: Res) => {
  const user = await db.user.findUnique({ where: { id: request.params.userId } });
  response.json(user);
});

users.post("/", async (request: Req, response: Res) => {
  const created = await db.user.create({ data: request.body });
  response.status(201).json(created);
});

users.patch("/:userId", async (request: Req, response: Res) => {
  if (!(await gate())) {
    response.status(403).json({ error: "forbidden" });
    return;
  }
  response.json(await db.user.update({ where: { id: request.params.userId } }));
});

admin
  .route("/reports")
  .get(async (_request: Req, response: Res) => {
    response.json(await db.post.findMany({ take: 50 }));
  })
  .post(requireUser, async (request: Req, response: Res) => {
    response.json(await db.post.create({ data: request.body }));
  });

app.use("/api/users", users);
app.use("/api/admin", admin);

/** Registered from a value the enumerator cannot resolve. */
const dynamicPath: string = process.env.LEGACY_PATH ?? "/legacy";
app.get(dynamicPath, (_request: Req, response: Res) => {
  response.json({ ok: true });
});

export { app };
