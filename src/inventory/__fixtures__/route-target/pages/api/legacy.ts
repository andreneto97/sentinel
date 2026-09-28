import { db } from "../../src/lib/db.ts";

interface ApiRequest {
  method?: string;
  query: Record<string, string>;
  body: Record<string, unknown>;
}

interface ApiResponse {
  status(code: number): ApiResponse;
  json(payload: unknown): void;
}

/** Pages-router handler: one file, two methods, no authentication. */
export default async function handler(request: ApiRequest, response: ApiResponse): Promise<void> {
  if (request.method === "POST") {
    await db.post.create({ data: request.body });
    response.status(201).json({ ok: true });
    return;
  }
  const posts = await db.post.findMany({ where: { orgId: request.query.orgId } });
  response.status(200).json(posts);
}
