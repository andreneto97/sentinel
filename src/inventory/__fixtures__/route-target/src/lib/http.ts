/** Minimal request/response shapes, so fixture handlers are typed without real framework types. */

/** An inbound request, as every fixture handler reads it. */
export interface Req {
  params: Record<string, string>;
  query: Record<string, string>;
  body: Record<string, unknown>;
}

/** An outbound response, as every fixture handler writes it. */
export interface Res {
  status(code: number): Res;
  json(payload: unknown): void;
  send(payload: unknown): void;
}

/** A Hono-style context. */
export interface Ctx {
  req: {
    json(): Promise<Record<string, unknown>>;
    query(key: string): string;
    param(key: string): string;
  };
  json(payload: unknown): Response;
}

/** A Koa-style context. */
export interface KoaCtx {
  params: Record<string, string>;
  status: number;
  body: unknown;
}
