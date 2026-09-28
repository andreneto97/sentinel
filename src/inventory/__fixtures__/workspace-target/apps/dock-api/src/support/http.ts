/**
 * The Express shapes the fixture's handlers are written against.
 *
 * Declared locally, the way `route-target/src/lib/http.ts` does, because the
 * shorthand ambient `express` module has no types and the classifier reads
 * parameter *names* rather than annotations anyway.
 */
export interface Req {
  readonly auth?: {
    readonly user?: { readonly type?: string };
    readonly permissions?: readonly string[];
  };
  readonly params: Record<string, string>;
  readonly body: unknown;
  readonly headers: Record<string, string | undefined>;
  readonly rawBody: string;
}

/** Express's response, reduced to what a handler here calls. */
export interface Res {
  status(code: number): Res;
  json(body: unknown): void;
}

/** Express's error forwarder. */
export type Next = (error?: unknown) => void;
