import { appRouter } from "../../../../src/trpc/router.ts";

declare function fetchRequestHandler(options: unknown): Promise<Response>;

/** The adapter that gives every procedure its HTTP path. */
const handler = (request: Request): Promise<Response> =>
  fetchRequestHandler({
    endpoint: "/api/trpc",
    req: request,
    router: appRouter,
    createContext: () => ({}),
  });

export { handler as GET, handler as POST };
