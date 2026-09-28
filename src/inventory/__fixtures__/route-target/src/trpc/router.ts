import { z } from "zod";
import { db } from "../lib/db.ts";

declare const publicProcedure: {
  input(schema: unknown): typeof publicProcedure;
  query(resolver: unknown): unknown;
  mutation(resolver: unknown): unknown;
};
declare const protectedProcedure: typeof publicProcedure;
declare function createTRPCRouter(routes: Record<string, unknown>): unknown;

const UpdatePost = z.object({ id: z.string(), title: z.string() });

/** Nested routers: the procedure path is composed from the keys. */
export const appRouter = createTRPCRouter({
  post: createTRPCRouter({
    byId: publicProcedure
      .input(z.object({ postId: z.string() }))
      .query(async ({ input }: { input: { postId: string } }) => {
        return await db.post.findUnique({ where: { id: input.postId } });
      }),
    update: protectedProcedure.input(UpdatePost).mutation(async ({ input }: { input: unknown }) => {
      return await db.post.update({ data: input });
    }),
  }),
  health: publicProcedure.query(() => ({ ok: true })),
});
