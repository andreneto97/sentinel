"use server";

import { z } from "zod";
import { requireUser } from "../../src/lib/auth.ts";
import { db } from "../../src/lib/db.ts";

const CreatePost = z.object({ title: z.string() });

/** Server action: authenticated, validated, writes. */
export async function createPost(form: FormData): Promise<void> {
  const user = await requireUser();
  const input = CreatePost.parse({ title: form.get("title") });
  await db.post.create({ data: { ...input, authorId: user.id } });
}

/** Server action with no authentication and no validation at all. */
export async function deletePost(postId: string): Promise<void> {
  await db.post.delete({ where: { id: postId } });
}
