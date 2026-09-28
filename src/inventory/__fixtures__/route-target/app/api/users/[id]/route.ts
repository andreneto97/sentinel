import { NextResponse } from "next/server";
import { z } from "zod";
import { requireUser } from "../../../../src/lib/auth.ts";
import { db } from "../../../../src/lib/db.ts";

const UpdateUser = z.object({ email: z.string(), role: z.string() });

/** Reads one user by id. */
export async function GET(
  request: Request,
  { params }: { params: { id: string } },
): Promise<Response> {
  const session = await requireUser();
  const limit = Number(new URL(request.url).searchParams.get("limit") ?? "20");
  const user = await db.user.findUnique({ where: { id: params.id }, take: limit });
  return NextResponse.json({ user, viewer: session.id });
}

/** Updates one user by id. */
export async function PATCH(
  request: Request,
  { params }: { params: { id: string } },
): Promise<Response> {
  const body = UpdateUser.parse(await request.json());
  const user = await db.user.update({ where: { id: params.id }, data: body });
  return NextResponse.json(user);
}

/** Deletes one user by id; no authentication anywhere in the body. */
export async function DELETE(
  _request: Request,
  { params }: { params: { id: string } },
): Promise<Response> {
  await db.user.delete({ where: { id: params.id } });
  return NextResponse.json({ ok: true });
}
