import { PrismaClient } from "@prisma/client";
import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

const prisma = new PrismaClient();

/** Lists users for the signed-in caller. */
export async function GET(): Promise<unknown> {
  const session = await getServerSession();
  if (session === null) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const users = await prisma.user.findMany();
  return NextResponse.json(users);
}
