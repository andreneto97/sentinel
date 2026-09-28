import { Controller, Delete, Get, HttpCode, Post, UseGuards } from "@nestjs/common";
import { db } from "../lib/db.ts";

declare const AuthGuard: unknown;

/** Nest controller: the prefix composes with every method decorator below. */
@Controller("users")
export class UsersController {
  @Get(":userId")
  @UseGuards(AuthGuard)
  async findOne(userId: string): Promise<unknown> {
    return await db.user.findUnique({ where: { id: userId } });
  }

  @Get()
  async list(cursor: string): Promise<unknown[]> {
    return await db.user.findMany({ cursor, take: 20 });
  }

  @Post()
  @HttpCode(201)
  async create(dto: Record<string, unknown>): Promise<unknown> {
    return await db.user.create({ data: dto });
  }

  @Delete(":userId")
  async remove(userId: string): Promise<unknown> {
    return await db.user.delete({ where: { id: userId } });
  }

  /** Not a route: no HTTP decorator, so it must not be counted as one. */
  helper(): string {
    return "not a route";
  }
}

/** A second controller in the same file, to prove the prefixes do not bleed. */
@Controller("health")
@UseGuards(AuthGuard)
export class HealthController {
  @Get()
  check(): { ok: boolean } {
    return { ok: true };
  }
}
