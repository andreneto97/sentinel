import { Controller, Get, UseGuards } from "@nestjs/common";

/** Read-only user endpoints. */
@Controller("users")
export class UsersController {
  @Get()
  @UseGuards()
  list(): unknown[] {
    return [];
  }
}
