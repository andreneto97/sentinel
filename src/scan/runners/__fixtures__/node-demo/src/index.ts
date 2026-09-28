import { mystery } from "not-a-listed-package";
import { handler } from "./a.ts";

export function main(): void {
  handler();
  mystery();
}

main();
