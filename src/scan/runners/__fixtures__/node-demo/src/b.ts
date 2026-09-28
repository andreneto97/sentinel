import { handler } from "./a.ts";

export function helper(): void {
  if (Math.random() > 2) handler();
}

export function neverUsed(): void {}

export type UnusedShape = { id: string };
