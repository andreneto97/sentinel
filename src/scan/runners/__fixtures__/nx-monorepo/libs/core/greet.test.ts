// Part of the fixture repository, not of Sentinel's own suite: it exists so the
// generated knip configuration has a real test file to treat as an entry point.
import { greet } from "./greet.ts";

export const greeting = greet("fixture");
