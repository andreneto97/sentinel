// This fixture exists to be *classified*, not compiled against real packages:
// phase 2 reads it as text and queries it with ast-grep. The shorthand
// declaration keeps `tsc --noEmit` green without adding a dependency Sentinel
// does not use. `express` and `stripe` are already declared by
// `fixtures-ambient.d.ts` and `async-target/ambient.d.ts`.

declare module "got";
