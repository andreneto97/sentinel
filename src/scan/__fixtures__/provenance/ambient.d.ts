// These fixtures exist to be *parsed*, not compiled against real packages: the
// provenance analyser reads each one as text and parses it with the TypeScript
// compiler API, with no program and no module resolution. The two shorthand
// declarations below keep `tsc --noEmit` green without adding dependencies
// Sentinel does not use.
//
// `typeorm` and `express` are not declared here. A shorthand ambient module
// makes its imports values rather than types, so `implements MigrationInterface`
// and `req: Request` would not compile; each fixture declares those two shapes
// locally instead.

declare module "@fleet/config";
declare module "@fleet/db/client";
