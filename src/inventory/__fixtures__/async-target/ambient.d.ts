// The async fixture exists to be *enumerated*, not compiled against real
// packages: phase 2 reads it as text and queries it with ast-grep. These
// shorthand declarations keep `tsc --noEmit` green without adding dependencies
// Sentinel does not use.
//
// Packages already declared by `src/profile/__fixtures__/fixtures.d.ts` or by
// `src/inventory/__fixtures__/fixtures-ambient.d.ts` are deliberately not
// repeated here.

declare module "inngest";
declare module "stripe";
declare module "node-cron";
declare module "firebase-functions";
declare module "@aws-sdk/client-sqs";
declare module "sqs-consumer";
