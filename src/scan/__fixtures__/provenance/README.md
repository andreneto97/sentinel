# Provenance fixtures

Seven files, each one a shape the provenance analyser has to resolve. They exist
to be **parsed**, not run: the analyser (`src/scan/_provenance.ts`) reads each
one as text and parses it with the TypeScript compiler API, with no program and
no module resolution.

The domain -- a bike-share network of stations, docks, bikes, rides and riders --
is invented for these fixtures, and so are the table names, the migration class
names and their timestamps. Nothing here describes a service that exists. Each
file is built around the shape it pins; the names are there only to make that
shape readable.

The migration timestamps are hand-typed and zero-padded -- `20240601000000` and
the two days after it, the same form every other migration in this tree uses --
so that nobody has to wonder whether a `Date.now()` value came off a real
history. The analyser never reads them; only the `implements` clause and the
`query(...)` call.

| File | What it pins |
|---|---|
| `add-bike-model-code.migration.ts` | a `for...of` over a local array literal, two sinks in one loop, one signature |
| `record-ride-change.migration.ts` | a module `const` bound to a string literal, interpolated from both `up()` and `down()` |
| `notify-dock-change.migration.ts` | a local helper returning a template that interpolates a configuration field |
| `normalize-labels.handler.ts` | a parameter typed `(typeof X)[number]` over an `as const` array, and a module-level template constant |
| `station-profile.service.ts` | `.map(...).join(...)` over an `as const` tuple, with a nested `.map` result read by index |
| `stale-queue-reaper.worker.ts` | two fields of an imported configuration module in one statement |
| `ride-search.ts` | request input reaching a statement through one in-file call site, beside a closed sibling |

Two things every file does, neither of them visible to the analyser:

1. The plpgsql bodies of the migrations are trimmed to the lines that
   *interpolate*. Every line that interpolates is kept; the SQL between them is
   not what is under test.
2. `MigrationInterface` / `QueryRunner` (typeorm) and `Request` / `Response` /
   `NextFunction` (express) are declared locally instead of imported, so the
   fixtures compile without a dependency Sentinel does not use. A shorthand
   ambient module declaration makes its imports values rather than types, so an
   import would not compile here; the analyser reads the `implements` clause and
   the `req: Request` annotation, not the import.

`@fleet/config` and `@fleet/db/client` are declared in `ambient.d.ts` for the
same reason. The analyser only needs the specifier to decide that a field of that
module is deploy-time configuration rather than caller input.

Formatting is whatever `biome` produces, which leaves every template literal
untouched.
