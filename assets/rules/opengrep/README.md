# Sentinel's opengrep rule pack

Run by `src/scan/runners/opengrep.ts` with `--config` pointed at this
directory. opengrep loads every `*.yaml` here; this file is ignored.

## Two constraints that are easy to break

**Rule files must be ASCII.** opengrep reads them with the ambient locale's
encoding, and the default in most CI containers is `C`, where a single
non-ASCII byte aborts the entire scan with a `UnicodeDecodeError` and no
findings. Write `--` instead of an em dash. `opengrep.test.ts` fails the build
if a non-ASCII byte appears here.

**Routing metadata has to be in `metadata.tags`.** The SARIF converter keeps
`tags`, `cwe` and `owasp` and silently drops every other custom metadata key,
so `metadata.sentinelDomain` alone never reaches the parser. Each rule
therefore mirrors its routing into tags:

| Tag | Read by | Falls back to |
|---|---|---|
| `sentinel-domain:<domain>` | the finding's domain | the first segment of the dotted rule id |
| `sentinel-severity:<severity>` | the finding's severity | the SARIF level (`error` -> high) |
| `sentinel-confidence:<confidence>` | the finding's confidence | `medium` |
| `sentinel-title:<short title>` | the finding's title | the rule id, humanised |
| `sentinel-impact:<one sentence>` | the finding's impact | the rule's `message` |
| `sentinel-fix:<one sentence>` | the finding's recommendation | a pointer to the description |

`cwe:` and `owasp:` metadata are emitted as tags by the converter and read back
from there, so they need no mirroring.

## Writing a rule

- The id **is** the Sentinel rule id: `<domain>.<area>.<what>`, dotted, kebab
  inside each segment. The runner routes on the first segment, so an id that
  starts with something other than a domain is dropped with a warning.
- `message` is the finding's description, written for a client reading a PDF:
  what the code does, why it matters, and what to do instead. No jargon that a
  senior engineer on the client's team would not use.
- Add both the vulnerable case and a safe counterpart to
  `src/scan/runners/__fixtures__/rule-pack-target/`, annotated with the rule id
  it must trigger (or `SAFE:`). The integration test in `opengrep.test.ts`
  asserts that every annotated rule fires and that nothing else does.
- Quote any pattern containing `: ` -- YAML reads it as a mapping otherwise,
  and opengrep reports the whole file as invalid.

## Provenance: what a pattern match does *not* prove

A pattern can see that a value was interpolated into a statement. It cannot see
whether a caller controls that value, and that gap is the largest source of
false positives an injection rule has: a table name held in a module constant
and a request query parameter are the same shape at the match site, and one of
them is not injectable at all.

So the four rules below are **graded after they fire**, by
`src/scan/_provenance.ts`, which parses the file the match sits in with the
TypeScript compiler API and resolves every interpolated expression back to its
declaration. The rule keeps reporting the *shape*; provenance decides what the
shape means.

| Rule | What is read |
|---|---|
| `appsec.injection.sql-built-from-variables` | the first argument only -- the rest are the driver's bound values |
| `appsec.injection.raw-query-unsafe` | the first argument only |
| `appsec.injection.command-interpolation` | the first argument only |
| `appsec.injection.path-from-request-input` | every argument -- the risk is the composed path |

The verdict decides the severity, and every one of them is stated in the
finding and counted in the step's reason:

| Verdict | Example | Severity | Confidence |
|---|---|---|---|
| closed | a module constant, a `for...of` over `['67']`, a parameter typed `(typeof X)[number]` | `info`, titled `Not injectable:` | high |
| config | a field of a module imported from `@configs/env`, or `process.env.*` | capped at `low` | low |
| unresolved | a parameter of an exported function, a value from another module | capped at `medium` | low |
| reachable | `req.query.sort`, directly or through one call site in the file | the rule's own | high |

Two consequences for whoever writes a rule here:

- **Do not add a rule to that table unless its match really is only a shape.**
  `appsec.injection.nosql-where-operator` matches an operator rather than a
  value, so it is reported exactly as it fires.
- **A fixture is now graded too.** A vulnerable case in
  `rule-pack-target/` whose value is a parameter of an exported function is
  `unresolved`, not `critical` -- which is correct, and worth knowing before
  reading the corpus test's output.
