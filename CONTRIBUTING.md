# Contributing

## Setup

```sh
bun install
bun run sentinel setup     # downloads the pinned analyzers into ~/.cache/sentinel
bun run sentinel doctor    # confirms what is present and what is missing
```

Bun 1.2 or newer. Nothing is installed globally and nothing needs `sudo`.

## The gate

```sh
bun run typecheck
bun run lint
bun test src
```

CI runs exactly these three. All must be clean before a pull request lands.

## How this codebase is put together

A few rules carry most of the design. Breaking one usually means the change
belongs somewhere else.

**Ports.** `node:fs` may only be imported by `src/ports/file-system.ts`, and
process spawning only by `src/ports/process-executor.ts`. Everything else takes
a port as an argument. That is what lets a command run end to end in a test
with no disk and no subprocess.

**Contracts are Zod, and they are the source of truth.** Anything written to
disk or parsed from outside the process — analyzer output, agent replies, a
config file — goes through a schema in `src/contracts/`. A naked `JSON.parse`
on external data is a review failure.

**Fixtures are shapes, never copies.** Tests run against small fake
repositories under `__fixtures__/`, written in invented domains. They are
deliberately realistic in *structure* — the same instruction order in a
Dockerfile, the same ORM call pattern — because bugs hide in real shapes. They
must never reproduce a real system's identity: no real organisation, schema,
migration identity, directory census or credential location.
`src/meta/no-real-world-data.test.ts` enforces this and fails the build if
something slips through. If it flags your change, fix the content rather than
widening the allowlist; the allowlist is bounded and every row states its
reason.

**Tests are colocated.** `<name>.ts` next to `<name>.test.ts`. Heavier
end-to-end tests live beside the command they exercise.

**A check that did not run is reported as not run.** This is the rule the whole
tool exists for. If you add a check, add its coverage accounting with it: how
many units it examined, how many it skipped, and why. A domain that reports
health it did not establish is a bug even when every line of it is correct.

## Adding a check

1. **Deterministic rule** — a new step in `src/scan/`, or a rule in
   `src/scan/rules/`. Invoke through the process port, parse with Zod, normalise
   into `Finding`, and degrade with a stated reason when the tool is missing.
2. **AI check** — a prompt builder in `src/audit/prompts/`, registered in that
   directory's `index.ts` with its unit kind and domain. The prompt carries the
   code; the agent never fetches it. State the severity rubric in the prompt so
   the model does not invent one.
3. **New unit kind** — an enumerator in `src/inventory/`, registered in
   `inventory.ts`. Every unit needs a `file:line` that resolves, because the
   citation verifier will check it.

## Commits

Conventional Commits. A commit message explains why the change is right, not
what the diff already shows.
