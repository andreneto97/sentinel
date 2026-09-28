# Sentinel

[![CI](https://github.com/andreneto97/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/andreneto97/sentinel/actions/workflows/ci.yml)

A backend dossier for Node.js and TypeScript repositories: dependencies,
application security, the data layer, the delivery pipeline, serverless and
async workloads, the API surface, reliability and dead code — in one PDF where
every claim points at a line of code.

Clone it, point it at a repository, read the report.

```sh
git clone https://github.com/andreneto97/sentinel && cd sentinel
bun install
bun run sentinel setup              # downloads the pinned analyzers, hash-verified
bun run sentinel analyze ../my-api
```

Or, from Claude Code inside this repo: `/sentinel ../my-api`.

---

## Why this exists

Static analyzers find what a pattern can match. A language model can read
intent, but it is happy to tell you about code it never opened. Most tools that
combine the two inherit the worst of both: a document full of confident prose
with nothing underneath it, and no way to tell the checked parts from the
guessed ones.

Sentinel is built around the opposite bet — that a report is worth what its
weakest claim is worth, so every claim has to be traceable, and the parts
nobody checked have to say so.

Four properties follow from that, and they are the whole design:

**Coverage is enumerated, not sampled.** Before anything is audited, Sentinel
lists the units: every route handler, data-access call site, migration,
scheduled job, queue consumer, webhook receiver, workflow job, container and
unsafe-input sink. The audit then answers for that list, and the report says
`196/200 route handlers audited` — with the other four named, and the reason
each one has no verdict.

**The model never reads files.** Sentinel locates the code, slices it, and puts
it *in the prompt*. The agent gets no filesystem tools. A citation that falls
outside the slice it was handed is rejected, because a claim about code the
model was not shown is a claim about something it already believed.

**Every citation is verified against disk.** Findings come back as
`file:line`; Sentinel reopens each one, confirms the line exists, and extracts
the snippet itself. Anything that does not resolve is dropped and counted. The
code in the report was read by the tool, not written by the model.

**It reports what is correct, too.** Assurances — "every mutation handler
asserts ownership before writing, 23 of 23, here is the evidence" — sit beside
the findings. A document that only lists defects is a complaint; an audit says
what it checked and found sound.

And one habit that falls out of all four: **bounding is not hiding.** A run
narrowed to one workspace, stopped by a budget, or missing an analyzer says so
in numbers — in the terminal, in the artifacts, on the PDF cover and next to
the scorecard. A domain nobody checked is reported as *not assessed*, never as
clean, because those are not the same thing and the difference is the only
thing standing between an audit and a reassuring document.

---

## What it checks

Eight domains. Every finding belongs to exactly one, and the report is
organised by them.

### D1 · Dependencies and supply chain
Known CVEs with the path that pulls each one in, direct versus transitive,
production versus dev. Outdated packages split by how far behind. Unused and
undeclared dependencies. Licence inventory from a generated SBOM, flagging
copyleft and unknown. Lockfile hygiene: present, matching, single package
manager, no override masking a patched version. Install-time risk from
`postinstall` scripts.

### D2 · Application security
The access-control questions a linter cannot ask, re-expressed for whatever
stack was detected:

- **Tenant and owner isolation** — reads and lists that do not constrain by the
  authenticated principal; on Postgres, tables with row-level security enabled
  and no policy behind it.
- **Server-side authorization** — privileged routes whose handler checks
  nothing, especially where a frontend hides the same action by role.
- **IDOR** — handlers that take an object id from the path, query or body and
  load it without an ownership predicate.
- **Secrets** — credentials in source, config, compose files, CI and docs, and
  in **git history**; `${VAR:-default}` fallbacks that become real secrets; a
  missing startup check that would have rejected them.
- **Injection and unsafe input** — SQL, NoSQL and command injection, XSS sinks
  (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `javascript:` URLs,
  `eval`), unescaped input in email and template rendering, and request
  boundaries with no schema validation.

Plus token expiry and signing algorithm, cookie flags, CORS, rate limiting and
password storage.

### D3 · Data layer
Missing foreign keys and missing indexes on the columns queries actually filter
and sort by. Nullable columns the code treats as required. Missing unique
constraints behind get-or-create logic. N+1 patterns — an ORM call inside a
loop or inside a `map` over rows. `SELECT *` on wide tables, unbounded reads
with no pagination, transactions that span network I/O, missing pool limits.

And the migration history: destructive statements with no backfill, operations
that take a long lock (a `NOT NULL` column with a default on a large table,
`CREATE INDEX` without `CONCURRENTLY`, a type change that rewrites the table),
schema drift against the ORM's own definitions, missing rollback paths, data
migrations mixed into schema migrations, seeds carrying real data.

Prisma, Drizzle, TypeORM, Sequelize, Knex, Mongoose, the Supabase client, and
raw `pg`/`mysql2`.

### D4 · Delivery and infrastructure
Dockerfiles: running as root, floating base tags, secrets in `ENV`/`ARG`,
`COPY . .` with no `.dockerignore`, no `HEALTHCHECK`, package manager cache
left in the layer. Compose: database ports published to the world,
`privileged`, host bind mounts, default credentials. Kubernetes, Helm and
Terraform misconfiguration.

And CI, which is where the sharpest findings tend to live: a workflow that runs
with repository secrets on code an outside contributor controls, expression
injection through `${{ github.event.* }}` interpolated into a shell, unpinned
third-party actions, over-broad `permissions`, secrets reaching a log, a
self-hosted runner reachable from a fork.

### D5 · Serverless and async workloads
The code that runs outside a request, which is where audits usually stop
looking. Functions across AWS Lambda, Vercel, Cloudflare Workers, Supabase and
Firebase, with their memory, timeout, runtime age, public URLs, concurrency and
dead-letter configuration — and wildcard IAM. Queue consumers without an
idempotency key, backoff, DLQ or concurrency bound. Scheduled work: cron
endpoints reachable without a shared secret, overlapping runs with no lock.
Webhook receivers without signature verification, replay protection or
raw-body handling — told apart from the management API that registers
subscriptions and from the outbound sender, because those are three different
things with three different risks.

### D6 · API surface and contracts
An endpoint matrix — method, path, auth, validation, pagination, rate limit —
where the gaps *are* the findings. Mass assignment. Responses that return more
of an entity than the caller should see. Errors that leak a stack trace or a
SQL string. GraphQL introspection, depth limits, field-level authorization.
Drift between a committed schema and the implemented routes.

### D7 · Reliability and observability
Outbound calls with no timeout, retries with no backoff, no circuit breaker.
Money- and state-changing operations with no idempotency key, and queue
handlers that can be redelivered without one. Transaction boundaries around
network I/O. Swallowed errors. PII and secrets in logs, missing correlation
ids. Health endpoints, graceful shutdown, connection draining. Cache keys that
omit the tenant.

### D8 · Dead code and maintainability
Unused files, exports, types and dependencies — verified in batches by a model
told to err toward "still used", because a dynamic import or a framework
convention keeps code alive in ways a static graph cannot see. Circular
dependencies and orphan modules. Complexity and duplication, used to prioritise
rather than to accuse.

---

## How a run works

Eight phases. Only two spend AI.

| | Phase | Kind | What it does |
|---|---|---|---|
| 0 | `profile` | deterministic | Detects the stack from evidence: package manager, framework, ORM, auth mechanism, database, migrations, serverless and queue definitions, containers, CI, IaC, monorepo layout. Every fact carries the file that proves it. |
| 0.5 | `propose` | **asks you** | Reports what it found that the current scope will *not* check, with the cost of each, and lets you opt in. |
| 1 | `scan` | deterministic | Runs the pinned analyzers concurrently and normalises every output into one finding shape. |
| 2 | `inventory` | deterministic | Enumerates every unit of audit, with a `file:line` for each. This is what makes coverage provable. |
| 3 | `link` | deterministic | Joins units to the profile and builds batches, ordered by risk. |
| 4 | `audit` | **AI** | Asks a model about each batch, with the code in the prompt. Every verdict is verified. |
| 5 | `deadcode` | **AI** | Verifies dead-code candidates in batches. |
| 6 | `score` | deterministic | Per-domain 0–100 with A–F bands, hard ceilings, and a coverage gate that refuses to score a domain nobody examined. |
| 7 | `report` | deterministic | Renders the PDF, the markdown and the GitHub issues. |

Checkpointed throughout: `sentinel resume` re-enters at the first incomplete
phase, and `sentinel report` re-renders a finished run **without spending any
AI** — so fixing a wording bug costs seconds, not another audit.

### Scope negotiation

Sentinel never silently ignores what it noticed. After profiling, it diffs what
the repository contains against what the run will check, and asks:

```
Sentinel found 3 thing(s) it will not check under the current scope.

 1. Deep migration analysis  [data · +15m · AI]
    Found     500 migrations in db/migrations
    Would do  Locking operations, destructive statements without a guard,
              drift against the ORM schema, missing rollback paths.
    Default   off   (--include data.deep-migrations)

Nothing here runs unless you say so: an unanswered proposal stays off.
```

Answers are remembered in a `sentinel.config.json` in the analysed repository —
written only when you ask for it with `--save-scope`, because an audit should
not leave files in someone's work tree uninvited.

### Human triage

Verification is a first-class input, not an edit:

```sh
bun run sentinel report <run-dir> --triage reviewed.json
```

A finding marked false is **withheld, not deleted** — it leaves the counts and
appears in a table with the reviewer's reason, because a reader cannot
otherwise tell a withdrawn claim from one that was never made. Corrected
severities keep both values, scores are recomputed, and the dossier states how
many findings a human actually checked and how many carry no review at all.

---

## Output

```
<target>/sentinel/<runId>/
  report.pdf          the dossier: cover, methodology, executive summary with
                      charts, assurances, coverage, findings by domain with
                      verified snippets, prioritised plan, appendix
  report-brief.pdf    the executive cut: criticals and highs in full, everything
                      else as counted groups  (--brief)
  report.md           the same, diffable between runs
  issues.md           one ready-to-paste GitHub issue per actionable finding,
                      with evidence, impact, fix and acceptance criteria
  findings.json       versioned, machine-readable, complete by construction
  assurances.json     what was checked and found sound
  inventory.json      every audited unit, with file:line
  analysis-scope.json what was analysed and what was left out
  raw/                every analyzer's untouched output, and every AI prompt
                      and reply, so a run is auditable after the fact
```

---

## Tools

Downloaded on `sentinel setup` into `~/.cache/sentinel/`, pinned by version and
SHA-256, verified on arrival. Nothing global, no `sudo`, and an unpinned or
mismatched artifact is refused rather than installed.

| | |
|---|---|
| **trivy** 0.74.0 | dependency CVEs, SBOM, and `trivy config` for containers, Kubernetes, Helm and Terraform |
| **gitleaks** 8.30.1 | secrets, including full git history |
| **opengrep** 1.30.0 | SAST over Sentinel's own rule pack |
| **ast-grep** 0.45.3 | structural enumeration for the inventory |
| **hadolint** 2.15.1 | Dockerfiles |
| **actionlint** 1.7.12 | GitHub Actions |
| **knip** 6.37.0 · **dependency-cruiser** 18.4.0 | dead code, cycles, orphans |

`sentinel doctor` reports what is present, and for anything missing, the one
sentence of coverage it costs — which the report then repeats, so a thin run
never reads as a clean one.

AI phases run on your **Claude subscription** through the Claude Agent SDK. No
API key, nothing metered.

---

## Commands

```
analyze <target>    Profile, negotiate scope, and produce the dossier
setup               Download and hash-verify the pinned analyzers
doctor              What is present, and what each missing tool costs
resume <run-dir>    Re-enter a run at its first incomplete phase
status <run-dir>    What a run contains, and whether it is fit to share
report <run-dir>    Re-render from artifacts, spending no AI
```

Useful flags: `--path apps/api` to bound a monorepo (repeatable; a directory, a
workspace name or a glob), `--include`/`--exclude` for domains and proposals,
`--no-ai` for a deterministic-only run, `--max-batches` and `--no-budget` for
the audit ceiling, `--brief` for the executive cut, `--triage` for reviewed
verdicts.

On a monorepo the dependency scan, the git-history secret scan and the delivery
checks still read the whole repository — a lockfile and a leaked credential
belong to all of it — and every artifact states which subtree was analysed and
how many units were not.

---

## What it is not

A tool whose whole argument is honesty about its own limits should start with
its own.

**The model is wrong sometimes, and the severe findings are where that is
costliest.** Measured against a large production monorepo, before the rules
were corrected, most of the critical and high findings did not survive
hand-verification — string interpolation of a module constant read as SQL
injection, an endpoint already behind an admin policy read as unscoped. Those
causes are fixed and pinned by tests, and the rate is far better now, but it is
not zero and will not be. **Read the severe findings before acting on them.**
The report is built to make that cheap: every one carries its evidence, its
preconditions and its confidence.

**Coverage is honest, not complete.** A domain reports what it examined. `api`
and `reliability` are the newest and least measured. The container enumerator
is new. Dead code is candidates, not verdicts.

**JS and TypeScript are first-class; everything else is partial.** Secrets,
CVEs, containers, CI and IaC are language-agnostic and work anywhere. SAST,
dead code and the data-layer analysis assume JS/TS.

**A large repository needs bounding.** Thousands of units against a throttled
subscription is hours. Use `--path`, or the batch budget, and read the sentence
the run prints about what it left out.

---

## Contributing

`bun test src` runs the suite. `bun run typecheck` and `bun run lint` gate the
same three things CI does — see [CONTRIBUTING.md](./CONTRIBUTING.md) for how the
codebase is put together, and [SECURITY.md](./SECURITY.md) for what a run
touches. `src/meta/no-real-world-data.test.ts` fails the build if anything
resembling a real organisation, credential, path or measured case history
appears in the tree — this repository analyses other people's code, and none of
it belongs here.

See [PLAN.md](./PLAN.md) for the design: the domains, the pipeline, the
contracts and the build order.

## Licence

MIT.
