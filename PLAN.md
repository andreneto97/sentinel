# Sentinel — design

Sentinel produces a **backend dossier**: a single, evidence-backed report on
the security, dependency, data-layer, delivery-pipeline and dead-code health
of a Node.js/TypeScript codebase.

Target stacks, in priority order: Node.js + TypeScript backends (Express,
Fastify, NestJS, Hono), Next.js (app + pages router, route handlers, server
actions), Expo / React Native clients that talk to those backends.

Runtime: **Bun + TypeScript**. AI phases run on the user's **Claude
subscription** through `@anthropic-ai/claude-agent-sdk` — no API key, $0 per
run, but low parallelism, which is why every expensive step is a
deterministic batch fed to the agent rather than "read the repo and think".

## Non-goals (v1)

- No SBVR / formal business-rule extraction.
- No per-module prose documentation: the most token-expensive output an
  analyser of this shape can produce, and the least actionable. Every phase
  here ends in a finding, an assurance or a count instead.
- No platform binary distribution. Sentinel is cloned and run from source.
- No languages beyond JS/TS as *first-class*. Secrets, CVEs, Docker, CI and
  IaC checks are language-agnostic and work anywhere; SAST, dead code and the
  data-layer analysis assume JS/TS.

## The domains

Every finding belongs to exactly one domain. The report is organised by them.

### D1 — Dependencies & supply chain
- Known CVEs in direct and transitive dependencies (trivy), with the
  dependency path that pulls each one in.
- Outdated packages, separating "patch available" from "major behind".
- Unused dependencies and unused exports (knip).
- Licence inventory from the SBOM, flagging copyleft and unknown licences.
- Lockfile integrity: lockfile present, matches `package.json`, single
  package manager, no `resolutions`/`overrides` masking a vulnerable version.
- Install-time risk: `postinstall` scripts in the dependency tree.

### D2 — Application security
The five access-control categories, re-expressed for the detected stack:
1. **Tenant/owner isolation** — read and list queries that do not constrain by
   the authenticated principal (or, on Supabase, tables without RLS policies).
2. **Server-side authorization** — privileged routes whose handler performs no
   role or ownership check, especially where the frontend hides the UI by role.
3. **IDOR** — handlers that take an object id from path/query/body and load it
   without an ownership predicate.
4. **Secrets** — hardcoded credentials in source, config, compose, CI, docs,
   and in **git history**; `${VAR:-default}` fallbacks that become real
   secrets; missing startup validation that rejects them.
5. **Injection & unsafe input** — SQL/NoSQL/command injection, XSS sinks
   (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `javascript:` URLs,
   `eval`), unsanitised HTML in emails and templates, missing schema
   validation at the request boundary.

Also: authentication weaknesses (token expiry, signature algorithm, cookie
flags, CORS, rate limiting, password storage).

### D3 — Data layer
- **Schema**: missing foreign keys, missing indexes on FK and on columns used
  in `WHERE`/`ORDER BY`, nullable columns that the code treats as required,
  missing unique constraints behind "get or create" logic, `text` where an
  enum/check belongs, timestamps without timezone.
- **Security**: RLS enabled without policies or absent entirely (Supabase and
  Postgres), broad `GRANT`s, credentials in connection strings, TLS disabled,
  the app connecting as a superuser/owner role.
- **Query performance**: N+1 patterns (ORM call inside a loop or inside a
  `map` over rows), `SELECT *` on wide tables, unbounded queries without
  pagination or `LIMIT`, missing `.select()` projections, queries inside
  transactions that also do network I/O, long-running transactions, missing
  connection pool limits, sequential `await`s that could be batched.
- **Migrations**: destructive operations without a guard, out-of-order
  timestamps, schema drift between the ORM schema and the migration history,
  locking migrations (adding a `NOT NULL` column with a default to a large
  table, `CREATE INDEX` without `CONCURRENTLY`, a type change that rewrites the
  table), missing down/rollback path, data migrations mixed into schema
  migrations, migrations never applied in CI, seed files carrying real data or
  credentials.

Supported data layers in v1: Prisma, Drizzle, TypeORM, Sequelize, Knex,
Mongoose, Supabase client, and raw `pg`/`mysql2` SQL.

### D4 — Delivery & infrastructure
- **Dockerfile**: running as root, `latest`/floating base tags, secrets in
  `ENV`/`ARG`, `COPY . .` without `.dockerignore`, missing multi-stage build,
  no `HEALTHCHECK`, package manager cache left in the layer, unpinned
  `apt`/`apk` installs. (hadolint + Sentinel rules.)
- **docker-compose**: published ports that should be internal, `privileged`,
  host bind mounts, default credentials in `environment`, missing
  `restart`/resource limits.
- **CI/CD (GitHub Actions)**: unpinned third-party actions (tag instead of
  SHA), `pull_request_target` with a checkout of untrusted code, script
  injection through `${{ github.event.* }}` interpolation into `run:`,
  over-broad `permissions`, secrets echoed into logs, missing `concurrency`,
  self-hosted runners on public repos. (actionlint + Sentinel rules.)
- **IaC** (when present): Terraform/Helm/Kubernetes misconfiguration via
  `trivy config`.
- **Runtime config**: `.env` committed, env vars read without validation, debug
  flags on, permissive CORS, missing security headers, missing graceful
  shutdown, missing request timeouts.

### D5 — Serverless & async workloads

Anything that runs outside a request/response cycle, which is where backend
audits usually stop looking.

- **Functions inventory**: AWS Lambda (`serverless.yml`, SAM template, CDK,
  Terraform), Vercel and Next.js route handlers including `runtime = "edge"`,
  Cloudflare Workers, Supabase Edge Functions, Firebase Functions. For each:
  memory and timeout settings, an EOL runtime version, bundle size and cold
  start risk, whether it has a public function URL or an unauthenticated
  trigger, concurrency limits, DLQ configured, VPC placement.
- **IAM and trigger permissions**: wildcard `Action`/`Resource` in a function's
  role, a role shared across functions, an S3/SQS trigger with a bucket or
  queue policy wider than the function needs.
- **Queues and background jobs** (BullMQ, SQS, Cloud Tasks, Inngest,
  Trigger.dev, custom workers): handlers without an idempotency key, no max
  attempts or backoff, no dead-letter queue, unbounded concurrency, work that
  belongs in a job being done inside the request path, jobs that never time out.
- **Scheduled work** (`vercel.json` crons, serverless `schedule`, GitHub
  Actions `schedule`, node-cron): cron endpoints reachable without a shared
  secret — the classic `GET /api/cron/*` left open — overlapping runs with no
  lock, schedules that drift across timezones, no alert on failure.
- **Webhooks**: inbound endpoints without signature verification, without
  replay/timestamp protection, or reading a parsed body where the raw body is
  required to verify; outbound calls without timeout, retry or backoff.
- **Realtime**: websocket/SSE connections authenticated only at handshake,
  per-message authorization missing, no backpressure or connection cap.
- **Uploads and storage**: no size or MIME validation, user-controlled object
  keys (path traversal), public buckets, signed URLs with long TTLs, files
  served with a user-supplied content type.
- **Email and notifications**: user input interpolated into HTML templates,
  PII in logs, missing rate limits on send.

### D6 — API surface & contracts

- **Endpoint matrix**: every route with its method, path, auth requirement,
  input validation, pagination, and rate limit — rendered as a table. Gaps in
  that table *are* the findings.
- Missing schema validation at the request boundary; mass assignment (spreading
  `req.body` into a create/update); no output serialisation, so a response
  leaks `passwordHash`, internal ids, soft-deleted rows or another tenant's
  fields.
- Error responses leaking stack traces or SQL; inconsistent status codes;
  unhandled error paths returning 200.
- **GraphQL**: introspection enabled in production, no depth or complexity
  limit, batching abuse, resolvers without field-level authorization.
- Drift between the committed OpenAPI/GraphQL schema and the implemented
  routes; breaking changes without a version bump.
- CORS configuration, cache headers on authenticated responses, and
  `Content-Type` handling.

### D7 — Reliability & observability

- **Outbound calls**: `fetch`/axios/database calls without a timeout, retries
  without backoff and jitter, no circuit breaker, no bulkhead around a
  third-party dependency.
- **Correctness under retry**: money- or state-changing operations without an
  idempotency key, transaction boundaries that span network I/O, missing
  distributed locks around read-modify-write.
- **Logging**: secrets or PII written to logs, unstructured logs, no
  correlation id, debug level left on in production.
- **Lifecycle**: no health/readiness endpoint, no graceful shutdown or signal
  handling, no connection draining, `process.exit` in library code.
- **Error handling**: swallowed errors (`catch {}`), unhandled promise
  rejections, errors logged and rethrown twice, empty catch in a job handler.
- **Caching**: cache keys that omit the tenant or user, no TTL, no stampede
  protection, caching authenticated responses.

### D8 — Dead code & maintainability
- Unused files, exports, types and dependencies (knip), each verified by an AI
  pass in batches to strip false positives (dynamic imports, framework
  conventions, barrel re-exports).
- Circular dependencies and orphan modules (dependency-cruiser).
- Complexity and duplication hotspots, used as *context for prioritisation*,
  not as findings of their own.

## Pipeline

Eight phases. Only phases 4 and 5 spend AI tokens.

| # | Phase | Kind | What it does |
|---|-------|------|--------------|
| 0 | `profile` | deterministic | Detects the stack: package manager, framework, ORM/query builder, auth mechanism, frontend presence, database engine, migration tool, serverless/queue/cron definitions, Docker/compose/CI/IaC files, monorepo layout. Emits `stack-profile.json`. |
| 0.5 | `propose` | deterministic + **asks you** | Reports what it found that it is *not* going to check under the current scope, and asks whether to include it. See below. |
| 1 | `scan` | deterministic | Runs the pinned external tools concurrently and normalises every output into one `Finding` shape. |
| 2 | `inventory` | deterministic | Enumerates the *units of audit*: every route handler (method, path, id parameters it reads), every data-access call site, every serverless function, queue consumer, cron entry and webhook receiver, every role gate in the frontend, every XSS sink, every migration, every CI workflow job. Emits `inventory.json` with a `file:line` for each unit. This is what makes coverage provable. |
| 3 | `link` | deterministic | Joins the inventory to the profile: which handler talks to which table, which frontend role gate maps to which endpoint, which env var feeds which connection string. Produces the worklist batches. |
| 4 | `audit` | **AI**, batched fan-out | For each batch of units, one agent decides whether any D2/D3 rule is violated, citing `file:line` for every claim. Batches are small and homogeneous (handlers with handlers, queries with queries) so the subscription's low parallelism is not the bottleneck. |
| 5 | `deadcode` | **AI**, batched | Verifies knip candidates in batches, erring toward "still used". |
| 6 | `score` | deterministic | Per-domain 0–100 score with A–F bands, hard ceilings (unrotated secret → ≤50, unpatched critical CVE → ≤60), and a run-level confidence. |
| 7 | `report` | deterministic | Renders `report.pdf` (English), `report.md`, `findings.json` and the GitHub-issues section. |

Each phase writes its artifacts and a checkpoint entry; `sentinel resume`
re-enters at the first incomplete phase.

## Scope negotiation (phase 0.5)

Sentinel never silently ignores something it noticed. After profiling, it
diffs **what exists in the repo** against **what the current scope will
actually check**, and reports the gap as a list of proposals. Each proposal
carries: what was detected, the evidence path, what Sentinel could check if
enabled, what it costs (extra minutes and whether it spends AI tokens), and a
default.

Examples of proposals it can raise:

- `terraform/` exists — enable `trivy config` over Terraform? (+40s, no AI)
- `serverless.yml` declares 12 functions — enable the IAM permission audit?
  (+2min, AI)
- 84 Prisma migrations found — enable deep migration analysis (locking
  operations, drift, rollback paths)? (+3min, AI)
- `.github/workflows/` has 6 workflows, 2 on self-hosted runners — enable the
  CI deep audit? (+1min, no AI)
- A second package (`apps/mobile`) exists in the monorepo but is outside the
  analysed path — include it?
- `hadolint` is not installed — Dockerfile findings will be limited to
  Sentinel's own rules. Install it now?
- 31 files are in a language with no SAST coverage — they will be counted but
  not analysed.

### Bounding a monorepo: `--path`

Scope negotiation answers "which *checks*"; `--path` answers "which *code*".
`sentinel analyze <target> --path apps/api` (repeatable — a directory, a
workspace package name, or a glob) restricts the units of audit to those
subtrees, which is what makes a large workspace affordable: where a whole-repo
run would enumerate thousands of units and plan hundreds of AI batches, a run
bounded to one deployable typically plans a dozen.

What it does **not** narrow, because these are properties of the repository
rather than of a subtree: the dependency scan (one lockfile), the git-history
secret scan (one history), the delivery checks (the Dockerfiles and workflows
that build a subtree sit above it), the dead-code and SAST pass (an export used
only from outside the scope would read as unused if the graph stopped at the
boundary), and the stack profile (in a workspace layout the manifests that prove
the stack sit above the analysed subtree). A finding from outside the scope is
therefore possible; it is kept, counted and labelled.

Phase 2 still enumerates the whole repository — it is deterministic and costs
seconds — because that is the only way to say what was left out in the run's own
numbers. `analysis-scope.json` carries the split, and the same sentence appears
in the run output, the PDF cover, `report.md`, `sentinel status` and beside the
scorecard: *this run analysed `apps/api` (300 units); the other 5,000 units in
this repository were not analysed*. The scores are computed against the
repository's counts, never the subtree's, so a bounded run can read worse than
it is and never better.

The scope is written to `sentinel.config.json`, so the next run over the same
repository reuses it and a change of scope shows up in a diff.

Three ways to answer:

1. **Through the skill** (the normal path): Claude shows the proposals as a
   short list of questions and you answer in the conversation.
2. **Flags**: `--include terraform,iam --exclude deadcode`.
3. **Config**: the answers are written to `sentinel.config.json` in the target
   repo, so the next run does not ask again — and a new proposal appearing
   later means the repo itself changed.

`--yes` accepts every default; `--propose-only` prints the proposals and
exits, which is the cheapest way to see what a full run would cover.

## Two rules that make the output trustworthy

**1. Every citation is verified against disk.** When an agent returns a
finding, Sentinel opens the cited file, checks the line exists, and *extracts
the snippet itself*. A finding whose citation does not resolve is dropped and
counted in `report.droppedFindings` — it never reaches the reader. Nothing in
the report is a sentence the model wrote about code it did not point at.

**2. Coverage is enumerated, not sampled.** Phase 2 produces the complete list
of units; phase 4 must return a verdict for every unit in its batch. The
report states `200/200 route handlers audited`. Units dropped by a failed
batch are listed explicitly — a partial run says so instead of looking
complete.

Corollary: the report carries **assurances**, not only findings. "All 23
mutation handlers in the API assert ownership before writing" is an output,
with the evidence that proves it. That is what turns the dossier into
something a client can read.

## Finding shape

```ts
{
  id,                 // stable hash of (domain, rule, file, symbol)
  domain,             // dependencies | appsec | data | delivery | deadcode
  rule,               // e.g. "data.missing-index-on-fk"
  severity,           // critical | high | medium | low | info
  title,
  file, line, endLine,
  snippet,            // extracted by Sentinel, never by the model
  evidence[],         // additional file:line pointers
  exploitability,     // preconditions: flags, config, auth level required
  impact,
  recommendation,
  acceptanceCriteria[],
  cwe[], owasp[],
  source,             // tool:<name> | agent:<phase> | rule:<id>
  confidence,         // high | medium | low
}
```

`Assurance` is the mirror image: `{ check, scope, unitsChecked, evidence[] }`.

## External tools (pinned by version + SHA-256)

Downloaded on `sentinel setup` into `~/.cache/sentinel/tools/<tool>/<version>/`,
hash-verified, never installed globally, never requiring sudo.

| Tool | Used for |
|---|---|
| trivy | dependency CVEs, SBOM (CycloneDX), **`trivy config`** for Dockerfile/compose/K8s/Terraform misconfiguration |
| gitleaks | secrets, including full git history |
| opengrep | SAST over Sentinel's own rule pack |
| ast-grep | structural enumeration for the inventory phase |
| hadolint | Dockerfile linting |
| actionlint | GitHub Actions linting (with shellcheck) |

Node-based tools (knip, dependency-cruiser, eslint) are installed at pinned
versions into a Sentinel-owned `node_modules` in the cache, not into the target
repo.

`sentinel doctor` reports which tools are present, which are missing, and what
each missing tool costs in coverage — and the report discloses the same.

## Layout

```
bin/sentinel.ts            CLI entry
src/cli/                   analyze | resume | doctor | setup | report | status
src/profile/               stack detection
src/tools/                 installer, tools.lock.json, runners/<tool>.ts
src/scan/                  per-tool normalisers → Finding[]
src/inventory/             routes, data access, role gates, sinks, migrations, workflows
src/agents/                Claude Agent SDK runtime, prompts, batching
src/verify/                citation verification + snippet extraction
src/score/                 scoring, bands, ceilings, confidence
src/report/                pdf (cover, charts, tables, chips), markdown, issues
src/contracts/             Zod schemas — the source of truth for every artifact
src/ports/                 process + filesystem seams (the only place they are used)
assets/rules/              Sentinel's own opengrep + ast-grep rules
.claude/commands/          the /sentinel skill
```

## Output

```
<target>/sentinel/<runId>/
  report.pdf          English, A4, cover + executive summary + donut by
                      severity + bars by domain + per-domain tables with
                      severity chips + prioritised plan + GitHub issues section
  report.md
  findings.json       versioned, diffable between runs
  assurances.json     what was checked and is correct, with evidence
  inventory.json      every audited unit, with file:line
  endpoint-matrix.md  route × auth × validation × pagination × rate limit
  stack-profile.json
  scope-proposal.json what was offered, what you accepted, what stayed out
  analysis-scope.json which subtree `--path` analysed, and the units it did not
  raw/                every tool's untouched output
```

## Build order

1. Contracts, ports, CLI skeleton, `doctor`/`setup` with the pinned installer.
2. Phase 0 profile + phase 1 scan with trivy/gitleaks/knip → first real
   `findings.json`. Useful on day one, no AI involved.
3. Phase 0.5 scope proposal + `sentinel.config.json`.
4. Phase 2 inventory (routes first, then data access, then functions/jobs/crons)
   + the citation verification layer.
5. Phase 4 audit over handlers, with the Claude Agent SDK runtime.
6. Data layer (D3) and delivery (D4), including hadolint/actionlint.
7. Scoring + PDF + issues + endpoint matrix.
8. Serverless & async (D5), API contracts (D6), reliability (D7).
9. Dead-code verification (D8).

Domains D1–D4 are the v1 milestone; D5–D8 land incrementally behind the scope
proposal, so an early run is honest about what it did not yet cover.
