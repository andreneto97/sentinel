---
description: Run the Sentinel backend dossier on a target repo, negotiating scope before spending anything.
argument-hint: <target-path> [--path <dir>] [--yes]
allowed-tools: Bash, Read, Write, Edit, Glob, Grep
---

Run a Sentinel analysis on `$ARGUMENTS`.

Follow this order and do not skip the confirmation steps.

1. **Resolve the target.** If no path was given, ask for one. Confirm it is a
   git repository and print the resolved absolute path.

2. **Check the toolchain.** Run `bun run sentinel doctor --json`. If tools are
   missing, tell the user which ones and what coverage is lost without them,
   then offer to run `bun run sentinel setup` (it downloads pinned,
   hash-verified binaries into the user's cache — nothing global, no sudo).

3. **Profile and propose.** Run `bun run sentinel analyze <target>
   --propose-only`. Present the proposals as a short numbered list: what was
   detected, what would be checked, and what it costs in time and AI usage.
   Ask which to enable. Do not guess — an unanswered proposal stays off.

4. **Bound a monorepo before spending anything.** If the proposal output shows a
   monorepo — `repo-layout monorepo`, an `nx`/`turbo` tool, several workspace
   packages — the useful question is which deployable to audit, not whether to
   audit 3,000 files. The unit count in the `--propose-only` output is what a
   full run would put through the AI phases, so when it runs into the thousands,
   say so and offer `--path`: `--path apps/api` (repeatable; a directory, a
   workspace package name or a glob). It narrows the audit, not the dependency
   scan, the git-history secret scan or the delivery checks, and every artifact
   states which subtree was analysed and how many units were left out. A scope
   the user accepts is remembered in the target's `sentinel.config.json`, so
   mention it rather than re-asking on the next run.

5. **Run it.** Re-run with the accepted scope:
   `bun run sentinel analyze <target> --include <list> [--path <dir>]`. AI
   phases use the Claude subscription, so expect low parallelism; report
   progress as phases complete rather than going silent.

6. **If it fails partway**, run `bun run sentinel resume <run-dir>` once. If it
   fails again, report the failing phase and its error rather than retrying in
   a loop.

7. **Read the result back.** Summarise: the per-domain scores, the count of
   findings by severity, the coverage line for each domain, anything in
   `droppedFindings`, and any unit the run skipped. State plainly whether the
   run is complete enough to share with a client, and where the PDF landed.

Never present a partial run as a finished audit. If a domain was skipped, a
batch failed, or the run was narrowed with `--path`, say so in the summary
before anything else — for a scoped run, quote the run's own scope sentence
("this run analysed `apps/api` (300 units); the other 5,000 units in this
repository were not analysed") rather than paraphrasing it.
