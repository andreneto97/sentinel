# Security

## Reporting a vulnerability

Report privately through GitHub's
[security advisories](https://github.com/andreneto97/sentinel/security/advisories/new)
rather than a public issue.

Include what you did, what happened, and what you expected. A proof of concept
helps; a run directory does not — it may contain findings about your own code.

## What Sentinel touches

Worth knowing before you point it at something that matters.

**It reads the target repository and does not write to it.** Run output goes to
`<target>/sentinel/<runId>/` by default, which `--out` moves anywhere else. The
one exception is `sentinel.config.json`, written at the target's root *only*
when you pass `--save-scope`.

**It spawns pinned analyzers.** `sentinel setup` downloads them into
`~/.cache/sentinel/`, verifies each against the SHA-256 in
`src/tools/tools.lock.json`, and refuses anything unpinned or mismatched.
Analyzers run as subprocesses with a timeout and an output cap. Sentinel does
not resolve tools from `PATH` unless asked, so a run is reproducible.

**It sends source code to a model.** The AI phases put slices of the analysed
repository into prompts, through the Claude Agent SDK on your own subscription.
If the code is confidential, that is the decision to make before running it —
`--no-ai` performs the deterministic half and never leaves the machine.

**Findings quote the code they cite**, so a run directory and its PDF inherit
the sensitivity of the repository they describe. Secrets are masked in the
report and in the raw output, but treat the artifacts as you would the source.

**Raw prompts and replies are kept** under `raw/agents/` so a run is auditable
after the fact. They contain the same code the findings quote.

## What it is not

Sentinel finds classes of problems; it does not prove their absence. A domain
it did not check is reported as not assessed, and a finding it reports may
still be wrong — read the severe ones against the code before acting. The
report is built to make that cheap, and `--triage` exists so a human verdict
becomes part of the document rather than a note beside it.
