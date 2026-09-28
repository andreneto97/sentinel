# SARIF fixtures

The SARIF payloads in this directory (the other fixtures here belong to the
JSON-based parsers). Real output from the pinned analyzers, trimmed but not
invented -- re-capture them whenever a tool version in
`src/tools/tools.lock.json` moves.

| File | Produced by |
|---|---|
| `gitleaks-report.sarif` | `gitleaks 8.30.1 detect --source <repo> --report-format sarif --redact` over a throwaway repository holding a private key (committed, then deleted) and a token in a committed `.env`. Both results keep their shape; the two commit SHAs were replaced with placeholders so the fixture identifies no repository, and the driver's 222 rule descriptions were cut to the two the results reference. |
| `opengrep-report.sarif` | `opengrep 1.30.0 scan --config assets/rules/opengrep --sarif --no-rewrite-rule-ids` over `src/scan/runners/__fixtures__/rule-pack-target/`. Six of the thirty matches were kept, with the rule descriptors they reference. |
| `opengrep-config-error.sarif` | The same command pointed at a rule file with a YAML syntax error. Verbatim except for the scratch path in the message. Note that the invocation still reports `executionSuccessful: true` with an empty `results` array -- this is the payload that proves a broken scan must not read as a clean one. |

The corpus the opengrep report cites lives at
`src/scan/runners/__fixtures__/rule-pack-target/`, so a finding built from this
fixture resolves against real files on disk and gets a real snippet.
