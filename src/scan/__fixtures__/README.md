# Scan engine fixtures

`target/` is a small but real repository: a Dockerfile, a compose file, a
GitHub Actions workflow and a `package.json`. Every finding the scan tests
assert on was produced by a real runner reading these files, so a snippet in an
assertion is text that exists on disk.

The two JSON payloads are the **real output** of the pinned binaries run
against `target/`, re-indented to two spaces so `biome check` passes. Their
values are untouched.

| File | Command | Tool version |
|---|---|---|
| `hadolint-dockerfile.json` | `hadolint --no-fail --no-color --format json Dockerfile` | hadolint 2.15.1 |
| `actionlint-workflows.json` | `actionlint -format '{{json .}}' -no-color .github/workflows/ci.yml` | actionlint 1.7.12 |

To refresh either one, run the command above from inside `target/` with the
binary from `~/.cache/sentinel/tools/<tool>/<version>/`.
