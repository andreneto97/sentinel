/**
 * gitleaks runner: secrets in the worktree *and in git history*, normalised to
 * `appsec.hardcoded-secret` findings.
 *
 * Two decisions shape everything here. The scan runs `gitleaks detect`, which
 * walks the commit graph, because a credential deleted from the worktree is
 * still a live credential in every clone -- `--no-git` is never passed. And the
 * scan runs with `--redact`, so neither the raw report under `raw/gitleaks/`
 * nor the finding ever carries the secret value: the dossier is meant to be
 * shareable with the client whose repository it describes.
 *
 * This is the one runner that does not hand its findings to
 * `verifyStepFindings`. That helper reads the cited line straight off disk,
 * which for a secret would paste the credential into the report, and it drops a
 * citation whose file no longer exists -- which is exactly the history-only
 * secret that most needs rotating. Citations here are resolved locally instead:
 * every value the scanner matched is masked first, and `src/verify` renders the
 * snippet from those masked lines.
 *
 * `--redact` also means the report says *where* a secret was matched and never
 * *what* was matched, and a rule id of `generic-api-key` says only that
 * something credential-shaped was there. Grading on that alone turns every
 * placeholder, key name and usage line in the repository into a `high` finding,
 * so this runner reads the matched text back -- from the worktree when it is
 * still there, and otherwise from the blob of the commit gitleaks cites
 * (`git show`, through the process port) -- and hands it to
 * `severity.ts#gradeSecret`. The text is held for the length of the run and
 * written nowhere.
 *
 * That is why the work is three passes rather than one:
 *
 * 1. {@link prepare} reads each hit: where the value is now, what it is, and
 *    what the line around it is doing. It also collects every string this
 *    repository uses to *name* a secret held elsewhere.
 * 2. {@link gradeHits} judges them, once that collection is complete -- an
 *    access id is recognisable as an identifier only because another file
 *    addresses a Kubernetes secret key by it.
 * 3. {@link citeHits} renders the citations, once every matched value is known,
 *    because a finding's context lines are where the *next* secret is printed.
 */

import { join } from "node:path";
import type { CodeRef, Finding, Severity } from "../../contracts/findings.ts";
import { extractSnippet, isInside, resolveRepoPath } from "../../verify/index.ts";
import { classifyFile } from "../_file-kind.ts";
import { type SarifFinding, type SarifLocation, parseSarif } from "../parsers/sarif.ts";
import {
  SECRET_SCANNER,
  type SecretContext,
  type SecretGrade,
  gradeSecret,
  isCloudProviderRule,
  isDemotedSecret,
  isGenericSecretRule,
  isPrivateKeyRule,
} from "../severity.ts";
import type { StepOutcome } from "../types.ts";
import {
  type RunnerContext,
  briefly,
  failedStep,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
} from "./_runner-support.ts";

/** Step name, matching the tool it drives. */
export const GITLEAKS_STEP = SECRET_SCANNER;

/** The single Sentinel rule id every gitleaks hit maps to. */
export const GITLEAKS_RULE = "appsec.hardcoded-secret";

/** History scanning is O(commits); a big repository needs more than a linter's budget. */
export const GITLEAKS_DEFAULT_TIMEOUT_MS = 600_000;

/** Lines of context kept on each side of the masked line. */
const CONTEXT_LINES = 3;

/** Snippet rendering knobs, matched to the verifier's own defaults. */
const MAX_LINE_WIDTH = 200;
const MAX_SNIPPET_LINES = 24;
const TAB_WIDTH = 2;

/** What a masked span is replaced with; fixed width, so the length leaks nothing. */
const MASK = "[REDACTED]";

/** The filesystem operations this runner needs beyond the shared context's. */
export interface GitleaksFileSystem {
  /** 1-indexed, inclusive; used to read only the window a snippet needs. */
  readLines(path: string, from: number, to: number): Promise<string[]>;
}

/** The context this runner takes: the shared one plus line-window reads. */
export interface GitleaksContext extends RunnerContext {
  readonly fs: RunnerContext["fs"] & GitleaksFileSystem;
}

/**
 * The rule-class tables live in `severity.ts` with the rest of the
 * secret-strength model; these two functions are the *rule-only* view of them,
 * which is what a reader checking "what does this rule id mean on its own" wants
 * and what `_file-kind.test.ts` pins the T3 exception against.
 *
 * The severity a finding actually carries comes from {@link gradeSecret}, which
 * also weighs what the matched text is and what it is doing there.
 */

/** Critical for key material and cloud accounts, high for every other secret. */
export function severityForRule(ruleId: string): Severity {
  return isPrivateKeyRule(ruleId) || isCloudProviderRule(ruleId) ? "critical" : "high";
}

/** Provider-specific patterns are proof; shape-and-entropy rules are a lead. */
export function confidenceForRule(ruleId: string): "high" | "medium" {
  return isGenericSecretRule(ruleId) ? "medium" : "high";
}

/** The commit metadata gitleaks hides in `partialFingerprints`. */
export interface CommitInfo {
  readonly sha: string | null;
  readonly author: string | null;
  readonly email: string | null;
  readonly date: string | null;
}

/** Reads the commit a secret was introduced in, when gitleaks reported one. */
export function readCommitInfo(finding: SarifFinding): CommitInfo {
  const value = (key: string): string | null => {
    const raw = finding.fingerprints[key];
    return raw === undefined || raw.trim() === "" ? null : raw.trim();
  };
  return {
    sha: value("commitSha"),
    author: value("author"),
    email: value("email"),
    date: value("date"),
  };
}

/** Short sha for prose; the full sha stays in the finding id. */
function shortSha(sha: string | null): string | null {
  return sha === null ? null : sha.slice(0, 10);
}

/**
 * Replaces the reported span with a fixed marker. gitleaks gives 1-based,
 * inclusive column bounds, so the secret is blanked by position -- this process
 * never has to hold the value to redact it.
 */
export function maskSpan(
  lines: readonly string[],
  firstLineNumber: number,
  location: SarifLocation,
): string[] {
  const endLine = location.endLine ?? location.startLine;
  return lines.map((line, index) => {
    const lineNumber = firstLineNumber + index;
    if (lineNumber < location.startLine || lineNumber > endLine) return line;
    const from = lineNumber === location.startLine ? (location.startColumn ?? 1) : 1;
    const to = lineNumber === endLine ? (location.endColumn ?? line.length) : line.length;
    const start = Math.max(0, from - 1);
    const stop = Math.min(line.length, to);
    if (stop <= start) return line;
    return `${line.slice(0, start)}${MASK}${line.slice(stop)}`;
  });
}

/**
 * True when the reported span still fits on the lines that are there now. A
 * shorter line means the file was edited after the commit gitleaks matched, so
 * what is on disk today is not the value it found.
 *
 * One column of slack, because gitleaks' `endColumn` is exclusive: a
 * `generic-api-key` hit whose match runs to the end of its line comes back with
 * `endColumn === line.length + 1` — a 52-character `NAME=<value>` line is
 * reported as columns 2..53. Without the slack, a pristine line fails its own
 * span test.
 */
export function spanFits(
  lines: readonly string[],
  firstLineNumber: number,
  location: SarifLocation,
): boolean {
  const endLine = location.endLine ?? location.startLine;
  const lineAt = (n: number): string | undefined => lines[n - firstLineNumber];
  const start = lineAt(location.startLine);
  if (start === undefined || start.length < (location.startColumn ?? 1) - 1) return false;
  const end = lineAt(endLine);
  return end !== undefined && end.length >= (location.endColumn ?? 0) - 1;
}

// ---------------------------------------------------------------------------
// Reading what the scanner matched
// ---------------------------------------------------------------------------

/**
 * Where the secret is now.
 *
 * `--redact` means the SARIF carries no value, and the columns gitleaks reports
 * are the columns of the blob *in the commit it matched*. A file that has been
 * edited since then — a line added at the top is enough — no longer holds the
 * reported span at the reported line, and declaring such a hit history-only on
 * the strength of a line-length comparison reports a value that is in HEAD today
 * as one that only exists in git history. So the question "is it still here" is
 * answered by looking for the value, not by measuring the line:
 *
 * - `worktree` — the reported span still fits the cited line.
 * - `moved` — the value was found elsewhere in the file, and the citation is
 *   re-anchored to where it is now. A template file that keeps growing at the top
 *   is the usual case.
 * - `history-only` — the value is provably not in the current file, or the file
 *   is gone. Purging history is the fix.
 * - `unresolved` — the line changed and Sentinel could not read the blob to see
 *   what was matched, so it says so instead of guessing either way.
 */
type Presence = "worktree" | "moved" | "history-only" | "unresolved";

/** A commit sha as gitleaks reports it and as `git show` will accept it. */
const SHA_PATTERN = /^[0-9a-f]{7,40}$/;

/** A blob past this is not a source file with a credential on one line of it. */
const BLOB_MAX_BYTES = 4_000_000;

/** `git show` of one blob is a millisecond operation; this only bounds a hang. */
const GIT_TIMEOUT_MS = 30_000;

/** How much of a current file Sentinel will read to look for a moved value. */
const MAX_FILE_LINES = 50_000;

/** Above this, the O(n·depth) YAML walk is not worth running over a whole file. */
const MAX_YAML_LINES = 5_000;

/** Reads the blob a commit held for a path, once per pair. */
interface BlobSource {
  read(sha: string | null, path: string): Promise<readonly string[] | null>;
  /** Why blobs could not be read at all, for the step's reason; null while fine. */
  failure(): string | null;
}

/** Strips a trailing CR so a CRLF file yields the same lines as a LF one. */
function stripCr(line: string): string {
  return line.endsWith("\r") ? line.slice(0, -1) : line;
}

/**
 * `git show <commit>:./<path>`, through the process port like every other
 * command. This is the only place Sentinel reads a historical blob, and the
 * bytes never leave the call: what is written is the masked snippet, the
 * judgement and the reason for it.
 */
function gitBlobs(ctx: GitleaksContext): BlobSource {
  const cache = new Map<string, readonly string[] | null>();
  let failure: string | null = null;

  return {
    failure: () => failure,
    async read(sha: string | null, path: string): Promise<readonly string[] | null> {
      if (sha === null || !SHA_PATTERN.test(sha) || failure !== null) return null;
      const key = `${sha}:${path}`;
      const known = cache.get(key);
      if (known !== undefined || cache.has(key)) return known ?? null;

      const result = await ctx.exec.run("git", ["show", `${sha}:./${path}`], {
        cwd: ctx.targetDir,
        timeoutMs: GIT_TIMEOUT_MS,
        maxOutputBytes: BLOB_MAX_BYTES,
      });
      if (result.notFound) {
        failure =
          "git is not on PATH, so the blobs gitleaks matched could not be read: a hit whose line has " +
          "since changed is reported as unresolved rather than graded by the value it matched";
      }
      const usable =
        !result.notFound && !result.timedOut && !result.truncated && result.exitCode === 0;
      const blob = usable ? result.stdout.split("\n").map(stripCr) : null;
      cache.set(key, blob);
      return blob;
    },
  };
}

/** Reads a current file once, or null when it is absent, escaping or unreadable. */
function worktreeFiles(
  ctx: GitleaksContext,
): (relative: string, absolute: string) => Promise<readonly string[] | null> {
  const cache = new Map<string, readonly string[] | null>();
  return async (relative: string, absolute: string) => {
    const known = cache.get(relative);
    if (known !== undefined || cache.has(relative)) return known ?? null;
    let lines: readonly string[] | null = null;
    if (await ctx.fs.exists(absolute)) {
      try {
        // A symlink inside the repo can still point out of it, and the link
        // target is what would be read.
        const root = await ctx.fs.realpath(ctx.targetDir);
        if (isInside(root, await ctx.fs.realpath(absolute))) {
          lines = await ctx.fs.readLines(absolute, 1, MAX_FILE_LINES);
        }
      } catch {
        lines = null;
      }
    }
    cache.set(relative, lines);
    return lines;
  };
}

/** The first bare token of a value, with quotes and separators left behind. */
function firstToken(text: string): string | undefined {
  return /[^\s'"`,;]+/.exec(text)?.[0];
}

/** The name a value is assigned to, and the value, as far as one line says. */
interface Assignment {
  readonly name: string | undefined;
  readonly value: string | undefined;
}

/**
 * Splits `NAME=value` / `name: value` out of the span the scanner reported.
 *
 * gitleaks' generic rules report a span that *starts inside the name*: a
 * `LENDING_SSO_CLIENT_ID=<value>` line comes back as columns 2..N, so the span
 * reads `ENDING_SSO_CLIENT_ID=…`. The separator is therefore found inside the
 * span, and the name is read back out of the whole line, where it is intact.
 */
export function readAssignment(line: string, from: number, to: number): Assignment {
  const start = Math.max(0, from - 1);
  const stop = Math.min(line.length, to);
  if (stop <= start) return { name: undefined, value: undefined };
  const span = line.slice(start, stop);
  const separator = Math.max(span.lastIndexOf("="), span.lastIndexOf(":"));
  const value = firstToken(separator === -1 ? span : span.slice(separator + 1));
  const nameEnd = separator === -1 ? start : start + separator;
  const name = /([A-Za-z_][\w.-]*)\s*$/.exec(line.slice(0, nameEnd))?.[1];
  return { name, value };
}

/** A YAML mapping key and the column its name starts at. */
const YAML_KEY = /^(\s*(?:-\s+)*)(?:(["'])([^"']+)\2|([A-Za-z0-9_.$-]+))\s*:(?:\s|$)/;

/** One mapping key: how deep it sits, and what it is called. */
interface YamlKey {
  readonly indent: number;
  readonly name: string;
}

/** Reads a line as a YAML mapping key, or null when it is not one. */
function readYamlKey(line: string): YamlKey | null {
  const match = YAML_KEY.exec(line);
  if (match === null) return null;
  const name = match[3] ?? match[4];
  if (name === undefined) return null;
  return { indent: (match[1] ?? "").length, name };
}

/** The mapping keys enclosing `index`, outermost first. */
function yamlAncestors(lines: readonly string[], index: number): string[] {
  const self = readYamlKey(lines[index] ?? "");
  if (self === null) return [];
  const chain: string[] = [];
  let limit = self.indent;
  for (let i = index - 1; i >= 0 && limit > 0; i -= 1) {
    const line = lines[i] ?? "";
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const key = readYamlKey(line);
    if (key === null || key.indent >= limit) continue;
    chain.push(key.name);
    limit = key.indent;
  }
  return chain.reverse();
}

/**
 * The keys whose child `key:`/`name:` is a **pointer** to a secret rather than a
 * secret. A `key: LOAN_RATE_POINTS_<id>` under `secretKeyRef:` names an entry in
 * a Kubernetes Secret that the repository does not contain, and a chart of any
 * size holds dozens of them — every one a `generic-api-key` hit on a string that
 * authenticates nothing.
 */
const SECRET_REF_PARENTS: ReadonlySet<string> = new Set([
  "secretkeyref",
  "configmapkeyref",
  "secretref",
  "configmapref",
  "valuefrom",
  "env",
  "envfrom",
]);

/** True when this line names a secret held elsewhere instead of holding one. */
function isSecretReference(lines: readonly string[], index: number): boolean {
  const self = readYamlKey(lines[index] ?? "");
  if (self === null) return false;
  const key = self.name.toLowerCase();
  if (key !== "key" && key !== "name") return false;
  const ancestors = yamlAncestors(lines, index);
  // Two levels, because `valueFrom: / secretKeyRef: / key:` puts the marker one
  // step further out than `env: / - name:` does.
  return ancestors.slice(-2).some((ancestor) => SECRET_REF_PARENTS.has(ancestor.toLowerCase()));
}

/**
 * Every value in this file that *names* a secret held somewhere else.
 *
 * Memoised on the line array, because several hits usually share one file and
 * the walk is O(lines × depth): the blob and worktree readers both cache, so two
 * hits in one file are handed the same array.
 */
const referenceNameCache = new WeakMap<readonly string[], string[]>();

function referenceNames(lines: readonly string[]): string[] {
  const cached = referenceNameCache.get(lines);
  if (cached !== undefined) return cached;
  const names = collectReferenceNames(lines);
  referenceNameCache.set(lines, names);
  return names;
}

function collectReferenceNames(lines: readonly string[]): string[] {
  if (lines.length > MAX_YAML_LINES) return [];
  const names: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!isSecretReference(lines, index)) continue;
    const line = lines[index] ?? "";
    const value = firstToken(line.slice(line.indexOf(":") + 1));
    if (value !== undefined) names.push(value);
  }
  return names;
}

/** Below this length, a value appearing inside a name is a coincidence. */
const MIN_REUSE_LENGTH = 8;

/**
 * Below this length a matched value is not a credential, so masking every
 * occurrence of it in a snippet would redact ordinary text for nothing.
 */
const MIN_MASKED_VALUE_LENGTH = 12;

/**
 * True when the matched value is also used in this file to name something. A
 * `credentialKey: <id>` line sits in the same chart as
 * `key: LOAN_RATE_POINTS_<id>`: the string is how the deployment *addresses*
 * that consumer, and nothing that authenticates is published as metadata.
 */
function isReusedAsName(names: Iterable<string>, value: string | undefined): boolean {
  if (value === undefined || value.length < MIN_REUSE_LENGTH) return false;
  for (const name of names) {
    if (name !== value && name.includes(value)) return true;
  }
  return false;
}

/** Comment openers by path shape; only the ones that cannot be read as syntax. */
const COMMENT_OPENERS: ReadonlyArray<readonly [RegExp, readonly string[]]> = [
  [/(^|\/)(?:makefile|dockerfile|\.env)[^/]*$/, ["#"]],
  [/\.(?:ya?ml|toml|ini|cfg|conf|sh|bash|zsh|mk|properties|example|sample|template)$/, ["#"]],
  [/\.(?:ts|tsx|js|jsx|mjs|cjs|go|java|kt|swift|scala|rs|c|cc|cpp|cs)$/, ["//"]],
  [/\.sql$/, ["--"]],
  [/\.(?:md|mdx|html?|xml|vue)$/, ["<!--"]],
  [/\.(?:py|rb|pl|r)$/, ["#"]],
];

/** True when the match sits after a comment opener on its own line. */
function insideComment(path: string, line: string, column: number): boolean {
  const lower = path.toLowerCase();
  const openers = COMMENT_OPENERS.find(([shape]) => shape.test(lower))?.[1] ?? [];
  const prefix = line.slice(0, Math.max(0, column - 1));
  return openers.some((opener) => prefix.includes(opener));
}

/** What the matched text is doing where it sits, from the line and the path. */
function contextFor(
  relative: string,
  lines: readonly string[] | null,
  index: number,
  column: number,
): SecretContext {
  if (lines !== null && index < lines.length) {
    if (isSecretReference(lines, index)) return "reference";
    if (insideComment(relative, lines[index] ?? "", column)) return "documentation";
  }
  const kind = classifyFile(relative).kind;
  // A fenced usage line in a README is documentation whether or not Sentinel can
  // see the fence; a `README-TEST.md` is how a `--account-id=123` argument ends up
  // reported as a production credential.
  if (kind === "documentation") return "documentation";
  if (kind === "example") return "template";
  return lines === null || index >= lines.length ? "unknown" : "assignment";
}

/** The first line and column where `value` occurs, or null when it does not. */
function findValue(
  lines: readonly string[],
  value: string,
): { readonly line: number; readonly column: number } | null {
  for (let index = 0; index < lines.length; index += 1) {
    const at = (lines[index] ?? "").indexOf(value);
    if (at !== -1) return { line: index + 1, column: at + 1 };
  }
  return null;
}

/** A location covering exactly the span a re-anchored value occupies today. */
function spanOf(file: string, line: number, column: number, length: number): SarifLocation {
  return {
    file,
    startLine: line,
    startColumn: column,
    endLine: line,
    endColumn: column + length - 1,
    snippet: null,
  };
}

/**
 * Replaces every occurrence of a known matched value with the marker.
 *
 * The span mask covers the line the finding cites; this covers the *context*
 * lines around it, and it has to. An env template holds one credential-shaped
 * value per line, so three lines of context around one match print the next
 * match in the clear — inside the very finding that exists to say a credential
 * must not be readable. Only values long enough to be a credential are masked
 * this way, so a `123` in a usage line does not turn the snippet around it into
 * redaction markers.
 */
function maskKnownValues(lines: readonly string[], values: readonly string[]): string[] {
  if (values.length === 0) return [...lines];
  return lines.map((line) =>
    values.reduce((text, value) => (value === "" ? text : text.split(value).join(MASK)), line),
  );
}

/**
 * Renders the masked citation. The snippet comes from the lines on disk -- never
 * from the tool's output -- and both the cited span and every other matched
 * value in the window are blanked first, so a shareable report can show where the
 * secret sits without showing any secret.
 */
function maskedRef(
  relative: string,
  current: readonly string[],
  anchor: SarifLocation,
  note: string,
  otherValues: readonly string[],
): CodeRef {
  const endLine = anchor.endLine ?? anchor.startLine;
  const from = Math.max(1, anchor.startLine - CONTEXT_LINES);
  const window = current.slice(from - 1, endLine + CONTEXT_LINES);
  // `extractSnippet` numbers lines by index, so the window is padded back to its
  // real position rather than being read as if it started at line 1.
  const lines = [
    ...new Array<string>(from - 1).fill(""),
    ...maskKnownValues(maskSpan(window, from, anchor), otherValues),
  ];
  const last = Math.min(endLine, lines.length);
  const snippet = extractSnippet({
    lines,
    line: anchor.startLine,
    endLine: last > anchor.startLine ? last : undefined,
    contextLines: CONTEXT_LINES,
    maxLineWidth: MAX_LINE_WIDTH,
    maxSnippetLines: MAX_SNIPPET_LINES,
    tabWidth: TAB_WIDTH,
  });
  return {
    file: relative,
    line: anchor.startLine,
    snippet,
    note,
    ...(last > anchor.startLine ? { endLine: last } : {}),
  };
}

/** One hit, read but not yet judged: judging needs what the other hits found. */
interface RawHit {
  readonly ruleId: string;
  readonly relative: string;
  readonly absolute: string;
  /** The span to mask and cite, once it is known what else must be masked with it. */
  readonly anchor: SarifLocation | null;
  /** Whether the file is still in the working tree, which is not the same question. */
  readonly filePresent: boolean;
  readonly presence: Presence;
  readonly commit: CommitInfo;
  /** The line gitleaks reported, which is not the cited line once re-anchored. */
  readonly reportedLine: number;
  readonly ruleDescription: string | null;
  /** The name the value is assigned to, when the line Sentinel read had one. */
  readonly name: string | undefined;
  /** The matched text. Held for the length of the run and written nowhere. */
  readonly value: string | undefined;
  readonly context: SecretContext;
  /**
   * A short hash of the matched value: the dedup key, held in memory only. It is
   * never written anywhere -- not even into the finding's id -- because a hash of
   * a low-entropy value is a confirmation oracle for it.
   */
  readonly fingerprint: string | null;
}

/** A hit with the model's verdict on it. */
interface GradedHit extends RawHit {
  readonly grade: SecretGrade;
}

/** A graded hit with its citation rendered, ready to become a finding. */
interface Prepared extends GradedHit {
  readonly ref: CodeRef;
}

/** Non-reversible enough for a dedup key, and it never leaves this process. */
function fingerprintOf(value: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex").slice(0, 16);
}

/**
 * Reads one hit: where the value is now and what it is. The *judgement* waits
 * for {@link gradeHits}, because one of its inputs — whether this value is used
 * anywhere in the repository to name a secret — is only known once every hit has
 * been read. Returns null only for a citation that points outside the repository.
 */
async function prepare(
  sarif: SarifFinding,
  ctx: GitleaksContext,
  blobs: BlobSource,
  worktree: (relative: string, absolute: string) => Promise<readonly string[] | null>,
  names: Set<string>,
): Promise<RawHit | null> {
  const location = sarif.primary;
  if (location === null) return null;
  const resolved = resolveRepoPath(location.file, ctx.targetDir);
  if (!resolved.ok) return null;
  const { absolute, relative } = resolved.value;

  const commit = readCommitInfo(sarif);
  const ruleId = sarif.ruleId === "" ? "unknown-rule" : sarif.ruleId;
  const current = await worktree(relative, absolute);
  const fits = current !== null && spanFits(current, 1, location);

  /** The lines the match itself was read from: today's file, or the blob. */
  let source: readonly string[] | null = fits ? current : null;
  let presence: Presence = fits ? "worktree" : "history-only";
  let anchor: SarifLocation = location;

  if (!fits) {
    const blob = await blobs.read(commit.sha, relative);
    if (blob !== null && location.startLine <= blob.length) {
      source = blob;
      const matched = readAssignment(
        blob[location.startLine - 1] ?? "",
        location.startColumn ?? 1,
        (location.endLine ?? location.startLine) > location.startLine
          ? Number.MAX_SAFE_INTEGER
          : (location.endColumn ?? Number.MAX_SAFE_INTEGER),
      ).value;
      const moved = matched === undefined || current === null ? null : findValue(current, matched);
      if (moved !== null && matched !== undefined) {
        // On the same line it never moved: the span test failed for some other
        // reason (a column shift, an edit elsewhere on the line), and saying
        // "re-anchored" about a value that is where it was would be noise.
        presence = moved.line === location.startLine ? "worktree" : "moved";
        anchor = spanOf(relative, moved.line, moved.column, matched.length);
      }
    } else if (current !== null) {
      // The file is here, the line has changed, and the blob could not be read:
      // Sentinel does not know whether the value is still in this file.
      presence = "unresolved";
    }
  }

  const index = location.startLine - 1;
  const multiLine = (location.endLine ?? location.startLine) > location.startLine;
  const matchLine = source === null ? "" : (source[index] ?? "");
  const assignment =
    source === null
      ? { name: undefined, value: undefined }
      : readAssignment(
          matchLine,
          location.startColumn ?? 1,
          multiLine ? Number.MAX_SAFE_INTEGER : (location.endColumn ?? Number.MAX_SAFE_INTEGER),
        );

  if (source !== null) for (const name of referenceNames(source)) names.add(name);

  return {
    ruleId,
    relative,
    absolute,
    anchor: presence === "worktree" || presence === "moved" ? anchor : null,
    filePresent: current !== null,
    presence,
    commit,
    reportedLine: location.startLine,
    ruleDescription: sarif.rule?.shortDescription ?? null,
    name: assignment.name,
    value: assignment.value,
    context: contextFor(relative, source, index, location.startColumn ?? 1),
    fingerprint: assignment.value === undefined ? null : fingerprintOf(assignment.value),
  };
}

/**
 * Renders every hit's citation, once every matched value is known.
 *
 * This is why citations are not rendered where they are read: the values that
 * have to be masked out of one finding's context lines are the values *other*
 * hits matched, in the same file, and those are only all known at the end.
 */
async function citeHits(
  hits: readonly GradedHit[],
  worktree: (relative: string, absolute: string) => Promise<readonly string[] | null>,
): Promise<Prepared[]> {
  /** Matched values long enough to be a credential, by file. */
  const perFile = new Map<string, string[]>();
  for (const hit of hits) {
    if (hit.value === undefined || hit.value.length < MIN_MASKED_VALUE_LENGTH) continue;
    const values = perFile.get(hit.relative);
    if (values === undefined) perFile.set(hit.relative, [hit.value]);
    else if (!values.includes(hit.value)) values.push(hit.value);
  }

  const cited: Prepared[] = [];
  for (const hit of hits) {
    const sha = shortSha(hit.commit.sha);
    const reach =
      sha === null ? "only reachable in git history" : `still reachable in commit ${sha}`;
    const current = hit.anchor === null ? null : await worktree(hit.relative, hit.absolute);
    const ref =
      hit.anchor !== null && current !== null
        ? maskedRef(
            hit.relative,
            current,
            hit.anchor,
            hit.presence === "moved"
              ? `secret value masked by Sentinel; re-anchored from line ${hit.reportedLine}, where ${sha === null ? "the scanner" : `commit ${sha}`} matched it`
              : "secret value masked by Sentinel",
            perFile.get(hit.relative) ?? [],
          )
        : {
            file: hit.relative,
            line: hit.reportedLine,
            note:
              hit.presence === "unresolved"
                ? `the line has changed since that commit and Sentinel could not read the blob, so whether the value is still in this file is unknown; ${reach}`
                : `${hit.filePresent ? "the value is no longer in this file" : "not in the working tree"}; ${reach}`,
          };
    cited.push({ ...hit, ref });
  }
  return cited;
}

/**
 * Judges every hit, once they have all been read.
 *
 * The one signal that needs the whole run is `reusedAsName`: a
 * `credentialKey: <id>` match can sit in a chart revision that does not itself
 * name that id, and what settles it is that *another* revision of the same chart
 * addresses a Kubernetes secret key as `LOAN_RATE_POINTS_<id>`. A value the
 * repository uses to name something is an identifier: nothing that authenticates
 * is published as metadata.
 */
function gradeHits(hits: readonly RawHit[], names: ReadonlySet<string>): GradedHit[] {
  return hits.map((hit) => ({
    ...hit,
    grade: gradeSecret({
      ruleId: hit.ruleId,
      ...(hit.name === undefined ? {} : { name: hit.name }),
      ...(hit.value === undefined ? {} : { value: hit.value }),
      context: hit.context,
      reusedAsName: isReusedAsName(names, hit.value),
    }),
  }));
}

/** A human label for the kind of credential, used in the title and the impact. */
function credentialLabel(ruleId: string): string {
  if (isPrivateKeyRule(ruleId)) return "private key";
  if (isCloudProviderRule(ruleId)) return "cloud provider credential";
  return "credential";
}

/**
 * What an attacker gets. A demoted judgement gets its own sentence: claiming
 * "anyone can authenticate as this application" about the name of a Kubernetes
 * secret key is how a report makes non-credentials read like breaches.
 */
function impactFor(ruleId: string, grade: SecretGrade): string {
  switch (grade.judgement) {
    case "secret-reference":
      return (
        "None directly: the repository holds the name of the key, and the value it names lives in " +
        "the secret store. What the name gives away is which secrets exist and how they are " +
        "addressed, which is reconnaissance rather than access."
      );
    case "public-identifier":
      return (
        "None on its own: this half of the pair is sent in the clear on every request, so it is " +
        "already public. It tells an attacker which account and which tenant to aim at, and it is " +
        "worth exactly as much as the paired secret is worth protecting."
      );
    case "documented-example":
      return (
        "None: the value documents the shape of an argument rather than holding a credential. The " +
        "cost of the finding is the reader's time, which is why it is reported as informational."
      );
    case "placeholder":
      return (
        "None: there is nothing here to authenticate with. The finding is kept at informational so " +
        "the match is on the record rather than silently dropped."
      );
    case "unverified-match":
      return (
        "Unknown, and that is the finding: the scanner matched a credential-shaped string that " +
        "Sentinel could not read back, so whether it authenticates anywhere is exactly what has to " +
        "be checked before this is either closed or escalated."
      );
    case "provider-credential":
    case "likely-credential":
      if (isPrivateKeyRule(ruleId)) {
        return (
          "A private key in the repository lets anyone impersonate this service, decrypt the traffic it " +
          "protected and sign artefacts as it. Every signature and session it produced has to be treated " +
          "as untrusted until the key is revoked and replaced."
        );
      }
      if (isCloudProviderRule(ruleId)) {
        return (
          "A cloud provider credential grants whatever its identity can do, which typically includes " +
          "reading the data stores, creating resources that cost money, and reading every other secret " +
          "held in that account."
        );
      }
      return (
        "Anyone with read access to this repository, to any clone of it or to any fork can authenticate " +
        "as this application to the third-party service."
      );
  }
}

/** Where the value is now, in one clause, true in every branch. */
function presenceSentence(presence: Presence, reportedLine: number, sha: string | null): string {
  switch (presence) {
    case "worktree":
      return "The value is still in the working tree.";
    case "moved":
      return `The value is still in the working tree: the line moved since ${sha === null ? "that commit" : `commit ${sha}`} (it was line ${reportedLine} there), and Sentinel re-anchored the citation to where the value is today.`;
    case "history-only":
      return "The value is no longer in the working tree, but it is still in the commit history, so every clone and fork of this repository still carries it.";
    case "unresolved":
      return `The file is still tracked, but line ${reportedLine} no longer holds the reported span and Sentinel could not read the blob for that commit, so whether the value is still in this file is unknown -- treat it as present until that is checked.`;
  }
}

/** The prose that carries the judgement and the commit, and never the secret. */
function describe(hit: Prepared, occurrences: readonly Prepared[]): string {
  const { grade, ruleId, commit, presence } = hit;
  const sha = shortSha(commit.sha);
  const parts: string[] = [
    hit.ruleDescription ??
      `gitleaks matched its \`${ruleId}\` pattern, which identifies a ${credentialLabel(ruleId)}.`,
  ];
  parts.push(
    `Sentinel graded it ${grade.judgement.replace(/-/g, " ")} at ${grade.severity}: ${grade.why}.`,
  );
  if (sha !== null) {
    const who = commit.author ?? commit.email;
    parts.push(
      `It entered the repository in commit ${sha}${who === null ? "" : ` by ${who}`}${commit.date === null ? "" : ` on ${commit.date}`}.`,
    );
  }
  parts.push(presenceSentence(presence, hit.reportedLine, sha));
  if (occurrences.length > 0) {
    const commits = new Set(
      occurrences.map((other) => shortSha(other.commit.sha) ?? "an unnamed commit"),
    );
    parts.push(
      `The same value matched ${occurrences.length} further time${occurrences.length === 1 ? "" : "s"} in this file (${[...commits].join(", ")}); they are one exposure and are listed as evidence rather than counted again.`,
    );
  }
  if (grade.whatWouldConfirm !== null) parts.push(grade.whatWouldConfirm);
  parts.push("The value itself is masked here and in the raw tool output.");
  return parts.join(" ");
}

/** Preconditions an attacker needs, which for a committed credential is only access. */
function exploitabilityFor(hit: Prepared): string {
  const sha = shortSha(hit.commit.sha);
  const reach = sha === null ? "the commit history" : `commit ${sha}`;
  if (hit.grade.hygiene) {
    return `None: on Sentinel's reading this is not a credential (${hit.grade.judgement.replace(/-/g, " ")}), so there is nothing to present to a provider. It is reported so the match is accounted for rather than dropped, and ${reach} is where it was matched.`;
  }
  if (hit.grade.judgement === "unverified-match") {
    return `Read access to the repository, plus the value being live -- which is the part Sentinel could not check. The match is in ${reach}.`;
  }
  return hit.presence === "worktree" || hit.presence === "moved"
    ? `No preconditions beyond read access to the repository: the value is in the checked-out tree and in ${reach}.`
    : `Read access to the repository is enough. Deleting the file did not remove the value -- \`git log -p\` and every existing clone still expose it through ${reach}.`;
}

/**
 * The checklist that closes the issue this finding becomes.
 *
 * A demoted judgement gets its own list. Telling a remediator to "rotate the
 * exposed credential and purge it from git history" for the integer `123` in a
 * README is how a report loses the reader it needed.
 */
function acceptanceCriteria(hit: Prepared): string[] {
  const sha = shortSha(hit.commit.sha);
  const purge = `The value has been purged from git history (\`git filter-repo\`)${sha === null ? "" : `, including commit ${sha}`}, or the exposure has been accepted in writing with the rotation date recorded.`;

  if (hit.grade.hygiene) {
    return [
      `A reviewer has confirmed Sentinel's reading — ${hit.grade.judgement.replace(/-/g, " ")} — or reopened this at credential severity if it is wrong.`,
      "If it is confirmed, the match is recorded in the scanner's allowlist (`.gitleaksignore`) with the reason, so the next run does not spend a reviewer on it again.",
      "If it is not, the credential is rotated first and the rest of this list applies.",
    ];
  }

  if (hit.grade.judgement === "unverified-match") {
    return [
      `The blob has been read (\`git show ${sha ?? "<commit>"}:${hit.relative}\`) and the matched value has been identified as either a credential or a placeholder.`,
      "If it is a credential, it has been rotated at the provider and the old value no longer authenticates.",
      purge,
      "A secret scanner runs in CI, so the next one is caught before it merges.",
    ];
  }

  return [
    "The credential has been revoked or rotated at the provider, and the old value no longer authenticates.",
    "The application reads the new value from the environment or a secret manager, and refuses to start when it is missing.",
    hit.presence === "worktree" || hit.presence === "moved"
      ? "The literal is gone from the working tree and the path is covered by `.gitignore` where appropriate."
      : "The path stays out of the working tree and is covered by `.gitignore`.",
    purge,
    "A secret scanner runs in CI, so the next one is caught before it merges.",
  ];
}

/** What to do about it, phrased for what the evidence actually supports. */
function recommendationFor(hit: Prepared): string {
  switch (hit.grade.judgement) {
    case "secret-reference":
      return (
        "Nothing to rotate: keep the reference. If the key names should not be readable from a public " +
        "clone, rename them to something that does not encode a tenant or an access id, and add this " +
        "path to the scanner's allowlist so the pointer stops being reported as the thing it points at."
      );
    case "public-identifier":
      return (
        "Check the paired secret rather than this half: if the `*_secret`, `*_token` or " +
        "`*_access_key` that goes with it is also committed, that is the finding to act on. This " +
        "identifier can stay, and the match belongs in the scanner's allowlist with that reason."
      );
    case "documented-example":
    case "placeholder":
      return (
        "No rotation is called for. Keep example values obviously fake (`<your-token>`), and record " +
        "this match in the scanner's allowlist so the next run does not raise it again."
      );
    case "unverified-match":
      return (
        "Read the blob for that commit to see what was matched, then either rotate it as a credential " +
        "or allowlist it as a fixture. Sentinel graded it on the uncertainty, not on the value."
      );
    case "provider-credential":
    case "likely-credential":
      return (
        "Rotate the credential first -- removing it from the code does not revoke it. Then move the " +
        "value to the environment or a secret manager, validate its presence at startup, and purge it " +
        "from git history so clones and forks stop carrying it."
      );
  }
}

/** The title, which names the judgement rather than asserting a credential. */
function titleFor(hit: Prepared): string {
  const where = `${hit.ref.file} (${hit.ruleId})`;
  switch (hit.grade.judgement) {
    case "secret-reference":
      return `Secret key name, not a secret value, in ${where}`;
    case "public-identifier":
      return `Public half of a credential pair committed in ${where}`;
    case "documented-example":
      return `Credential-shaped value in a documented example in ${where}`;
    case "placeholder":
      return `Placeholder matched as a credential in ${where}`;
    case "unverified-match":
      return `Unverified credential-shaped value in ${where}`;
    case "provider-credential":
    case "likely-credential":
      return `Hardcoded ${credentialLabel(hit.ruleId)} in ${where}`;
  }
}

/** Turns one group of gitleaks hits — one value in one file — into a finding. */
function toFinding(group: readonly Prepared[]): Finding | null {
  const hit = group[0];
  if (hit === undefined) return null;
  const occurrences = group.slice(1);
  const { grade } = hit;

  const base = makeFinding({
    domain: "appsec",
    rule: GITLEAKS_RULE,
    severity: grade.severity,
    confidence: grade.confidence,
    title: titleFor(hit),
    description: describe(hit, occurrences),
    impact: impactFor(hit.ruleId, grade),
    recommendation: recommendationFor(hit),
    file: hit.ref.file,
    line: hit.ref.line,
    ...(hit.ref.endLine === undefined ? {} : { endLine: hit.ref.endLine }),
    // The commit and the line *in that commit* keep two secrets of the same kind
    // in one file apart, and neither changes when the file around them is
    // edited. The matched value is deliberately not part of this: the id is
    // published, and an id derived from a value is a confirmation oracle for it.
    symbol: `${hit.ruleId}:${hit.commit.sha ?? "worktree"}:L${hit.reportedLine}`,
    evidence: occurrences.map((other) => ({
      file: other.ref.file,
      line: other.ref.line,
      note: `the same value, matched in ${shortSha(other.commit.sha) ?? "another commit"}`,
    })),
    exploitability: exploitabilityFor(hit),
    acceptanceCriteria: acceptanceCriteria(hit),
    cwe: isPrivateKeyRule(hit.ruleId)
      ? ["CWE-798: Use of Hard-coded Credentials", "CWE-321: Use of Hard-coded Cryptographic Key"]
      : ["CWE-798: Use of Hard-coded Credentials"],
    owasp: ["A07:2021 - Identification and Authentication Failures"],
    source: { kind: "tool", name: GITLEAKS_STEP },
  });
  // The masked citation replaces the bare one `makeFinding` built, because this
  // is the one runner that may not let the verifier read the line back.
  return { ...base, location: hit.ref };
}

/** Best-first inside a group: what is checked out beats what is only in history. */
const PRESENCE_RANK: Readonly<Record<Presence, number>> = {
  worktree: 0,
  moved: 1,
  unresolved: 2,
  "history-only": 3,
};

/**
 * Collapses the hits that are one exposure: the same value, in the same file.
 *
 * gitleaks reports a value once per commit that contains it, so one line that
 * two commits both carry — a rebase, a revert and a re-apply, a file moved and
 * moved back — is reported twice although there is one value in one file to
 * rotate. Grouping on (path, value) rather than on (path, line, commit) is what
 * makes the headline count the number of exposures.
 */
function groupHits(hits: readonly Prepared[]): Prepared[][] {
  const groups = new Map<string, Prepared[]>();
  for (const hit of hits) {
    // With no value read there is nothing to compare, so the reported line keeps
    // such hits apart instead of merging them on a guess.
    const key = `${hit.relative}\u001f${hit.fingerprint ?? `L${hit.reportedLine}:${hit.ruleId}`}`;
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [hit]);
    else group.push(hit);
  }
  for (const group of groups.values()) {
    group.sort(
      (left, right) =>
        PRESENCE_RANK[left.presence] - PRESENCE_RANK[right.presence] ||
        (left.commit.date ?? "").localeCompare(right.commit.date ?? "") ||
        left.reportedLine - right.reportedLine,
    );
  }
  return [...groups.values()];
}

/** Builds the gitleaks argument list. `--no-git` is never among them, by design. */
export function gitleaksArgs(targetDir: string, reportPath: string): string[] {
  return [
    "detect",
    "--source",
    targetDir,
    "--report-format",
    "sarif",
    "--report-path",
    reportPath,
    // The report has to be shareable, so the match never lands in it.
    "--redact",
    // Leaks are the expected outcome, not a runner failure.
    "--exit-code",
    "0",
    "--no-banner",
    "--log-level",
    "error",
  ];
}

/**
 * Runs gitleaks over the target's git history and normalises every hit into an
 * `appsec.hardcoded-secret` finding with a masked snippet.
 */
export async function runGitleaks(ctx: GitleaksContext): Promise<StepOutcome> {
  const startedAt = performance.now();

  const binary = await ctx.tools.resolve("gitleaks", { allowPath: ctx.allowPathTools ?? false });
  if (binary === null) {
    return skipped(
      GITLEAKS_STEP,
      startedAt,
      "gitleaks is not installed, so committed credentials go unreported; run `sentinel setup`",
    );
  }
  if (!(await ctx.fs.exists(join(ctx.targetDir, ".git")))) {
    return skipped(
      GITLEAKS_STEP,
      startedAt,
      "the target is not a git repository, and history is the point of this step: a secret that was " +
        "committed and later deleted is exactly what a worktree-only scan misses",
    );
  }

  const reportPath = join(ctx.runDir, "raw", GITLEAKS_STEP, "report.sarif");
  await ctx.fs.mkdirp(join(ctx.runDir, "raw", GITLEAKS_STEP));

  const result = await ctx.exec.run(binary, gitleaksArgs(ctx.targetDir, reportPath), {
    cwd: ctx.targetDir,
    // A stray config in the ambient environment must not silently redefine what
    // counts as a secret; a `.gitleaks.toml` inside the repo still applies.
    env: { GITLEAKS_CONFIG: undefined, GITLEAKS_CONFIG_TOML: undefined },
    timeoutMs: ctx.timeoutMs ?? GITLEAKS_DEFAULT_TIMEOUT_MS,
  });

  if (result.notFound) {
    return failedStep(
      GITLEAKS_STEP,
      startedAt,
      `the gitleaks binary at ${binary} could not be run`,
    );
  }
  if (result.timedOut) {
    return failedStep(
      GITLEAKS_STEP,
      startedAt,
      `gitleaks did not finish within the time budget; history scanning is O(commits), so a large repository needs a longer one. ${briefly(result.stderr)}`,
    );
  }
  if (result.exitCode !== 0) {
    return failedStep(
      GITLEAKS_STEP,
      startedAt,
      `gitleaks exited with code ${result.exitCode}: ${briefly(result.stderr)}`,
    );
  }
  if (!(await ctx.fs.exists(reportPath))) {
    return failedStep(
      GITLEAKS_STEP,
      startedAt,
      `gitleaks reported success but wrote no report at ${reportPath}`,
    );
  }

  let raw: string;
  try {
    raw = await ctx.fs.readFile(reportPath);
  } catch (error) {
    return failedStep(
      GITLEAKS_STEP,
      startedAt,
      `the gitleaks report could not be read: ${briefly(error instanceof Error ? error.message : String(error))}`,
      [reportPath],
    );
  }

  const parsed = parseSarif(raw);
  if (!parsed.ok) {
    return failedStep(GITLEAKS_STEP, startedAt, `gitleaks: ${parsed.error}`, [reportPath]);
  }

  const blobs = gitBlobs(ctx);
  const worktree = worktreeFiles(ctx);
  /** Every string this repository uses to *name* a secret held somewhere else. */
  const names = new Set<string>();
  const hits: RawHit[] = [];
  let dropped = 0;
  for (const sarif of parsed.findings) {
    const hit = await prepare(sarif, ctx, blobs, worktree, names);
    if (hit === null) {
      dropped += 1;
      continue;
    }
    hits.push(hit);
  }

  const groups = groupHits(await citeHits(gradeHits(hits, names), worktree));
  const findings: Finding[] = [];
  for (const group of groups) {
    const finding = toFinding(group);
    if (finding !== null) findings.push(finding);
  }

  const collapsed = hits.length - groups.length;
  const demoted = groups.filter((group) => {
    const primary = group[0];
    return primary !== undefined && isDemotedSecret(primary.grade.judgement);
  }).length;

  const reason = joinReasons([
    // Stated even on a clean run: a reader has to know what was not looked at.
    "gitleaks detect reads committed history, so uncommitted working-tree changes are outside this scan",
    ...parsed.errors.map((error) => `gitleaks reported: ${error}`),
    // A demotion nobody can count is a suppression, so the step says how many and
    // on what grounds; every one of them keeps its finding, at `info` or `low`.
    demoted === 0
      ? null
      : `${demoted} of ${groups.length} match${groups.length === 1 ? "" : "es"} were graded as something other than a credential (a secret *name*, the public half of a pair, a documented example or a placeholder) and are reported below credential severity with the reason on each one`,
    collapsed === 0
      ? null
      : `${collapsed} further hit${collapsed === 1 ? "" : "s"} matched the same value in the same file under another commit and ${collapsed === 1 ? "was" : "were"} folded into the finding for it`,
    blobs.failure(),
    dropped === 0
      ? null
      : `${dropped} hit${dropped === 1 ? "" : "s"} cited a path outside the target directory and ${dropped === 1 ? "was" : "were"} dropped`,
    result.truncated ? "the tool's output was truncated at the capture limit" : null,
  ]);

  return outcome(
    GITLEAKS_STEP,
    result.truncated ? "degraded" : "ok",
    reason,
    findings,
    [reportPath],
    startedAt,
  );
}
