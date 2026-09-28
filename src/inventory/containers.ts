/**
 * Phase 2 — the container units (D4): the image every Dockerfile ships, and
 * every service a compose file declares.
 *
 * `container` was a declared unit kind with no enumerator behind it. The cost
 * was not an empty table but a false one: `counts.container` was always 0, the
 * skip path that prints "audited deterministically in phase 1" never fired, and
 * every D4 finding arrived attached to no unit of audit however many Dockerfiles
 * and compose files the repository held. This module is what makes the claim
 * countable.
 *
 * ## What counts as one unit
 *
 * - **One unit per Dockerfile, anchored at its final `FROM`.** The final stage
 *   is the thing that runs: it decides the base image, the user, the environment
 *   and the healthcheck. The earlier stages are evidence — they are named in
 *   `earlierStages`, their secrets in `secretsInEarlierStages`, and the unit's
 *   span starts at the final `FROM` so the audit slice is the shipping stage and
 *   not four hundred lines of build. A `FROM build` final stage is followed back
 *   through the aliases, so the base image reported is the image, not the alias.
 * - **One unit per compose service.** A service is the deployed shape of an
 *   image: what it publishes, on which interface, what of the host it mounts and
 *   whether it is privileged are decided here and nowhere else. A service that
 *   builds a Dockerfile in this repository points at that image's unit through
 *   `targetUnitId`, so the two halves can be read together.
 *
 * ## Nothing here parses anything twice
 *
 * The Dockerfile reader, the base-image classifier, the compose port/env/volume
 * readers and both artifact classifiers are **imported** from
 * `src/scan/rules/container.ts`, the module phase 1's deterministic D4 rules
 * already use (seven of its helpers changed from private to exported; no
 * behaviour moved). YAML goes through `src/scan/rules/_mini-yaml.ts`, the same
 * reader, which records the file line of every node — a unit without an exact
 * line cannot be sliced into an audit prompt. What this module adds is the part
 * a rule pack has no use for: identity, span, and the attributes the D4 prompt
 * reasons about.
 */

import { basename, posix } from "node:path";
import type { AuditUnit } from "../contracts/findings.ts";
import { ATTRIBUTE } from "../contracts/inventory.ts";
import { composeFiles as composeFilesOf } from "../profile/detect-data-layer.ts";
import { toLines } from "../profile/text.ts";
import {
  type YamlEntry,
  type YamlNode,
  childOf,
  entriesOf,
  entryOf,
  isTrue,
  itemsOf,
  parseYaml,
  textOf,
} from "../scan/rules/_mini-yaml.ts";
import {
  type DockerInstruction,
  type DockerStage,
  type Dockerfile,
  SECRET_NAME,
  bindsEveryInterface,
  classifyCompose,
  classifyDockerfileRole,
  classifyImage,
  hostPathOf,
  parseAssignments,
  parseDockerfile,
  readEnvironment,
  readPort,
  roleOfImage,
  roleOfServiceName,
} from "../scan/rules/container.ts";
import {
  type AttributePatch,
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  brief,
  finishOutcome,
  notApplicable,
} from "./_unit-support.ts";

/** Cap per artifact kind, so a pathological monorepo cannot turn phase 2 into a crawl. */
export const MAX_CONTAINER_FILES = 50;

/** Attribute value for a setting that exists but is not derivable from the file. */
const UNKNOWN = "unknown";

/** Attribute value for something that is simply not there. */
const NONE = "none";

/** What `artifact` says a unit was read from. */
const IMAGE_ARTIFACT = "dockerfile-image";

/** What `artifact` says a compose-service unit was read from. */
const SERVICE_ARTIFACT = "compose-service";

/**
 * Paths that declare an image: `Dockerfile`, `Dockerfile.ci`, `api.Dockerfile`.
 *
 * The first two spellings are phase 0's, from `src/profile/detect-delivery.ts`,
 * so the files the D4 rules graded and the files the inventory counts are one
 * list; the third is the spelling phase 1's own glob accepts as well. Compose
 * files are not matched here at all — `composeFiles` from phase 0 is imported,
 * because two definitions of "this is a compose file" is how a graded file comes
 * to have no unit.
 */
export const DOCKERFILE_PATH = /(^|\/)(Dockerfile(\.[\w.-]+)?|[\w.-]+\.Dockerfile)$/;

/**
 * Top-level compose keys that are not services.
 *
 * Only consulted for a file with no `services:` mapping, which compose v2
 * allows. `volumes:` and `networks:` are mappings like a service is, and a
 * root-level one must not read as a unit of audit: a fabricated denominator
 * cannot be told from a real one. {@link serviceEntries} holds the other half of
 * that guard, for the keys this list cannot know about.
 */
const NON_SERVICE_KEYS: readonly string[] = [
  "configs",
  "include",
  "name",
  "networks",
  "secrets",
  "version",
  "volumes",
];

/** The `build:` of one compose service, resolved against the repository. */
interface BuildRef {
  /** The service that builds it, as its unit is labelled: `compose.yml#nodejs`. */
  readonly service: string;
  /** Repo-relative Dockerfile, when one resolved on disk. */
  readonly dockerfile: string | undefined;
  /** Repo-relative build context; `.` is the repository root. */
  readonly context: string | undefined;
  /** The `dockerfile:` value as written, kept when it resolved to nothing. */
  readonly declared: string | undefined;
}

/**
 * Normalises repo-relative segments, or undefined when they climb out of the
 * repository — a context Sentinel cannot see is not a context it may describe.
 */
export function repoPath(...segments: readonly string[]): string | undefined {
  const joined = posix.normalize(posix.join(...segments));
  const trimmed = joined.replace(/^\.\//, "").replace(/\/+$/, "");
  if (trimmed === "" || trimmed === ".") return ".";
  if (trimmed === ".." || trimmed.startsWith("../")) return undefined;
  return trimmed;
}

/** The scalar at `key`, collapsed, or undefined when the key carries no scalar. */
function scalarOf(node: YamlNode | null | undefined): string | undefined {
  const text = textOf(node);
  if (text === null) return undefined;
  const collapsed = brief(text);
  return collapsed === "" ? undefined : collapsed;
}

/**
 * The last line a mapping entry covers, taken as the line before the next
 * sibling starts. YAML block structure has no end token, and a unit needs a
 * range for the audit prompt to slice.
 */
function entryEnd(entries: readonly YamlEntry[], index: number, fileLines: number): number {
  const next = entries[index + 1];
  return next === undefined ? fileLines : Math.max(entries[index]?.line ?? 1, next.line - 1);
}

/** `yes` / `no`, the vocabulary every other enumerator's boolean attributes use. */
function yesNo(value: boolean): string {
  return value ? "yes" : "no";
}

// ---------------------------------------------------------------------------
// The image a Dockerfile ships
// ---------------------------------------------------------------------------

/**
 * The image the final stage really builds on, following `FROM <alias>` hops.
 *
 * `FROM build` names an earlier stage, not a registry image, and reporting
 * `build` as the base image would also report it as floating on an implicit
 * `latest`. The hop count is bounded by the number of stages, so a Dockerfile
 * with a cycle cannot spin here.
 */
export function baseImageOf(parsed: Dockerfile, final: DockerStage): string {
  const byAlias = new Map<string, DockerStage>();
  for (const stage of parsed.stages) {
    if (stage.alias !== null) byAlias.set(stage.alias.toLowerCase(), stage);
  }
  let current = final;
  for (let hop = 0; hop < parsed.stages.length; hop += 1) {
    const earlier = byAlias.get(current.image.trim().toLowerCase());
    if (earlier === undefined || earlier.index >= current.index) break;
    current = earlier;
  }
  return current.image;
}

/** Whether the base image's tag can move under the build, in the D4 prompt's words. */
function tagAttributes(image: string): { tag: string; precision: string; floating: string } {
  if (image === "" || image.includes("$")) {
    return { tag: UNKNOWN, precision: UNKNOWN, floating: UNKNOWN };
  }
  // `scratch` is the empty image: there is no tag, so there is nothing to float.
  if (image === "scratch") return { tag: NONE, precision: "none", floating: "no" };
  const { precision, tag } = classifyImage(image);
  return {
    // `none` is an image with no tag written at all, which the builder reads as
    // `latest`. Reporting a bare `latest` would read as a tag somebody chose.
    tag: precision === "none" ? "latest (implicit)" : tag,
    precision,
    floating: precision === "digest" || precision === "exact" ? "no" : "yes",
  };
}

/** The last line with content, so a citation does not point past the end of the file. */
function lastLineOf(text: string): number {
  const lines = toLines(text);
  let last = lines.length;
  while (last > 1 && (lines[last - 1] ?? "").trim() === "") last -= 1;
  return last;
}

/** `ENV`/`ARG` names in these instructions that name a credential rather than a setting. */
function secretNames(instructions: readonly DockerInstruction[]): string[] {
  const names = new Set<string>();
  for (const instruction of instructions) {
    if (instruction.keyword !== "ENV" && instruction.keyword !== "ARG") continue;
    for (const pair of parseAssignments(instruction.argument)) {
      if (SECRET_NAME.test(pair.name)) names.add(pair.name);
    }
  }
  return [...names].sort();
}

/** The user the shipping stage ends as, and whether that is uid 0. */
export interface ShippingUser {
  /** The effective user, with the `ARG` it came from when it came from one. */
  readonly user: string;
  /** `yes`, `no`, or `unknown` when the value is a build argument with no default. */
  readonly runsAsRoot: string;
}

/**
 * Reads the shipping stage's `USER`, resolving `$VAR` against the `ARG`/`ENV`
 * defaults in scope.
 *
 * `USER $USERNAME` with `ARG USERNAME=nobody` above it is a non-root image, and
 * an enumerator that reported it as `unknown` would hand the D4 prompt the same
 * value it gives an image that really cannot be decided. No `USER` at all is
 * uid 0 — that is the deterministic fact phase 1's `runs-as-root` rule states,
 * and this attribute has to agree with it.
 */
export function shippingUser(parsed: Dockerfile, final: DockerStage): ShippingUser {
  const inStage = new Set<DockerInstruction>(final.instructions);
  const defaults = new Map<string, string>();
  const sources = new Map<string, string>();
  for (const instruction of parsed.instructions) {
    if (instruction.keyword !== "ARG" && instruction.keyword !== "ENV") continue;
    // A stage's own declarations, plus the pre-`FROM` ones every stage inherits.
    const beforeStages = !inStage.has(instruction) && instruction.line < final.from.line;
    const global =
      beforeStages && parsed.stages.every((stage) => stage.from.line > instruction.line);
    if (!inStage.has(instruction) && !global) continue;
    for (const pair of parseAssignments(instruction.argument)) {
      if (pair.value === null || pair.value === "") continue;
      defaults.set(pair.name, pair.value);
      sources.set(pair.name, instruction.keyword);
    }
  }

  const users = final.instructions.filter((instruction) => instruction.keyword === "USER");
  const last = users[users.length - 1];
  if (last === undefined) return { user: NONE, runsAsRoot: "yes" };

  const written = last.argument.trim();
  const variable = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(written);
  if (variable !== null) {
    const name = variable[1] ?? "";
    const resolved = defaults.get(name);
    if (resolved === undefined) return { user: written, runsAsRoot: UNKNOWN };
    return {
      user: `${resolved} (from ${sources.get(name) ?? "ARG"} ${name})`,
      runsAsRoot: yesNo(isRoot(resolved)),
    };
  }
  // `USER $UID:$GID` is substituted at build time out of anything's reach here,
  // and `no` would be a claim: the build may well pass 0.
  if (written.includes("$")) return { user: written, runsAsRoot: UNKNOWN };
  return { user: written, runsAsRoot: yesNo(isRoot(written)) };
}

/** True when a `USER` value selects uid 0, in either spelling. */
function isRoot(user: string): boolean {
  return /^(root|0)(:|$)/.test(user.trim().toLowerCase());
}

/** The final `ENTRYPOINT` or `CMD` of the shipping stage, or undefined when it has neither. */
function entrypointOf(final: DockerStage): string | undefined {
  const commands = final.instructions.filter(
    (instruction) => instruction.keyword === "ENTRYPOINT" || instruction.keyword === "CMD",
  );
  const last = commands[commands.length - 1];
  return last === undefined ? undefined : `${last.keyword} ${last.argument}`;
}

/** True when the shipping stage declares a healthcheck that is not `HEALTHCHECK NONE`. */
function hasHealthcheck(final: DockerStage): boolean {
  return final.instructions.some(
    (instruction) =>
      instruction.keyword === "HEALTHCHECK" && !/^none$/i.test(instruction.argument.trim()),
  );
}

/**
 * The image one Dockerfile ships, or undefined when it ships none.
 *
 * A file with no `FROM` builds nothing: it is reported as a note by the caller
 * rather than counted as a unit nobody can audit.
 */
export function imageUnit(
  file: string,
  text: string,
  refs: readonly BuildRef[],
): DraftUnit | undefined {
  const parsed = parseDockerfile(text);
  const final = parsed.stages[parsed.stages.length - 1];
  if (final === undefined) return undefined;

  const stages = parsed.stages.length;
  const base = baseImageOf(parsed, final);
  const tag = tagAttributes(base);
  const user = shippingUser(parsed, final);
  const earlier = parsed.stages.slice(0, -1);
  const built = refs.filter((ref) => ref.dockerfile === file);
  const contexts = [
    ...new Set(
      built.map((ref) => ref.context).filter((value): value is string => value !== undefined),
    ),
  ].sort();

  return {
    kind: "container",
    label: file,
    file,
    line: final.from.line,
    endLine: lastLineOf(text),
    // One image ships per file, so the file is the identity and the symbol is
    // the same word for every one of them — never the stage index, which moves
    // when a stage is added above it.
    symbol: "image",
    note:
      stages === 1
        ? "the single stage of this Dockerfile, which is the image that runs"
        : `the shipping stage of a ${stages}-stage build; the earlier stages are evidence for it`,
    attributes: {
      artifact: IMAGE_ARTIFACT,
      baseImage: base === "" ? UNKNOWN : base,
      baseImageTag: tag.tag,
      tagPrecision: tag.precision,
      floatingTag: tag.floating,
      stages: String(stages),
      earlierStages:
        earlier.length === 0
          ? undefined
          : earlier
              .map(
                (stage) =>
                  `${stage.index + 1}${stage.alias === null ? "" : ` ${stage.alias}`} FROM ${stage.image} (line ${stage.from.line})`,
              )
              .join("; "),
      user: user.user,
      runsAsRoot: user.runsAsRoot,
      healthcheck: yesNo(hasHealthcheck(final)),
      secretsInEnv: secretNames(final.instructions).join(",") || NONE,
      secretsInEarlierStages:
        [...new Set(earlier.flatMap((stage) => secretNames(stage.instructions)))]
          .sort()
          .join(",") || undefined,
      entrypoint: entrypointOf(final),
      // `shipped` is the conservative answer phase 1's classifier gives an image
      // nothing marks as tooling; the prompt uses it to calibrate, never to skip.
      imageRole: classifyDockerfileRole(parsed).role,
      // A build context is a fact about whoever runs `docker build`. When no
      // compose service here builds this image, that is a CI pipeline outside
      // this repository's files, and saying so is the honest answer; `inherited`
      // is a compose override that takes the context from the file it merges with.
      buildContext:
        contexts.length > 0 ? contexts.join(",") : built.length > 0 ? "inherited" : "undeclared",
      builtBy:
        built.length === 0
          ? undefined
          : built
              .map((ref) => ref.service)
              .sort()
              .join(","),
    },
  };
}

// ---------------------------------------------------------------------------
// The services a compose file declares
// ---------------------------------------------------------------------------

/** What reading one compose file produced. */
interface ComposeRead {
  readonly units: readonly DraftUnit[];
  /** Every `build:` in the file, so the Dockerfile units can name their context. */
  readonly refs: readonly BuildRef[];
  /** Everything about the file that has to be disclosed rather than assumed. */
  readonly notes: readonly string[];
  /**
   * True when the YAML reader could not read the whole file.
   *
   * It is not a note among notes. The reader stops at the construct it cannot
   * parse — a `db` service whose `command:` is a multi-line flow sequence is
   * enough, and every service and setting after it is invisible — so the services
   * enumerated are a *prefix* of the file's services and the attributes of the
   * last one are partial. Neither can be presented as a complete reading of the
   * file.
   */
  readonly partial: boolean;
}

/**
 * The service entries of a compose file.
 *
 * A file with a `services:` mapping is read as written. Without one — compose v2
 * lets services sit at the root, and the file list is matched by name — an entry
 * only counts as a service when it declares `image:` or `build:`, the one of
 * which every service must have. That is what keeps a YAML file that merely
 * happens to be called `compose-something.yml` from turning its top-level keys
 * into units of audit: a fabricated denominator cannot be told from a real one.
 */
function serviceEntries(root: YamlNode): readonly YamlEntry[] {
  const services = childOf(root, "services");
  if (services !== null) return entriesOf(services);
  return entriesOf(root).filter(
    (entry) =>
      !NON_SERVICE_KEYS.includes(entry.key.toLowerCase()) &&
      (childOf(entry.value, "image") !== null || childOf(entry.value, "build") !== null),
  );
}

/** The `build:` of one service, resolved against the files the snapshot listed. */
function buildRefOf(
  ctx: EnumerationContext,
  file: string,
  label: string,
  node: YamlNode,
): BuildRef | undefined {
  const build = childOf(node, "build");
  if (build === null) return undefined;
  const scalar = textOf(build);
  const declaredContext = scalar ?? scalarOf(childOf(build, "context"));
  const declaredFile = scalar === null ? scalarOf(childOf(build, "dockerfile")) : undefined;
  const directory = posix.dirname(file);
  const context = declaredContext === undefined ? undefined : repoPath(directory, declaredContext);
  // `dockerfile:` is relative to the context. An override file that inherits the
  // context from the file it is merged with declares none, so the repository
  // root and the compose file's own directory are tried as well — and a path
  // that resolves to nothing on disk is reported as declared, never as resolved.
  const candidates = [context, ".", directory].filter(
    (value): value is string => value !== undefined,
  );
  const relative = declaredFile ?? "Dockerfile";
  let resolved: string | undefined;
  for (const candidate of candidates) {
    const joined = repoPath(candidate, relative);
    if (joined !== undefined && ctx.snapshot.has(joined)) {
      resolved = joined;
      break;
    }
  }
  return {
    service: label,
    dockerfile: resolved,
    context,
    declared: resolved === undefined ? relative : undefined,
  };
}

/** Every published port of a service, with the interface it binds. */
function portAttributes(node: YamlNode): { ports: string; bind: string | undefined } {
  const published = itemsOf(childOf(node, "ports"))
    .map((item) => readPort(item))
    .filter((port): port is NonNullable<typeof port> => port !== null);
  if (published.length === 0) return { ports: NONE, bind: undefined };
  const everywhere = published.some((port) => bindsEveryInterface(port));
  const addresses = [
    ...new Set(
      published.map((port) => port.hostIp?.trim() ?? "").filter((address) => address !== ""),
    ),
  ].sort();
  return {
    ports: published.map((port) => port.raw.trim()).join(","),
    // "every interface" is the fact the D4 rule grades on, so it is stated in
    // those words rather than left to a reader to infer from a missing host IP.
    bind: everywhere ? "every interface" : addresses.join(","),
  };
}

/** Every host path a service bind-mounts, in the order the file lists them. */
function hostMounts(node: YamlNode): string[] {
  const mounts: string[] = [];
  for (const item of itemsOf(childOf(node, "volumes"))) {
    const text = textOf(item);
    const source =
      text !== null ? (text.split(":")[0] ?? "") : (textOf(childOf(item, "source")) ?? "");
    const hostPath = hostPathOf(source);
    if (hostPath !== null) mounts.push(hostPath);
  }
  return mounts;
}

/** Reads one compose file into service units and the build references it declares. */
export function composeRead(ctx: EnumerationContext, file: string, text: string): ComposeRead {
  const document = parseYaml(text);
  const partial = document.errors.length > 0;
  const notes = document.errors.map(
    (error) =>
      `${file}: ${error} — services and settings after that line are not in this inventory`,
  );
  if (document.root === null) {
    return {
      units: [],
      refs: [],
      notes: [...notes, `${file}: no YAML document to read`],
      partial: true,
    };
  }
  const entries = serviceEntries(document.root);
  const lineCount = lastLineOf(text);
  const scope = classifyCompose(text, document.root);
  const units: DraftUnit[] = [];
  const refs: BuildRef[] = [];
  // The citation carries the disclosure as well as the enumerator's reason,
  // because a reader meets a unit in the report one row at a time and an
  // attribute read from a file the reader could not finish must say so there.
  const note = partial
    ? `the compose reader stopped at ${document.errors[0] ?? "an error"} in this file, so these attributes are only what it could read`
    : undefined;

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined || entry.value.kind !== "mapping") continue;
    const node = entry.value;
    const label = `${basename(file)}#${entry.key}`;
    const image = scalarOf(childOf(node, "image"));
    const ref = buildRefOf(ctx, file, label, node);
    if (ref !== undefined) refs.push(ref);
    if (ref?.declared !== undefined) {
      notes.push(
        `${file}: service "${entry.key}" builds ${ref.declared}, which is not in the repository`,
      );
    }
    const role = image === undefined ? roleOfServiceName(entry.key) : roleOfImage(image);
    const ports = portAttributes(node);
    const mounts = hostMounts(node);
    const privileged = entryOf(node, "privileged");
    const healthcheck = childOf(node, "healthcheck");
    const secrets = readEnvironment(childOf(node, "environment"))
      .map((pair) => pair.name)
      .filter((name) => SECRET_NAME.test(name));

    units.push({
      kind: "container",
      label,
      file,
      line: entry.line,
      endLine: entryEnd(entries, index, lineCount),
      symbol: `service:${entry.key}`,
      note,
      attributes: {
        artifact: SERVICE_ARTIFACT,
        service: entry.key,
        image,
        imageSource:
          ref !== undefined ? "built-here" : image !== undefined ? "pulled" : "not declared",
        dockerfile: ref?.dockerfile,
        buildContext: ref === undefined ? undefined : (ref.context ?? "inherited"),
        publishedPorts: ports.ports,
        portBindAddress: ports.bind,
        privileged: yesNo(privileged !== null && isTrue(privileged.value)),
        hostMounts: mounts.join(",") || NONE,
        mountsDockerSocket: yesNo(mounts.some((mount) => mount.includes("docker.sock"))),
        healthcheck: yesNo(healthcheck !== null && !isTrue(childOf(healthcheck, "disable"))),
        user: scalarOf(childOf(node, "user")),
        restart:
          scalarOf(childOf(node, "restart")) ??
          (childOf(childOf(node, "deploy"), "restart_policy") === null
            ? NONE
            : "deploy.restart_policy"),
        serviceRole: role.role,
        // Phase 1 caps a finding's severity on this verdict; the prompt is told
        // the same thing, in the same words, so the two cannot disagree about
        // whether a compose file is a workstation's or a deployment's.
        composeScope: scope.scope,
        secretsInEnv: [...new Set(secrets)].sort().join(",") || NONE,
      },
    });
  }

  return { units, refs, notes, partial };
}

// ---------------------------------------------------------------------------
// The enumerator
// ---------------------------------------------------------------------------

/** Caps a listing, keeping the count it dropped so the cap is disclosed and never silent. */
function capped(all: readonly string[]): { files: string[]; dropped: number } {
  return {
    files: [...all].slice(0, MAX_CONTAINER_FILES),
    dropped: Math.max(0, all.length - MAX_CONTAINER_FILES),
  };
}

/**
 * Enumerates the image every Dockerfile ships and every service a compose file
 * declares.
 *
 * Compose is read first, because a Dockerfile does not know its own build
 * context — the service that builds it does.
 */
export const containerEnumerator: InventoryEnumerator = {
  name: "containers",
  kinds: ["container"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const dockerfiles = capped(ctx.snapshot.filesMatching(DOCKERFILE_PATH));
    const composeFiles = capped(composeFilesOf(ctx.snapshot));
    if (dockerfiles.files.length === 0 && composeFiles.files.length === 0) {
      return notApplicable("the repository has no Dockerfile and no compose file");
    }

    const units: DraftUnit[] = [];
    const notes: string[] = [];
    const refs: BuildRef[] = [];
    /** A file that was listed and could not be read is a gap, not a clean result. */
    const unreadable: string[] = [];
    /** Compose files the YAML reader could only read part of; same rule applies. */
    const incomplete: string[] = [];

    for (const dropped of [
      dockerfiles.dropped === 0 ? null : `${dockerfiles.dropped} Dockerfile(s)`,
      composeFiles.dropped === 0 ? null : `${composeFiles.dropped} compose file(s)`,
    ]) {
      if (dropped !== null)
        notes.push(`stopped at ${MAX_CONTAINER_FILES} files; ${dropped} were not read`);
    }

    for (const file of composeFiles.files) {
      const text = await ctx.snapshot.read(file);
      if (text === undefined) {
        unreadable.push(file);
        continue;
      }
      const read = composeRead(ctx, file, text);
      units.push(...read.units);
      refs.push(...read.refs);
      notes.push(...read.notes);
      if (read.partial) incomplete.push(file);
    }

    for (const file of dockerfiles.files) {
      const text = await ctx.snapshot.read(file);
      if (text === undefined) {
        unreadable.push(file);
        continue;
      }
      const unit = imageUnit(file, text, refs);
      if (unit === undefined) {
        notes.push(`${file}: no \`FROM\`, so it builds no image`);
        continue;
      }
      units.push(unit);
    }

    if (unreadable.length > 0) {
      notes.push(`could not read ${unreadable.sort().join(", ")}`);
    }

    const outcome = finishOutcome(units, {
      notes,
      searchOk: true,
      emptyReason: "the Dockerfiles and compose files declare no image and no service",
    });
    // A file Sentinel listed and could not read to the end is missing coverage,
    // whatever the units it did produce: the claim "these are this repository's
    // images and services" is no longer complete, so the enumerator says so
    // instead of reading as `ok`. This is rule 1 — a check that did not run is
    // reported as not run — applied to enumeration: a service the reader never
    // reached must not become a repository that does not have it.
    return unreadable.length > 0 || incomplete.length > 0
      ? { ...outcome, status: "degraded" }
      : outcome;
  },
  async crossReference(own: readonly AuditUnit[]): Promise<AttributePatch> {
    const imageByFile = new Map<string, AuditUnit>();
    for (const unit of own) {
      if (unit.attributes.artifact === IMAGE_ARTIFACT) imageByFile.set(unit.location.file, unit);
    }
    const patches = new Map<string, Readonly<Record<string, string | undefined>>>();
    for (const unit of own) {
      if (unit.attributes.artifact !== SERVICE_ARTIFACT) continue;
      const dockerfile = unit.attributes.dockerfile;
      if (dockerfile === undefined) continue;
      const image = imageByFile.get(dockerfile);
      if (image === undefined) continue;
      patches.set(unit.id, { [ATTRIBUTE.targetUnitId]: image.id });
    }
    return patches;
  },
};

/** Every D4 container enumerator, in the order the aggregator registers them. */
export const CONTAINER_ENUMERATORS: readonly InventoryEnumerator[] = [containerEnumerator];
