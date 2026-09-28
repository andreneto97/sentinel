import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { ATTRIBUTE } from "../contracts/inventory.ts";
import { composeFiles as composeFilesOf } from "../profile/detect-data-layer.ts";
import { parseDockerfile } from "../scan/rules/container.ts";
import {
  enumerationContext,
  inventoryContext,
  stubSearch,
} from "./__fixtures__/enumeration-harness.ts";
import type { DraftUnit } from "./_unit-support.ts";
import {
  CONTAINER_ENUMERATORS,
  DOCKERFILE_PATH,
  composeRead,
  containerEnumerator,
  repoPath,
  shippingUser,
} from "./containers.ts";
import { runInventory } from "./inventory.ts";

/**
 * A workspace's container artifacts, one per branch this enumerator has: the
 * per-app multi-stage image that drops to `nobody` through a build argument, a
 * cloud emulator on an untagged base, the developer image whose build args map
 * the host's uid, a digest-pinned image whose final stage names an earlier one by
 * alias, a placeholder with no `FROM`, a compose file that publishes Postgres on
 * every interface, a compose file the YAML reader cannot finish, and an override
 * that names a Dockerfile with no context of its own.
 *
 * Not in `FixtureName` because the harness's union is not this module's to widen,
 * and kept apart from `async-target` because that fixture's counts are asserted
 * by the aggregator's own tests.
 */
const TARGET = join(import.meta.dir, "__fixtures__", "container-target");

/** A repository with source files and no container artifact at all. */
const EMPTY_TARGET = join(import.meta.dir, "__fixtures__", "slice-target");

const ctx = await enumerationContext(TARGET, stubSearch([]));
const outcome = await containerEnumerator.enumerate(ctx);

/** The one unit whose label matches, so a failing assertion names what it looked for. */
function unit(label: string): DraftUnit {
  const found = outcome.units.find((candidate) => candidate.label === label);
  if (found === undefined) {
    throw new Error(
      `no unit labelled "${label}"; got ${outcome.units.map((candidate) => candidate.label).join(", ")}`,
    );
  }
  return found;
}

/** One attribute of one unit, or undefined when the enumerator omitted it. */
function attribute(label: string, key: string): string | undefined {
  return unit(label).attributes[key];
}

describe("which files declare a container", () => {
  test("the Dockerfile spellings phase 1 globs for are the ones phase 2 lists", () => {
    for (const file of [
      "Dockerfile",
      "apps/dock-api/ops/Dockerfile",
      "ops/Dockerfile.ci",
      "ops/api.Dockerfile",
    ]) {
      expect(DOCKERFILE_PATH.test(file)).toBe(true);
    }
    // A path that merely contains the word is not a Dockerfile.
    expect(DOCKERFILE_PATH.test("docs/dockerfiles.md")).toBe(false);
  });

  test("the compose files are phase 0's list, not a second definition of one", () => {
    // `composeFiles` is imported from the phase 0 detector, so a file the profile
    // proved and the D4 rules graded cannot be a file with no unit of audit.
    expect(composeFilesOf(ctx.snapshot)).toEqual([
      "ops/compose/compose-emulator-extras.yml",
      "ops/compose/compose-tests.yml",
      "ops/compose/compose.yml",
    ]);
  });

  test("a path that climbs out of the repository is not a path", () => {
    expect(repoPath("ops/compose", "../../")).toBe(".");
    expect(repoPath(".", "./ops/emulator/Dockerfile")).toBe("ops/emulator/Dockerfile");
    expect(repoPath("ops/compose", "../../../elsewhere")).toBeUndefined();
  });
});

describe("the image a Dockerfile ships", () => {
  test("one unit per file, anchored at the final FROM, earlier stages as evidence", () => {
    const image = unit("apps/dock-api/ops/Dockerfile");
    expect(image.kind).toBe("container");
    expect(image.symbol).toBe("image");
    // Line 20 is the second `FROM`; the first, at line 4, is the build stage.
    expect(image.line).toBe(20);
    expect(image.endLine).toBe(35);
    expect(image.attributes.stages).toBe("2");
    expect(image.attributes.earlierStages).toBe("1 build FROM node:24-bookworm-slim (line 4)");
    expect(image.note).toContain("shipping stage of a 2-stage build");
  });

  test("a `USER $ARG` is resolved through the ARG's default rather than reported unknown", () => {
    expect(attribute("apps/dock-api/ops/Dockerfile", "user")).toBe("nobody (from ARG USERNAME)");
    expect(attribute("apps/dock-api/ops/Dockerfile", "runsAsRoot")).toBe("no");
    expect(attribute("ops/compose/devbox/Dockerfile", "user")).toBe("dev (from ARG UNAME)");
  });

  test("a USER the build substitutes is unknown, never reported as non-root", () => {
    // `USER $UID:$GID` with no default in the file: the build may pass 0, and
    // `runsAsRoot: no` would be a claim phase 2 cannot make.
    const dockerfile = parseDockerfile(
      ["FROM node:24.8.0-bookworm-slim", "ARG UID", "USER $UID:$GID"].join("\n"),
    );
    const stage = dockerfile.stages[0];
    expect(stage).toBeDefined();
    if (stage === undefined) return;
    expect(shippingUser(dockerfile, stage)).toEqual({
      user: "$UID:$GID",
      runsAsRoot: "unknown",
    });
  });

  test("no USER at all is uid 0, in the same words phase 1's rule uses", () => {
    expect(attribute("ops/emulator/Dockerfile", "user")).toBe("none");
    expect(attribute("ops/emulator/Dockerfile", "runsAsRoot")).toBe("yes");
  });

  test("an explicit `USER root` is root, and the digest behind an alias is not floating", () => {
    expect(attribute("ops/pinned/Dockerfile", "runsAsRoot")).toBe("yes");
    // The final stage is `FROM base`: the base image reported is the image the
    // alias resolves to, not the alias — which would also read as floating.
    expect(attribute("ops/pinned/Dockerfile", "baseImage")).toContain("@sha256:");
    expect(attribute("ops/pinned/Dockerfile", "baseImageTag")).toBe("digest");
    expect(attribute("ops/pinned/Dockerfile", "floatingTag")).toBe("no");
  });

  test("an untagged base floats on an implicit latest, and says which it is", () => {
    expect(attribute("ops/emulator/Dockerfile", "baseImageTag")).toBe("latest (implicit)");
    expect(attribute("ops/emulator/Dockerfile", "tagPrecision")).toBe("none");
    expect(attribute("ops/emulator/Dockerfile", "floatingTag")).toBe("yes");
    // A tag with no patch component still moves under the build.
    expect(attribute("apps/dock-api/ops/Dockerfile", "tagPrecision")).toBe("floating");
    expect(attribute("apps/dock-api/ops/Dockerfile", "floatingTag")).toBe("yes");
  });

  test("a HEALTHCHECK is reported where there is one and where there is not", () => {
    expect(attribute("ops/pinned/Dockerfile", "healthcheck")).toBe("yes");
    expect(attribute("apps/dock-api/ops/Dockerfile", "healthcheck")).toBe("no");
  });

  test("a secret name in the shipping stage is not the same fact as one in a build stage", () => {
    expect(attribute("ops/pinned/Dockerfile", "secretsInEnv")).toBe("SERVICE_API_TOKEN");
    expect(attribute("apps/dock-api/ops/Dockerfile", "secretsInEnv")).toBe("none");
    expect(attribute("apps/dock-api/ops/Dockerfile", "secretsInEarlierStages")).toBe(
      "NODE_AUTH_TOKEN",
    );
  });

  test("the build context comes from the compose service that builds the image", () => {
    expect(attribute("ops/emulator/Dockerfile", "buildContext")).toBe(".");
    expect(attribute("ops/emulator/Dockerfile", "builtBy")).toBe("compose.yml#localstack");
    // Two services build the developer image, and both are named.
    expect(attribute("ops/compose/devbox/Dockerfile", "builtBy")).toBe(
      "compose-tests.yml#nodejs,compose.yml#nodejs",
    );
    // An override declares a Dockerfile and no context; it inherits one.
    expect(attribute("ops/pinned/Dockerfile", "buildContext")).toBe("inherited");
    // Nothing in the repository builds the per-app image: CI does, elsewhere.
    expect(attribute("apps/dock-api/ops/Dockerfile", "buildContext")).toBe("undeclared");
    expect(attribute("apps/dock-api/ops/Dockerfile", "builtBy")).toBeUndefined();
  });

  test("phase 1's own classifier decides whether the image ships", () => {
    expect(attribute("apps/dock-api/ops/Dockerfile", "imageRole")).toBe("shipped");
    expect(attribute("ops/compose/devbox/Dockerfile", "imageRole")).toBe("tooling");
    expect(attribute("ops/emulator/Dockerfile", "imageRole")).toBe("tooling");
  });

  test("a Dockerfile with no FROM is disclosed, not counted and not dropped silently", () => {
    expect(outcome.units.some((candidate) => candidate.file.includes("placeholder"))).toBe(false);
    expect(outcome.reason).toContain("ops/placeholder/Dockerfile: no `FROM`");
  });
});

describe("the services a compose file declares", () => {
  test("one unit per service, spanning its block", () => {
    const service = unit("compose.yml#db");
    expect(service.kind).toBe("container");
    expect(service.symbol).toBe("service:db");
    expect(service.line).toBe(56);
    expect(service.endLine).toBe(71);
    expect(service.attributes.service).toBe("db");
    expect(service.attributes.artifact).toBe("compose-service");
  });

  test("a published port carries the interface it binds", () => {
    expect(attribute("compose.yml#db", "publishedPorts")).toBe("55432:5432");
    expect(attribute("compose.yml#db", "portBindAddress")).toBe("every interface");
    expect(attribute("compose.yml#redis", "publishedPorts")).toBe("127.0.0.1:6379:6379");
    expect(attribute("compose.yml#redis", "portBindAddress")).toBe("127.0.0.1");
    expect(attribute("compose-emulator-extras.yml#localstack", "publishedPorts")).toBe("none");
  });

  test("host mounts are listed, the docker socket is its own fact, named volumes are not mounts", () => {
    expect(attribute("compose.yml#localstack", "hostMounts")).toBe(
      "../emulator/ready.d,/var/run/docker.sock,../../",
    );
    expect(attribute("compose.yml#localstack", "mountsDockerSocket")).toBe("yes");
    // `db:/var/lib/postgresql/data` is a named volume; only the bind mount counts.
    expect(attribute("compose.yml#db", "hostMounts")).toBe("./db/initdb.d");
    expect(attribute("compose.yml#db", "mountsDockerSocket")).toBe("no");
  });

  test("privileged is reported for the service that sets it and the ones that do not", () => {
    expect(attribute("compose-emulator-extras.yml#localstack", "privileged")).toBe("yes");
    expect(attribute("compose.yml#db", "privileged")).toBe("no");
  });

  test("whether the image is built here or pulled, and which Dockerfile it builds", () => {
    expect(attribute("compose.yml#localstack", "imageSource")).toBe("built-here");
    expect(attribute("compose.yml#localstack", "dockerfile")).toBe("ops/emulator/Dockerfile");
    expect(attribute("compose.yml#localstack", "buildContext")).toBe(".");
    expect(attribute("compose.yml#db", "imageSource")).toBe("pulled");
    expect(attribute("compose.yml#db", "image")).toBe("postgres:16.4");
    expect(attribute("compose.yml#db", "dockerfile")).toBeUndefined();
    // An override resolves its Dockerfile without a context of its own.
    expect(attribute("compose-emulator-extras.yml#localstack", "dockerfile")).toBe(
      "ops/pinned/Dockerfile",
    );
    expect(attribute("compose-emulator-extras.yml#localstack", "buildContext")).toBe("inherited");
  });

  test("the service's role and its file's scope are phase 1's verdicts, unchanged", () => {
    expect(attribute("compose.yml#db", "serviceRole")).toBe("datastore");
    expect(attribute("compose.yml#opensearch-dashboard", "serviceRole")).toBe("web-ui");
    expect(attribute("compose.yml#localstack", "serviceRole")).toBe("emulator");
    expect(attribute("compose.yml#db", "composeScope")).toBe("development");
  });

  test("a credential name in the environment is reported, a placeholder is still a name", () => {
    expect(attribute("compose.yml#db", "secretsInEnv")).toBe("POSTGRES_PASSWORD");
    expect(attribute("compose.yml#nodejs", "secretsInEnv")).toBe("NODE_AUTH_TOKEN");
    expect(attribute("compose.yml#redis", "secretsInEnv")).toBe("none");
  });

  test("a top-level key that is not a service never becomes a unit of audit", () => {
    // Compose v2 lets services sit at the root. `volumes:` and `networks:` are
    // mappings too, and counting one as a unit would fabricate a denominator —
    // which is worse than missing one, because it cannot be told from a real one.
    const read = composeRead(
      ctx,
      "ops/compose/compose-helpers.yml",
      [
        "api:",
        "  image: ghcr.io/acme/api:1.2.3",
        "volumes:",
        "  data:",
        "networks:",
        "  web: ~",
      ].join("\n"),
    );
    expect(read.units.map((candidate) => candidate.symbol)).toEqual(["service:api"]);
    // And an entry that declares neither `image:` nor `build:` is not a service
    // at all, which is what keeps a YAML file that only happens to be named like
    // a compose file from inventing units.
    const helpers = composeRead(
      ctx,
      "ops/compose/compose-helpers.yml",
      ["defaults:", "  timeout: 30", "retries:", "  count: 3"].join("\n"),
    );
    expect(helpers.units).toHaveLength(0);
  });
});

describe("a file the reader could not finish", () => {
  test("the truncated compose file degrades the enumerator instead of reading as ok", () => {
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("ops/compose/compose-tests.yml: line 20");
    expect(outcome.reason).toContain("are not in this inventory");
  });

  test("every unit from it carries the disclosure on its own citation", () => {
    // The attributes below the reader's stopping point are missing, not false:
    // this `db` really does publish `50001:5432`, and the note is what stops the
    // row reading as a service that publishes nothing.
    expect(unit("compose-tests.yml#db").note).toContain("only what it could read");
    expect(attribute("compose-tests.yml#db", "publishedPorts")).toBe("none");
    // And the service after the stopping point is absent rather than invented.
    expect(outcome.units.some((candidate) => candidate.label === "compose-tests.yml#redis")).toBe(
      false,
    );
    // A file that parsed to the end carries no such note.
    expect(unit("compose.yml#redis").note).toBeUndefined();
  });
});

describe("the enumerator", () => {
  test("claims the container kind and produces one unit per image and per service", () => {
    expect(containerEnumerator.kinds).toEqual(["container"]);
    expect(outcome.units.filter((u) => u.attributes.artifact === "dockerfile-image")).toHaveLength(
      4,
    );
    expect(outcome.units.filter((u) => u.attributes.artifact === "compose-service")).toHaveLength(
      8,
    );
  });

  test("a repository with no container artifact is skipped, not empty", async () => {
    const empty = await enumerationContext(EMPTY_TARGET, stubSearch([]));
    const result = await containerEnumerator.enumerate(empty);
    expect(result.status).toBe("skipped");
    expect(result.units).toHaveLength(0);
    expect(result.reason).toBe("the repository has no Dockerfile and no compose file");
  });
});

describe("what the inventory does with the units", () => {
  test("every citation resolves, the kind is counted, and the services point at their image", async () => {
    const context = inventoryContext(TARGET);
    const { document } = await runInventory(context, {
      enumerators: CONTAINER_ENUMERATORS,
      search: stubSearch([]),
      write: false,
    });

    expect(document.counts.container).toBe(12);
    expect(document.dropped).toHaveLength(0);
    expect(document.enumerators.map((report) => report.name)).toEqual(["containers"]);
    expect(document.enumerators[0]?.status).toBe("degraded");

    const image = document.units.find((u) => u.location.file === "ops/compose/devbox/Dockerfile");
    const service = document.units.find((u) => u.label === "compose.yml#nodejs");
    expect(image).toBeDefined();
    expect(service?.attributes[ATTRIBUTE.targetUnitId]).toBe(image?.id ?? "");
    // A service that pulls its image points at nothing, and says nothing.
    const pulled = document.units.find((u) => u.label === "compose.yml#db");
    expect(pulled?.attributes[ATTRIBUTE.targetUnitId]).toBeUndefined();
  });
});
