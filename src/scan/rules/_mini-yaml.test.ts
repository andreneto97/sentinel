import { describe, expect, test } from "bun:test";
import {
  asMapping,
  asSequence,
  childOf,
  entriesOf,
  entryOf,
  isTrue,
  itemsOf,
  lineOfMatch,
  linesMatching,
  parseYaml,
  splitKey,
  stripComment,
  textOf,
} from "./_mini-yaml.ts";

/** The real workflow the CI rules are tested against. */
const WORKFLOW = `${import.meta.dir}/__fixtures__/repo/.github/workflows/risky.yml`;
/** The real compose file the container rules are tested against. */
const COMPOSE = `${import.meta.dir}/__fixtures__/repo/docker-compose.yml`;

describe("stripComment", () => {
  test("drops a trailing comment", () => {
    expect(stripComment("image: node:20 # the runtime")).toBe("image: node:20");
  });

  test("keeps a # that is inside quotes", () => {
    expect(stripComment('run: echo "#1 of 3"')).toBe('run: echo "#1 of 3"');
  });

  test("keeps a # that is not preceded by whitespace", () => {
    expect(stripComment("tag: v1#build")).toBe("tag: v1#build");
  });
});

describe("splitKey", () => {
  test("splits at the colon that ends the key", () => {
    expect(splitKey("image: postgres:15", 0)).toEqual({
      key: "image",
      rest: "postgres:15",
      valueColumn: 8,
    });
  });

  test("treats a bare colon at end of line as an empty value", () => {
    expect(splitKey("jobs:", 0)?.rest).toBe("");
  });

  test("rejects a colon with no following space", () => {
    expect(splitKey("https://example.com", 0)).toBeNull();
  });

  test("rejects a sequence item", () => {
    expect(splitKey("- uses: actions/checkout@v4", 0)).toBeNull();
  });
});

describe("parseYaml", () => {
  test("reads nested block mappings with the line of every key", () => {
    const document = parseYaml("a:\n  b:\n    c: 1\n");
    expect(document.errors).toEqual([]);
    expect(entryOf(document.root, "a")?.line).toBe(1);
    const b = childOf(childOf(document.root, "a"), "b");
    expect(entryOf(childOf(document.root, "a"), "b")?.line).toBe(2);
    expect(entryOf(b, "c")?.line).toBe(3);
    expect(textOf(childOf(b, "c"))).toBe("1");
  });

  test("accepts a sequence indented at its key's own column", () => {
    const document = parseYaml("on:\n- push\n- pull_request\n");
    expect(itemsOf(childOf(document.root, "on")).map(textOf)).toEqual(["push", "pull_request"]);
  });

  test("keeps a mapping that starts on the dash line", () => {
    const document = parseYaml("steps:\n  - name: a\n    run: b\n  - name: c\n");
    const steps = itemsOf(childOf(document.root, "steps"));
    expect(steps).toHaveLength(2);
    expect(textOf(childOf(steps[0], "name"))).toBe("a");
    expect(textOf(childOf(steps[0], "run"))).toBe("b");
    expect(entryOf(steps[1], "name")?.line).toBe(4);
  });

  test("maps each line of a literal block scalar back to its file line", () => {
    const document = parseYaml("run: |\n  first\n  second\n  third\n");
    const run = childOf(document.root, "run");
    expect(textOf(run)).toBe("first\nsecond\nthird");
    expect(linesMatching(run, /second/)).toEqual([{ line: 3, text: "second" }]);
    expect(lineOfMatch(run, /third/)).toBe(4);
  });

  test("keeps the inner indentation of a block scalar", () => {
    const document = parseYaml("run: |\n  if true; then\n    echo hi\n  fi\n");
    expect(textOf(childOf(document.root, "run"))).toBe("if true; then\n  echo hi\nfi");
  });

  test("unquotes scalars, including a quoted sequence item", () => {
    const document = parseYaml(`ports:\n  - "5432:5432"\n  - '6379:6379'\n`);
    expect(itemsOf(childOf(document.root, "ports")).map(textOf)).toEqual([
      "5432:5432",
      "6379:6379",
    ]);
  });

  test("reads flow sequences and flow mappings on one line", () => {
    const document = parseYaml("a: [x, y]\nb: {k: v, n: [1, 2]}\nc: {}\n");
    expect(itemsOf(childOf(document.root, "a")).map(textOf)).toEqual(["x", "y"]);
    expect(textOf(childOf(childOf(document.root, "b"), "k"))).toBe("v");
    expect(itemsOf(childOf(childOf(document.root, "b"), "n")).map(textOf)).toEqual(["1", "2"]);
    expect(entriesOf(childOf(document.root, "c"))).toEqual([]);
  });

  test("does not mistake a port or a URL for a flow key separator", () => {
    const document = parseYaml("ports: [127.0.0.1:5432:5432]\n");
    expect(itemsOf(childOf(document.root, "ports")).map(textOf)).toEqual(["127.0.0.1:5432:5432"]);
  });

  test("reports an unterminated flow collection instead of hanging", () => {
    const document = parseYaml("a: [x, y\n");
    expect(document.errors.join(" ")).toContain("unterminated flow sequence");
  });

  test("treats a missing value as an empty scalar, not as a missing key", () => {
    const document = parseYaml("permissions:\njobs:\n  a: 1\n");
    expect(entryOf(document.root, "permissions")).not.toBeNull();
    expect(textOf(childOf(document.root, "permissions"))).toBeNull();
    expect(entryOf(document.root, "jobs")?.line).toBe(2);
  });

  test("reads only the first document and says so", () => {
    const document = parseYaml("---\na: 1\n---\nb: 2\n");
    expect(textOf(childOf(document.root, "a"))).toBe("1");
    expect(entryOf(document.root, "b")).toBeNull();
    expect(document.errors.join(" ")).toContain("more than one YAML document");
  });

  test("flags a tab used for indentation", () => {
    expect(parseYaml("a:\n\tb: 1\n").errors.join(" ")).toContain("tab used for indentation");
  });

  test("returns a null root for an empty or comment-only file", () => {
    expect(parseYaml("").root).toBeNull();
    expect(parseYaml("# nothing here\n\n").root).toBeNull();
  });

  test("reads the YAML 1.1 spellings of true", () => {
    const document = parseYaml("a: true\nb: yes\nc: false\nd: 1\n");
    expect(isTrue(childOf(document.root, "a"))).toBe(true);
    expect(isTrue(childOf(document.root, "b"))).toBe(true);
    expect(isTrue(childOf(document.root, "c"))).toBe(false);
    expect(isTrue(childOf(document.root, "d"))).toBe(false);
  });
});

describe("parseYaml on the real fixtures", () => {
  test("reads the workflow fixture with no errors and the right anchors", async () => {
    const document = parseYaml(await Bun.file(WORKFLOW).text());
    expect(document.errors).toEqual([]);

    const triggers = entriesOf(childOf(document.root, "on")).map((entry) => entry.key);
    expect(triggers).toEqual(["pull_request_target", "issue_comment"]);

    const jobs = entriesOf(childOf(document.root, "jobs"));
    expect(jobs).toHaveLength(1);
    const deploy = jobs[0];
    expect(deploy?.key).toBe("deploy");
    expect(deploy?.line).toBe(8);
    expect(textOf(childOf(deploy?.value, "runs-on"))).toBe("self-hosted");

    const steps = itemsOf(childOf(deploy?.value, "steps"));
    expect(steps).toHaveLength(4);
    expect(entryOf(steps[0], "uses")?.line).toBe(11);
    // The secret sits on the second line of the step's literal block, not on `run:`.
    expect(linesMatching(childOf(steps[3], "run"), /secrets\./)).toEqual([
      { line: 21, text: 'echo "token is ${{ secrets.NPM_TOKEN }}"' },
    ]);
  });

  test("reads the compose fixture, including both environment spellings", async () => {
    const document = parseYaml(await Bun.file(COMPOSE).text());
    expect(document.errors).toEqual([]);

    const services = entriesOf(childOf(document.root, "services"));
    expect(services.map((entry) => entry.key)).toEqual(["db", "api", "cache"]);

    const db = services[0]?.value;
    expect(asMapping(db)).not.toBeNull();
    expect(itemsOf(childOf(db, "ports")).map(textOf)).toEqual(["5432:5432"]);
    // `db` uses the mapping spelling of environment...
    expect(entriesOf(childOf(db, "environment")).map((entry) => entry.key)).toEqual([
      "POSTGRES_PASSWORD",
      "POSTGRES_USER",
    ]);

    // ...and `api` uses the list spelling.
    const api = services[1]?.value;
    expect(asSequence(childOf(api, "environment"))).not.toBeNull();
    expect(itemsOf(childOf(api, "environment")).map(textOf)).toEqual([
      "DATABASE_URL=${DATABASE_URL}",
      "JWT_SECRET=changeme",
    ]);
    expect(isTrue(childOf(api, "privileged"))).toBe(true);
    expect(itemsOf(childOf(api, "volumes")).map((item) => item.line)).toEqual([21, 22]);
  });
});
