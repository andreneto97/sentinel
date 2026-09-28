import { describe, expect, test } from "bun:test";
import {
  lastIdentifier,
  maskLiterals,
  objectEntries,
  objectValue,
  parseChain,
  splitTopLevel,
  stringLiteral,
  unwrap,
} from "./_chain.ts";

describe("maskLiterals", () => {
  test("keeps the length so indices mean the same thing in both strings", () => {
    const source = 'db.where(eq(t.name, "a, b")) // note';
    expect(maskLiterals(source)).toHaveLength(source.length);
  });

  test("a brace inside a SQL literal cannot unbalance a chain", () => {
    const masked = maskLiterals('sql("SELECT {json} FROM t")');
    expect(masked).not.toContain("{");
    expect(masked).not.toContain("}");
  });

  test("a template literal is blanked whole, interpolation included", () => {
    const source = "query(`a ${fn({ x: 1 })} b`)";
    const masked = maskLiterals(source);
    expect(masked).toHaveLength(source.length);
    // The call's own parentheses survive; everything the template holds does not.
    expect(masked).toStartWith("query(");
    expect(masked).toEndWith(")");
    expect(masked).not.toContain("{");
    expect(masked).not.toContain("`");
  });

  test("a regular expression is not read as division", () => {
    const masked = maskLiterals("find({ name: /a(b/ })");
    // The unbalanced `(` inside the regex must not survive into the mask.
    expect(masked.split("(").length - 1).toBe(1);
  });
});

describe("splitTopLevel", () => {
  test("splits only at the commas that are not nested", () => {
    expect(splitTopLevel('eq(a, b), inArray(c, [1, 2]), "x, y"')).toEqual([
      "eq(a, b)",
      "inArray(c, [1, 2])",
      '"x, y"',
    ]);
  });
});

describe("parseChain", () => {
  test("splits a Drizzle chain into its receiver and its links", () => {
    const chain = parseChain(
      "db.select().from(bookings).where(eq(bookings.orgId, orgId)).limit(50)",
    );
    expect(chain.base).toBe("db");
    expect(chain.segments.map((segment) => segment.name)).toEqual([
      "select",
      "from",
      "where",
      "limit",
    ]);
    expect(chain.segments[1]?.args).toEqual(["bookings"]);
    expect(chain.segments[3]?.args).toEqual(["50"]);
  });

  test("a dotted receiver stays whole", () => {
    expect(parseChain("prisma.booking.findMany({ where: { id } })").base).toBe("prisma.booking");
  });

  test("a bare call opens the chain with an unnamed link", () => {
    const chain = parseChain('knex("users").where({ id }).first()');
    expect(chain.base).toBe("knex");
    expect(chain.segments[0]?.name).toBe("");
    expect(chain.segments[0]?.args).toEqual(['"users"']);
    expect(chain.segments.map((segment) => segment.name)).toEqual(["", "where", "first"]);
  });

  test("a tagged template is a link, and its body is the argument", () => {
    const chain = parseChain("prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`");
    expect(chain.segments[0]?.name).toBe("$queryRaw");
    expect(chain.segments[0]?.tagged).toBe(true);
    expect(chain.segments[0]?.argsText).toBe("SELECT * FROM users WHERE id = ${id}");
  });

  test("a multi-line chain reads the same as a single-line one", () => {
    const chain = parseChain("db\n  .select()\n  .from(users)\n  .where(eq(users.id, id))");
    expect(chain.segments.map((segment) => segment.name)).toEqual(["select", "from", "where"]);
  });

  test("type arguments do not break the chain", () => {
    const chain = parseChain("repo.find<User>({ where: { id } }).then((r) => r)");
    expect(chain.segments.map((segment) => segment.name)).toEqual(["find", "then"]);
  });

  test("a trailing property read is a tail, not a link", () => {
    const chain = parseChain('pool.query("SELECT 1").rows');
    expect(chain.tail).toBe("rows");
    expect(chain.segments).toHaveLength(1);
  });

  test("await and wrapping parentheses are stripped before parsing", () => {
    expect(parseChain("await (db.select().from(t))").base).toBe("db");
  });

  test("a string argument containing a paren does not end the call early", () => {
    const chain = parseChain('knex.raw("SELECT count(*) FROM t WHERE a = ?", [1])');
    expect(chain.segments[0]?.args).toEqual(['"SELECT count(*) FROM t WHERE a = ?"', "[1]"]);
  });
});

describe("objectEntries", () => {
  test("reads nested values whole", () => {
    const entries = objectEntries("{ where: { userId: session.user.id }, take: 20 }");
    expect(entries.map((entry) => entry.key)).toEqual(["where", "take"]);
    expect(entries[0]?.value).toBe("{ userId: session.user.id }");
  });

  test("shorthand binds the key to itself", () => {
    expect(objectEntries("{ tenantId }")).toEqual([{ key: "tenantId", value: "tenantId" }]);
  });

  test("a quoted key is reported unquoted", () => {
    expect(objectValue('{ "user_id": uid }', "user_id")).toBe("uid");
  });

  test("a spread is reported as one, not as a column", () => {
    expect(objectEntries("{ ...rest, id }").map((entry) => entry.key)).toEqual(["...", "id"]);
  });
});

describe("stringLiteral", () => {
  test("reads every quote style", () => {
    expect(stringLiteral('"users"')).toBe("users");
    expect(stringLiteral("'users'")).toBe("users");
    expect(stringLiteral("`users`")).toBe("users");
  });

  test("a template with a substitution is an expression, not a literal", () => {
    expect(stringLiteral("`users_${suffix}`")).toBeNull();
  });
});

describe("unwrap and lastIdentifier", () => {
  test("unwrap removes await and one layer of parentheses", () => {
    expect(unwrap("await (db.select())")).toBe("db.select()");
  });

  test("lastIdentifier names the receiver", () => {
    expect(lastIdentifier("this.usersRepository")).toBe("usersRepository");
  });
});
