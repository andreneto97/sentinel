/** One subscription filter condition. */
export type FilterCondition = string | { readonly prefix: string };

/** What a condition compiles to. */
export interface ConditionMatcher {
  matches(value: string): boolean;
}

const discriminatorKey = (condition: FilterCondition): string =>
  typeof condition === "string" ? "literal" : (Object.keys(condition)[0] ?? "unknown");

const strategies = new Map<string, (condition: FilterCondition) => ConditionMatcher>([
  ["literal", (c) => ({ matches: (value) => value === String(c) })],
  ["prefix", (c) => ({ matches: (value) => value.startsWith(String(c)) })],
]);

/**
 * Domain logic under a webhook-shaped path, and the reason the route marker
 * requires a quoted path: `strategies.get(key)` is a `Map` read, and a marker
 * that accepted a bare `.get(` would read it as an HTTP entry point.
 */
export const matcherFor = (condition: FilterCondition): ConditionMatcher => {
  const creator = strategies.get(discriminatorKey(condition));
  if (creator === undefined) throw new Error("unknown filter condition");
  return creator(condition);
};
