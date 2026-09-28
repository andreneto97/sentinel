/**
 * Test support for the fixture repository's auth middleware.
 *
 * It exists so `normalise.test.ts` can grade a finding that cites a file which
 * really sits in `__tests__/`, with a snippet Sentinel reads off disk. The
 * literal below is the shape a secret scanner grades `critical` and the file-kind
 * policy caps: a signing secret that is a unit-test fixture and forges nothing.
 */

/** The signing secret the middleware tests hand to the handler under test. */
const TEST_JWT_SECRET = "test";

/** A signature a test can present; deliberately not a real JWT implementation. */
export function signTestToken(sub: string): string {
  return `${sub}.${TEST_JWT_SECRET}`;
}
