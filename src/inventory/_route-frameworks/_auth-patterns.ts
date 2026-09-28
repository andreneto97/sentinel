/**
 * What an authentication check looks like in source.
 *
 * Its own module because two callers need the same answer about the same text
 * and neither can own it. `_handler-facts.ts` asks "does this handler body
 * contain a guard, and on which line" to fill `authCheck`; `_shared.ts` asks
 * "does this imported file contain a guard at all" to decide whether a symbol
 * imported from it *is* a guard. Putting the patterns in either one would make
 * the other import it, and a cycle between two modules of the same directory is
 * the kind of thing `dependency-cruiser` reports about the repository Sentinel
 * is auditing.
 *
 * The lists are deliberately open at one end. {@link AUTH_CALLS} is the closed
 * set of names the ecosystem already agreed on; {@link AUTH_SHAPED} plus
 * {@link AUTH_SUBJECTS} is the shape a codebase invents its own guard in. A
 * project's `requireBusiness()` matches neither — which is what
 * {@link containsAuthCheck} is for: the symbol is resolved to the file that
 * defines it, and that file is asked whether it authenticates.
 */

/** Guards that are recognisable wherever they appear, with or without arguments. */
export const AUTH_CALLS =
  /\b(?:getServerSession|getServerAuthSession|unstable_getServerSession|requireUser|requireAuth|requireSession|requireRole|requireAdmin|requireOwner|requireTenant|requirePermission|ensureAuthenticated|ensureUser|ensureSession|assertAuthenticated|assertUser|assertRole|assertOwner|assertPermission|isAuthenticated|authenticateRequest|authorizeRequest|verifyToken|verifyJwt|verifySession|verifyAuth|checkAuth|checkPermission|checkRole|validateSession|validateToken|getCurrentUser|getViewer|getPrincipal|withAuth|clerkMiddleware)\s*\(/;

/** Guards that only mean "authentication" when called with no arguments at all. */
export const AUTH_NULLARY =
  /\b(?:auth|getSession|getUser|currentUser|getAuth|getToken|useSession)\s*\(\s*\)/;

/** Library-specific checks whose shape is unmistakable. */
export const AUTH_LIBRARY: readonly RegExp[] = [
  /\bsupabase\s*\.\s*auth\s*\.\s*(?:getUser|getSession|getClaims)\s*\(/,
  /\bjwt\s*\.\s*verify\s*\(/,
  /\bjwtVerify\s*\(/,
  /\bpassport\s*\.\s*authenticate\s*\(/,
  /@UseGuards\s*\([^)]*\)/,
  /\bauth\s*\(\s*\)\s*\.\s*protect\s*\(/,
];

/**
 * A hand-rolled guard: a `require*`/`assert*`/`verify*` call whose name is
 * about identity. Named separately from {@link AUTH_CALLS} because the list of
 * names a codebase invents is open, and the shape is not.
 */
export const AUTH_SHAPED =
  /\b((?:require|ensure|assert|check|verify|validate|guard)[A-Z][\w$]*)\s*\(/g;

/** Words that make a `require*`-shaped call an authentication check. */
export const AUTH_SUBJECTS =
  /(?:Auth|User|Session|Role|Perm|Access|Owner|Admin|Tenant|Member|Token|Login|Signed|Principal|Viewer|Account|Identity)/;

/**
 * True when this source authenticates somewhere in it.
 *
 * A whole-file question, not a per-line one: the caller is deciding whether the
 * module it is looking at is one that authenticates, so where in the file the
 * check sits does not matter. `AUTH_SHAPED` is re-created rather than reused so
 * the shared global regex's `lastIndex` cannot leak between callers.
 */
export function containsAuthCheck(source: string): boolean {
  if (AUTH_CALLS.test(source)) return true;
  if (AUTH_NULLARY.test(source)) return true;
  if (AUTH_LIBRARY.some((pattern) => pattern.test(source))) return true;
  const shaped = new RegExp(AUTH_SHAPED.source, "g");
  let match = shaped.exec(source);
  while (match !== null) {
    const name = match[1];
    if (name !== undefined && AUTH_SUBJECTS.test(name)) return true;
    match = shaped.exec(source);
  }
  return false;
}
