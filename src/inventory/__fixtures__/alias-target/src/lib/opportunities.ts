/**
 * A domain guard that delegates one hop to the auth helper.
 *
 * Its name is about a domain role, not about identity, so no name pattern
 * recognises it; the file it lives in is not the auth helper either.
 */
import { requireAccess } from "@/lib/auth";

/** The signed-in business, or throws. */
export async function requireBusiness(): Promise<{ business: { id: string } }> {
  const principal = await requireAccess("business");
  return { business: { id: principal.id } };
}

/** Parses the form; nothing to do with identity. */
export function parseOpportunityForm(form: FormData): { ok: boolean } {
  return { ok: form.has("title") };
}
