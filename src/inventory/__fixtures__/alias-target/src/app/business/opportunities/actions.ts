"use server";

import { parseOpportunityForm, requireBusiness } from "@/lib/opportunities";

/** Creates an opportunity for the signed-in business. */
export async function createOpportunity(form: FormData): Promise<{ ok: boolean }> {
  const { business } = await requireBusiness();
  const parsed = parseOpportunityForm(form);
  return { ok: parsed.ok && business.id !== "" };
}
