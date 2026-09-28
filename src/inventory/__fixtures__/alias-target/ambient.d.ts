// This fixture exists to be *read*, not compiled: the point of it is that its
// imports go through the `@/*` alias its own `tsconfig.json` declares, which the
// repository's root `tsconfig.json` knows nothing about. Declaring the two
// specifiers keeps `tsc --noEmit` green without teaching the root config an
// alias that belongs to a fixture.
declare module "@/lib/auth" {
  export function requireAccess(role: string): Promise<{ id: string; role: string }>;
}
declare module "@/lib/opportunities" {
  export function requireBusiness(): Promise<{ business: { id: string } }>;
  export function parseOpportunityForm(form: FormData): { ok: boolean };
}
