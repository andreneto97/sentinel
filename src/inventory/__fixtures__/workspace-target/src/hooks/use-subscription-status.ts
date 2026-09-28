/** A client hook under `hooks/`, which the path filter must not offer as a candidate. */
export function useSubscriptionStatus(id: string): { readonly id: string; readonly live: boolean } {
  return { id, live: id !== "" };
}
