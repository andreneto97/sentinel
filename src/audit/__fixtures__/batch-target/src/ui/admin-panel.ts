/**
 * A client-side role gate: it hides a destructive control from a viewer, and the
 * endpoint behind it is what the audit has to be shown to judge the gate.
 */

/** The caller as the client knows it. */
export interface ClientUser {
  readonly role: string;
}

/** Renders a link, as the fixture's fake view layer would. */
export function link(label: string, href: string): string {
  return `${label} -> ${href}`;
}

/** Shows the delete control only to an admin. */
export function adminPanel(user: ClientUser, orderId: string): string {
  const controls: string[] = [link("orders", "/api/orders")];
  if (user.role === "admin") {
    controls.push(link("delete order", `/api/orders/${orderId}`));
  }
  return controls.join("\n");
}
