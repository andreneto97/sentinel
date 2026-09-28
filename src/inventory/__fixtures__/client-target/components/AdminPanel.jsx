import { RequireRole } from "./RequireRole";

/** The admin panel: three separate browser-side authorization decisions. */
export function AdminPanel({ user, notice }) {
  const isAdmin = user.role === "admin";
  const canPublish = user.permissions.includes("post:publish");

  return (
    <section>
      {/* biome-ignore lint/security/noDangerouslySetInnerHtml: the fixture is enumerated as an XSS sink. */}
      <div dangerouslySetInnerHTML={{ __html: notice }} />
      {isAdmin ? (
        <button type="button" onClick={() => fetch("/api/admin/users", { method: "DELETE" })}>
          Delete every user
        </button>
      ) : null}
      {canPublish ? <PublishButton /> : null}
      {/* biome-ignore lint/a11y/useValidAriaRole: `role` is this component's own prop, not an ARIA role. */}
      <RequireRole role="owner">
        <button type="button" onClick={() => fetch("/api/billing/refund", { method: "POST" })}>
          Refund
        </button>
      </RequireRole>
    </section>
  );
}

function PublishButton() {
  return (
    <button type="button" onClick={() => fetch("/api/posts/publish", { method: "POST" })}>
      Publish
    </button>
  );
}
