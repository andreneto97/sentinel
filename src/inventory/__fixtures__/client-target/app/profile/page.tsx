// @ts-nocheck - a fixture is read as text; the repo's tsconfig has no `jsx` option.
"use client";

/** A client component whose edit affordance is decided in the browser. */
export default function ProfilePage({ session }) {
  const canEdit = session.user.role === "editor";
  return (
    <main>
      {canEdit ? (
        <a href="/settings" onClick={() => fetch("/api/profile", { method: "PATCH" })}>
          Edit profile
        </a>
      ) : null}
    </main>
  );
}
