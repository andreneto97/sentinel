// @ts-nocheck - a fixture is read as text; the repo's tsconfig has no `jsx` option.

/** Renders a comment body verbatim, and hides the delete button by permission. */
export function CommentBody({ comment, viewer }) {
  const canDelete = viewer.permissions.includes("comment:delete");
  return (
    <article>
      {/* biome-ignore lint/security/noDangerouslySetInnerHtml: the fixture is enumerated as an XSS sink. */}
      <div dangerouslySetInnerHTML={{ __html: comment.html }} />
      {canDelete ? (
        <button
          type="button"
          onClick={() => fetch(`/api/comments/${comment.id}`, { method: "DELETE" })}
        >
          Delete
        </button>
      ) : null}
    </article>
  );
}
