// Intentionally vulnerable corpus for the Sentinel opengrep rule pack.

/** appsec.xss.dangerously-set-inner-html */
export function Article({ article }) {
  // biome-ignore lint/security/noDangerouslySetInnerHtml: intentionally vulnerable fixture
  return <div dangerouslySetInnerHTML={{ __html: article.body }} />;
}

/** SAFE: JSX escapes interpolated text. */
export function Title({ article }) {
  return <h1>{article.title}</h1>;
}
