// Intentionally vulnerable corpus for the Sentinel opengrep rule pack.

// biome-ignore lint/nursery/noRestrictedImports: an intentionally vulnerable fixture, never loaded by Sentinel
import { execSync } from "node:child_process";
import cors from "cors";
import express from "express";

const app = express();

/** appsec.cors.reflects-any-origin-with-credentials */
app.use(cors({ origin: true, credentials: true }));

/** delivery.express.body-parser-without-limit */
app.use(express.json());

/** appsec.injection.child-process-in-request-handler */
app.get("/export", (req, res) => {
  const output = execSync("pg_dump mydb");
  res.send(output);
});

/** delivery.node.tls-verification-disabled */
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

/** delivery.express.missing-helmet — this app never mounts helmet. */
app.listen(3000);

/** appsec.cors.wildcard-origin */
export function publicHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
}
