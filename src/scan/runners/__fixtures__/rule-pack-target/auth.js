// Intentionally vulnerable corpus for the Sentinel opengrep rule pack.

import crypto from "node:crypto";
import jwt from "jsonwebtoken";

/** appsec.auth.jwt-algorithm-none */
export function verifyLoose(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256", "none"] });
}

/** appsec.auth.jwt-hardcoded-secret */
export function signSession(payload) {
  return jwt.sign(payload, "super-secret-dev-key", { expiresIn: "7d" });
}

/** SAFE: the secret comes from the environment. */
export function verifyStrict(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["RS256"] });
}

/** appsec.crypto.weak-password-hash */
export function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

/** appsec.crypto.insecure-random-token */
export function issueResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

/** SAFE: a jitter value is not a secret. */
export function backoffJitter() {
  const delay = Math.random() * 100;
  return delay;
}

/** appsec.crypto.deprecated-create-cipher */
export function encryptLegacy(plaintext, passphrase) {
  const cipher = crypto.createCipher("aes-256-cbc", passphrase);
  return cipher.update(plaintext, "utf8", "hex") + cipher.final("hex");
}

/** appsec.auth.insecure-cookie-flags */
export function loginHandler(req, res) {
  res.cookie("session", req.body.token, { maxAge: 86400000 });
  res.end();
}

/** SAFE: every flag is set. */
export function loginHandlerHardened(req, res) {
  res.cookie("session", req.body.token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 86400000,
  });
  res.end();
}
