import assert from "node:assert/strict";
import { join, sep } from "node:path";
import { test } from "node:test";
import { isAllowedExternalUrl, resolveAppPath } from "./paths";

const root = join(process.cwd(), "frontend", "dist");

test("serves files inside the root", () => {
  assert.equal(resolveAppPath(root, "/index.html"), join(root, "index.html"));
  assert.equal(resolveAppPath(root, "/"), join(root, "index.html"));
  assert.equal(resolveAppPath(root, "/assets/app.js"), join(root, "assets", "app.js"));
});

for (const evil of [
  "/../package.json",
  "/..%2F..%2Fpackage.json",
  "/%2E%2E/%2E%2E/package.json",
  "/assets/../../secret",
  "/%E0%A4%A",
  "/index.html%00.js",
]) {
  test(`rejects ${evil}`, () => {
    assert.equal(resolveAppPath(root, evil), null);
  });
}

// Backslash is a separator only on Windows; elsewhere it is a literal filename character.
// Either way the resolved path must never escape the root.
for (const tricky of ["/..\\..\\secret", "/%5C..%5C..%5Csecret"]) {
  test(`stays inside root: ${tricky}`, () => {
    const r = resolveAppPath(root, tricky);
    assert.ok(r === null || r.startsWith(root + sep), String(r));
  });
}

test("external links: only https on allowlisted documentation hosts", () => {
  assert.ok(isAllowedExternalUrl("https://cwe.mitre.org/data/definitions/319.html"));
  assert.ok(isAllowedExternalUrl("https://owasp.org/API-Security/editions/2023/en/0x11-t10/"));
  for (const bad of [
    "http://owasp.org/",
    "https://owasp.org.evil.example/",
    "https://evil.example/?u=owasp.org",
    "https://user:pw@owasp.org/",
    "https://owasp.org:8443/",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "not a url",
  ]) {
    assert.equal(isAllowedExternalUrl(bad), false, bad);
  }
});
