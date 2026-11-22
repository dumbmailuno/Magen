import { isAbsolute, join, normalize, relative } from "node:path";

/**
 * Map an app:// URL pathname to a file inside `root`, or `null` if it would escape `root`
 * (path traversal, encoded or not). Pure so it can be unit-tested without Electron.
 */
export function resolveAppPath(root: string, pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null; // malformed percent-encoding
  }
  if (decoded.includes("\0")) return null;
  const target = normalize(join(root, decoded === "/" || decoded === "" ? "index.html" : decoded));
  const rel = relative(root, target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return null;
  return target;
}

/** Documentation hosts that finding references may open in the system browser. */
export const EXTERNAL_DOC_HOSTS: readonly string[] = [
  "owasp.org",
  "cwe.mitre.org",
  "nginx.org",
  "spec.openapis.org",
  "www.rfc-editor.org",
  "ssl-config.mozilla.org",
  "portswigger.net",
];

/** True only for https URLs on an allowlisted documentation host (no credentials, no ports). */
export function isAllowedExternalUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    EXTERNAL_DOC_HOSTS.includes(url.hostname)
  );
}
