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
