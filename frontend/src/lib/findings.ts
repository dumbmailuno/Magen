import {
  FINDING_STATUSES,
  SEVERITIES,
  SEVERITY_RANK,
  SOURCES,
  type Finding,
  type FindingStatus,
  type Location,
  type Severity,
  type Source,
} from "./types";

/** Mirror of backend Location.key(): file, zero-padded line, end line, pointer, url. */
function locationKey(loc: Location): string {
  const line = String(loc.line ?? 0).padStart(8, "0");
  return [loc.file ?? "", line, String(loc.end_line ?? ""), loc.pointer ?? "", loc.url ?? ""].join(
    "|",
  );
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Canonical order, identical to backend sort_findings: severity desc, rule id, first
 * location, id. Used when merging results from several inputs. Duplicate ids collapse.
 */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const f of findings) if (!unique.has(f.id)) unique.set(f.id, f);
  const firstLoc = (f: Finding) => f.evidence.map((e) => locationKey(e.location)).sort()[0] ?? "";
  return [...unique.values()].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      cmp(a.rule_id, b.rule_id) ||
      cmp(firstLoc(a), firstLoc(b)) ||
      cmp(a.id, b.id),
  );
}

export interface Filters {
  severity: Severity[];
  status: FindingStatus[];
  source: Source[];
}

export const NO_FILTERS: Filters = { severity: [], status: [], source: [] };

export function applyFilters(findings: readonly Finding[], f: Filters): Finding[] {
  return findings.filter(
    (x) =>
      (f.severity.length === 0 || f.severity.includes(x.severity)) &&
      (f.status.length === 0 || f.status.includes(x.status)) &&
      (f.source.length === 0 || f.source.includes(x.source)),
  );
}

function pick<T extends string>(raw: string | null, allowed: readonly T[]): T[] {
  if (!raw) return [];
  const set = new Set(raw.split(","));
  return allowed.filter((a) => set.has(a));
}

/** Filters live in the URL (`?sev=high,low&status=potential&source=static`). */
export function filtersFromParams(params: URLSearchParams): Filters {
  return {
    severity: pick(params.get("sev"), SEVERITIES),
    status: pick(params.get("status"), FINDING_STATUSES),
    source: pick(params.get("source"), SOURCES),
  };
}

export function filtersToParams(f: Filters, params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  const set = (key: string, values: string[]) => {
    if (values.length) next.set(key, values.join(","));
    else next.delete(key);
  };
  set("sev", f.severity);
  set("status", f.status);
  set("source", f.source);
  return next;
}

export function countBy<K extends string>(findings: readonly Finding[], key: (f: Finding) => K) {
  const out = new Map<K, number>();
  for (const f of findings) out.set(key(f), (out.get(key(f)) ?? 0) + 1);
  return out;
}

/** "nginx.conf:12" / "spec.yaml:4-9" / pointer when there is no line. */
export function formatLocation(loc: Location): string {
  const file = loc.file ?? loc.url ?? "";
  if (loc.line === null) return loc.pointer ? `${file} ${loc.pointer}` : file;
  return `${file}:${loc.line}${loc.end_line ? `-${loc.end_line}` : ""}`;
}
