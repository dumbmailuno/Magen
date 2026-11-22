/**
 * Mirror of backend/app/models/finding.py (CLAUDE.md §5).
 * The backend test `test_committed_json_schema_is_current` guards docs/finding.schema.json;
 * when it changes, update this file in the same commit.
 */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = ["confirmed", "potential", "inconclusive"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const SOURCES = ["static", "runtime", "correlated"] as const;
export type Source = (typeof SOURCES)[number];

export type EvidenceKind = "openapi" | "nginx" | "http" | "tls";

export interface Location {
  file: string | null;
  line: number | null;
  end_line: number | null;
  pointer: string | null;
  url: string | null;
}

export interface Evidence {
  kind: EvidenceKind;
  location: Location;
  excerpt: string;
  request: string | null;
  response: string | null;
}

export interface References {
  owasp_api: string[];
  cwe: string[];
  links: string[];
}

export interface Remediation {
  template_fix: string | null;
  ai_fix: string | null;
  validated: boolean;
}

export interface AiExplanation {
  text: string;
  model: string;
  prompt_version: string;
  generated_at: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  source: Source;
  evidence: Evidence[];
  references: References;
  remediation: Remediation;
  ai_explanation: AiExplanation | null;
}

/** Error shape returned by every failing endpoint. */
export interface ApiErrorBody {
  code: string;
  message: string;
  detail: unknown;
}

export interface Health {
  status: string;
  version: string;
  commit: string;
  generated_by: string;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Mirror of backend app/api/meta.py RuleInfo. */
export interface RuleInfo {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  target: "openapi" | "nginx" | "runtime";
  description: string;
  references: References;
  deprecated: boolean;
}

/** Mirror of backend app/api/analyze.py OpenApiResult. */
export interface OpenApiResult {
  generated_by: string;
  source_name: string;
  openapi_version: string;
  operation_count: number;
  rules_run: string[];
  findings: Finding[];
}

/** Mirror of backend app/api/analyze.py NginxResult. */
export interface NginxResult {
  generated_by: string;
  source_name: string;
  server_count: number;
  is_snippet: boolean;
  unresolved_includes: { path: string; line: number }[];
  rules_run: string[];
  findings: Finding[];
}

export type InputKind = "openapi" | "nginx";
