import { Play, Server } from "lucide-react";
import { useState } from "react";
import type { ReactNode } from "react";
import { AiPanel } from "@/components/AiPanel";
import { EmptyState } from "@/components/EmptyState";
import { EvidenceBlock } from "@/components/EvidenceBlock";
import { FileField } from "@/components/FileField";
import { FilterBar } from "@/components/FilterBar";
import { FindingList } from "@/components/FindingList";
import { CompareView } from "@/components/CompareView";
import { DiffView } from "@/components/DiffView";
import { FixCard } from "@/components/FixCard";
import { ProbeLog } from "@/components/ProbeLog";
import { ScanProgress } from "@/components/ScanProgress";
import { TargetAllowlistForm } from "@/components/TargetAllowlistForm";
import { SummaryStrip } from "@/components/SummaryStrip";
import { Alert } from "@/components/ui/alert";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { NO_FILTERS, type Filters } from "@/lib/findings";
import remediationFixture from "@/test/fixtures/remediation-legacy.json";
import retestFixture from "@/test/fixtures/session-retest.json";
import { FINDING_STATUSES, SEVERITIES, SOURCES, type Finding, type Session } from "@/lib/types";
import { AppearanceControls } from "@/pages/SettingsPage";

/**
 * /dev/components — every component × state (CLAUDE.md §10). Switch theme/density at the
 * top to review each combination and capture thesis screenshots.
 */

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3 border-t border-border pt-6">
      <h2 className="text-lg font-semibold text-fg">{title}</h2>
      {children}
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="w-28 shrink-0 text-sm text-fg-muted">{label}</span>
      {children}
    </div>
  );
}

const SPEC_EXCERPT = `servers:
  - url: http://api.example.com/v1
paths:
  /users:
    get:
      security: []`;

const HTTP_EXCERPT = `GET /v1/users HTTP/1.1
Host: api.example.com
Authorization: ••••

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Server: nginx/1.18.0`;

const FALLBACK =
  "The server URL uses plain HTTP, so credentials and data can be read or modified in transit. Serve the API over HTTPS only.";

function sample(i: number, severity: Finding["severity"], status: Finding["status"]): Finding {
  return {
    id: `sample${i}`,
    rule_id: "NGX-TLS-003",
    title:
      i === 2
        ? "A very long finding title that has to truncate with a tooltip showing the full text in the list"
        : `Sample finding ${i}`,
    category: "Transport security",
    severity,
    status,
    source: i === 1 ? "runtime" : "static",
    evidence: [
      {
        kind: "nginx",
        location: {
          file: "very/long/path/to/sites-available/api.example.com.conf",
          line: 12 + i,
          end_line: null,
          pointer: "/http/0",
          url: null,
        },
        excerpt: "add_header X 1;",
        request: null,
        response: null,
      },
    ],
    references: { owasp_api: ["API8:2023"], cwe: ["CWE-319"], links: [] },
    remediation: {
      template_fix: 'add_header Strict-Transport-Security "max-age=31536000" always;',
      ai_fix: null,
      validated: i === 1,
    },
    ai_explanation: null,
  };
}

const RETEST_COMPARISON = (retestFixture as Session).comparison;
const CRITICAL = sample(0, "critical", "confirmed");
const HIGH = sample(1, "high", "potential");
const SAMPLES: Finding[] = [CRITICAL, HIGH, sample(2, "low", "inconclusive")];

export function DevComponentsPage() {
  const [file, setFile] = useState<File | null>(null);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [selected, setSelected] = useState("sample0");
  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Components" description="Design-system review page (dev builds only)." />
      <AppearanceControls />

      <Section title="Button">
        {(["primary", "secondary", "ghost", "danger"] as const).map((variant) => (
          <Row key={variant} label={variant}>
            <Button variant={variant} size="sm">
              Small
            </Button>
            <Button variant={variant}>Default</Button>
            <Button variant={variant} disabled>
              Disabled
            </Button>
            <Button variant={variant} loading>
              Loading
            </Button>
          </Row>
        ))}
        <Row label="icon">
          <Button variant="ghost" size="icon" aria-label="Start scan">
            <Play aria-hidden className="size-4" />
          </Button>
        </Row>
      </Section>

      <Section title="Input">
        <div className="grid grid-cols-2 gap-4">
          <Input label="Base URL" placeholder="https://api.example.com" mono />
          <Input label="With helper" helper="Only hosts on your allowlist can be probed." />
          <Input
            label="With error"
            defaultValue="ftp://nope"
            error="URL must use http or https."
            mono
          />
          <Input label="Disabled" disabled defaultValue="Disabled" />
          <Input label="Read-only" readOnly defaultValue="127.0.0.1" mono />
        </div>
      </Section>

      <Section title="SeverityBadge">
        <Row label="all">
          {SEVERITIES.map((s) => (
            <SeverityBadge key={s} severity={s} />
          ))}
        </Row>
      </Section>

      <Section title="StatusBadge & SourceTag">
        <Row label="status">
          {FINDING_STATUSES.map((s) => (
            <StatusBadge key={s} status={s} />
          ))}
        </Row>
        <Row label="source">
          {SOURCES.map((s) => (
            <SourceTag key={s} source={s} />
          ))}
        </Row>
      </Section>

      <Section title="EvidenceBlock">
        <EvidenceBlock
          variant="code"
          content={SPEC_EXCERPT}
          location="specs/petstore.yaml"
          startLine={4}
          highlight={[5]}
        />
        <EvidenceBlock
          variant="http"
          content={HTTP_EXCERPT}
          location="https://api.example.com/v1/users"
        />
        <EvidenceBlock
          variant="config"
          content={"server {\n    listen 80;\n    server_tokens on;\n    autoindex on;\n}"}
          location="C:/very/long/path/to/some/deeply/nested/directory/structure/that/keeps/going/nginx.conf"
          startLine={12}
          highlight={[14, 15]}
        />
      </Section>

      <Section title="AiPanel">
        <AiPanel state="collapsed" fallback={FALLBACK} />
        <AiPanel state="loading" fallback={FALLBACK} />
        <AiPanel
          state="ready"
          text="Because the spec declares an http:// server, clients following the documentation will send bearer tokens unencrypted."
          model="qwen3:4b"
          promptVersion="explain-v1"
          fallback={FALLBACK}
          onRegenerate={() => undefined}
        />
        <AiPanel state="unavailable" fallback={FALLBACK} />
        <AiPanel
          state="error"
          errorMessage="model output failed validation"
          fallback={FALLBACK}
          onRegenerate={() => undefined}
        />
      </Section>

      <Section title="FileField">
        <div className="grid grid-cols-2 gap-4">
          <FileField
            label="OpenAPI spec"
            accept=".yaml,.yml,.json"
            file={file}
            onChange={setFile}
            helper="Selected / empty states"
          />
          <FileField
            label="With error"
            accept=".conf"
            file={null}
            onChange={() => undefined}
            error="File is larger than 5 MB."
          />
          <FileField
            label="Disabled"
            accept=".conf"
            file={null}
            onChange={() => undefined}
            disabled
          />
        </div>
      </Section>

      <Section title="Alert">
        <Alert tone="info" title="Some configuration was not visible">
          snippets/security-headers.conf (line 7) was not analyzed.
        </Alert>
        <Alert
          tone="warning"
          title="Partial results: 1 of 2 inputs could not be analyzed"
          action={
            <Button variant="secondary" size="sm">
              Retry
            </Button>
          }
        />
        <Alert tone="danger" title="The scan failed">
          {"bad.conf: line 1: unexpected '}'"}
        </Alert>
      </Section>

      <Section title="SummaryStrip, FilterBar & FindingList">
        <SummaryStrip findings={SAMPLES} />
        <SummaryStrip findings={[]} />
        <FilterBar filters={filters} onChange={setFilters} />
        <FindingList findings={SAMPLES} selectedId={selected} onSelect={setSelected} />
      </Section>

      <Section title="FixCard">
        <FixCard remediation={CRITICAL.remediation} ruleId="NGX-TLS-003" />
        <FixCard remediation={HIGH.remediation} ruleId="NGX-TLS-003" />
        <FixCard remediation={{ template_fix: null, ai_fix: null, validated: false }} ruleId="X" />
      </Section>

      <Section title="DiffView & CompareView">
        <DiffView diff={remediationFixture.diff} filename="legacy-tls.conf" />
        <DiffView diff="" filename="unchanged.conf" />
        {RETEST_COMPARISON && <CompareView comparison={RETEST_COMPARISON} />}
      </Section>

      <Section title="ScanProgress">
        <ScanProgress
          stage="static"
          hasRuntime
          current="petstore.yaml"
          runtime={null}
          onStop={() => undefined}
        />
        <ScanProgress
          stage="runtime"
          hasRuntime
          current="https://api.example.com/"
          runtime={{ scanId: 1, done: 5, total: 13, current: "GET /.git/HEAD", stopping: false }}
          onStop={() => undefined}
        />
        <ScanProgress
          stage="runtime"
          hasRuntime
          current="https://api.example.com/"
          runtime={{ scanId: 1, done: 6, total: 13, current: "GET /.env", stopping: true }}
          onStop={() => undefined}
        />
      </Section>

      <Section title="TargetAllowlistForm & ProbeLog">
        <TargetAllowlistForm onAdded={() => undefined} />
        <ProbeLog scanId={-1} />
      </Section>

      <Section title="Skeleton & EmptyState">
        <div className="flex flex-col gap-2">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-2/3" />
        </div>
        <EmptyState
          icon={Server}
          title="No targets yet"
          description="Add a host you own or have written permission to test."
          action={<Button>Add target</Button>}
        />
      </Section>
    </div>
  );
}
