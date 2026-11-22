import { Play, Server } from "lucide-react";
import type { ReactNode } from "react";
import { AiPanel } from "@/components/AiPanel";
import { EmptyState } from "@/components/EmptyState";
import { EvidenceBlock } from "@/components/EvidenceBlock";
import { PageHeader } from "@/components/layout/PageHeader";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { FINDING_STATUSES, SEVERITIES, SOURCES } from "@/lib/types";
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

export function DevComponentsPage() {
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
