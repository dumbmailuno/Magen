import { ExternalLink } from "lucide-react";
import type { ReactNode } from "react";
import { EvidenceBlock, type EvidenceVariant } from "@/components/EvidenceBlock";
import { FixCard } from "@/components/FixCard";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatLocation } from "@/lib/findings";
import type { Evidence, Finding, RuleInfo } from "@/lib/types";

const VARIANT: Record<Evidence["kind"], EvidenceVariant> = {
  openapi: "code",
  nginx: "config",
  http: "http",
  tls: "http",
};

const STATUS_NOTE: Record<Finding["status"], string> = {
  confirmed: "Confirmed by static and runtime evidence.",
  potential: "Found in the spec or config; not yet confirmed against the running system.",
  inconclusive:
    "Part of the configuration was not visible (an include or the main config), so this may already be handled elsewhere.",
};

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-sm font-medium uppercase tracking-wide text-fg-muted">{title}</h3>
      {children}
    </section>
  );
}

function hostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function cweUrl(cwe: string): string {
  return `https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`;
}

/** Evidence first, then why it matters, then the fix, then references (design-system §1). */
export function FindingDetail({
  finding,
  rule,
}: {
  finding: Finding;
  rule: RuleInfo | null | undefined;
}) {
  return (
    <article aria-labelledby="finding-title" className="flex flex-col gap-6">
      <header className="flex flex-col gap-2">
        <h2 id="finding-title" className="text-lg font-semibold text-fg">
          {finding.title}
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <SourceTag source={finding.source} />
          <span className="font-mono text-xs text-fg-muted">{finding.rule_id}</span>
          <span className="text-xs text-fg-muted">· {finding.category}</span>
        </div>
        <p className="text-sm text-fg-muted">{STATUS_NOTE[finding.status]}</p>
      </header>

      <Section title="Evidence">
        {finding.evidence.map((ev, i) => (
          <EvidenceBlock
            key={i}
            variant={VARIANT[ev.kind]}
            content={ev.excerpt}
            location={formatLocation(ev.location)}
            {...(ev.location.line !== null
              ? { startLine: ev.location.line, highlight: [ev.location.line] }
              : {})}
          />
        ))}
      </Section>

      <Section title="Why it matters">
        {rule === undefined ? (
          <div className="flex flex-col gap-2" aria-hidden>
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-4/5" />
          </div>
        ) : (
          <p className="text-base text-fg">
            {rule?.description ?? "Rule description unavailable."}
          </p>
        )}
      </Section>

      <Section title="Fix">
        <FixCard remediation={finding.remediation} ruleId={finding.rule_id} />
        <p className="text-xs text-fg-muted">
          Magen never edits your files. Apply the fix yourself, then retest.
        </p>
      </Section>

      <Section title="References">
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {finding.references.owasp_api.map((o) => (
            <li key={o} className="font-mono text-fg">
              OWASP {o}
            </li>
          ))}
          {finding.references.cwe.map((c) => (
            <li key={c}>
              <a
                className="inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline"
                href={cweUrl(c)}
                target="_blank"
                rel="noreferrer"
              >
                {c}
                <ExternalLink aria-hidden className="size-3" />
                <span className="sr-only">(opens in browser)</span>
              </a>
            </li>
          ))}
          {finding.references.links.map((l) => (
            <li key={l} className="min-w-0">
              <a
                className="inline-flex items-center gap-1 break-all text-accent underline-offset-2 hover:underline"
                href={l}
                target="_blank"
                rel="noreferrer"
              >
                {hostname(l)}
                <ExternalLink aria-hidden className="size-3" />
                <span className="sr-only">(opens in browser)</span>
              </a>
            </li>
          ))}
        </ul>
      </Section>
    </article>
  );
}
