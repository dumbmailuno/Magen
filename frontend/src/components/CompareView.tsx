import { CircleCheck, CirclePlus, Radio, Repeat, type LucideIcon } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";
import type { Comparison, Finding } from "@/lib/types";

function Column({
  title,
  icon: Icon,
  findings,
  empty,
  tone,
}: {
  title: string;
  icon: LucideIcon;
  findings: Finding[];
  empty: string;
  tone: string;
}) {
  return (
    <section
      aria-label={title}
      className="flex min-w-0 flex-col gap-2 rounded-md border border-border bg-surface p-4"
    >
      <h3 className="flex items-center gap-2 text-base font-semibold text-fg">
        <Icon aria-hidden className={`size-4 ${tone}`} />
        {title}
        <span className="ml-auto text-2xl font-semibold tabular-nums">{findings.length}</span>
      </h3>
      {findings.length === 0 ? (
        <p className="text-sm text-fg-muted">{empty}</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {findings.map((f) => (
            <li key={f.id} className="flex flex-col gap-1 border-t border-border pt-2">
              <span className="truncate text-sm text-fg" title={f.title}>
                {f.title}
              </span>
              <span className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <StatusBadge status={f.status} />
                <span className="font-mono text-xs text-fg-muted">{f.rule_id}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Retest result: resolved / persists / new, with the remediation rate (design-system §8). */
export function CompareView({ comparison }: { comparison: Comparison }) {
  const rate = comparison.remediation_rate;
  return (
    <div className="flex flex-col gap-4">
      <p className="text-base text-fg" role="status">
        {rate === null
          ? "The baseline had no findings."
          : `${Math.round(rate * 100)}% of baseline findings resolved (${comparison.resolved.length} of ${comparison.resolved.length + comparison.persists.length}).`}
        {comparison.changed_inputs.length > 0 && (
          <span className="text-fg-muted">
            {" "}
            Changed inputs: {comparison.changed_inputs.join(", ")}.
          </span>
        )}
      </p>
      {comparison.still_observed.length > 0 && (
        <Alert
          tone="warning"
          title="Fixed in the config, but still observed live — not redeployed yet?"
        >
          <ul className="flex flex-col gap-1">
            {comparison.still_observed.map((f) => (
              <li key={f.id} className="flex items-center gap-2">
                <Radio aria-hidden className="size-3.5 shrink-0" />
                <span className="font-mono text-xs">{f.rule_id}</span> {f.title}
              </li>
            ))}
          </ul>
          <p className="mt-1">
            These count as persisting until the running system no longer shows them.
          </p>
        </Alert>
      )}
      <div className="grid gap-4 split:grid-cols-3">
        <Column
          title="Resolved"
          icon={CircleCheck}
          tone="text-success"
          findings={comparison.resolved}
          empty="Nothing resolved yet."
        />
        <Column
          title="Persists"
          icon={Repeat}
          tone="text-fg-muted"
          findings={comparison.persists}
          empty="Nothing carried over."
        />
        <Column
          title="New"
          icon={CirclePlus}
          tone="text-warning"
          findings={comparison.new}
          empty="No new findings."
        />
      </div>
      {comparison.status_changes.length > 0 && (
        <section
          aria-label="Status changes"
          className="rounded-md border border-border bg-surface p-4"
        >
          <h3 className="mb-2 text-sm font-medium text-fg-muted">Status changes</h3>
          <ul className="flex flex-col gap-1 text-sm">
            {comparison.status_changes.map((c) => (
              <li key={c.finding_id}>
                <span className="font-mono text-xs text-fg-muted">{c.rule_id}</span> {c.title}:{" "}
                {c.before} → {c.after}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
