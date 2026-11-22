import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";
import { countBy } from "@/lib/findings";
import { FINDING_STATUSES, SEVERITIES, type Finding } from "@/lib/types";

/** Counts by severity and status. Numbers are text, badges carry icon + label. */
export function SummaryStrip({ findings }: { findings: readonly Finding[] }) {
  const bySev = countBy(findings, (f) => f.severity);
  const byStatus = countBy(findings, (f) => f.status);
  return (
    <section
      aria-label="Summary"
      className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-md border border-border bg-surface p-4"
    >
      <p className="text-2xl font-semibold tabular-nums text-fg">
        {findings.length}
        <span className="ml-2 text-base font-normal text-fg-muted">
          {findings.length === 1 ? "finding" : "findings"}
        </span>
      </p>
      <ul className="flex flex-wrap items-center gap-3" aria-label="By severity">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center gap-1">
            <SeverityBadge severity={s} />
            <span className="text-base font-medium tabular-nums text-fg">{bySev.get(s) ?? 0}</span>
          </li>
        ))}
      </ul>
      <ul className="flex flex-wrap items-center gap-3" aria-label="By status">
        {FINDING_STATUSES.map((s) => (
          <li key={s} className="flex items-center gap-1">
            <StatusBadge status={s} />
            <span className="text-base font-medium tabular-nums text-fg">
              {byStatus.get(s) ?? 0}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
