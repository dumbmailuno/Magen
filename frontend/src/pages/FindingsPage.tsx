import {
  CircleCheck,
  GitCompare,
  ListChecks,
  Play,
  RefreshCw,
  RotateCcw,
  SearchX,
} from "lucide-react";
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { FilterBar } from "@/components/FilterBar";
import { FindingDetail } from "@/components/FindingDetail";
import { FindingList } from "@/components/FindingList";
import { PageHeader } from "@/components/layout/PageHeader";
import { ProbeLog } from "@/components/ProbeLog";
import { RemediationPanel } from "@/components/RemediationPanel";
import { ScanProgress } from "@/components/ScanProgress";
import { SummaryStrip } from "@/components/SummaryStrip";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  applyFilters,
  filtersFromParams,
  filtersToParams,
  NO_FILTERS,
  type Filters,
} from "@/lib/findings";
import { useRules } from "@/lib/rules";
import { useScan, type StaticInput } from "@/lib/scan";
import type { Finding, RuntimeScan, Session } from "@/lib/types";

function Coverage({
  session,
  runtime,
  runtimeError,
  onRetry,
}: {
  session: Session;
  runtime: RuntimeScan | null;
  runtimeError: string | null;
  onRetry: () => void;
}) {
  const failed = session.inputs.filter((i) => !i.ok);
  const notes = [
    ...session.inputs.flatMap((i) => i.notes),
    ...session.runtime_notes,
    ...(runtime?.notes ?? []),
  ];
  const hidden = session.inputs.some((i) => i.notes.length > 0);
  return (
    <>
      {(failed.length > 0 || runtimeError) && (
        <Alert
          tone="warning"
          title="Partial results: some inputs could not be analyzed"
          action={
            <Button variant="secondary" size="sm" onClick={onRetry}>
              <RefreshCw aria-hidden className="size-4" />
              Retry
            </Button>
          }
        >
          <ul>
            {failed.map((i) => (
              <li key={i.filename}>
                <span className="font-mono">{i.filename}</span>: {i.error}
              </li>
            ))}
            {runtimeError && (
              <li>
                <span className="font-mono">Runtime scan</span>: {runtimeError}
              </li>
            )}
          </ul>
        </Alert>
      )}
      {notes.length > 0 && (
        <Alert tone="info" title="Coverage notes">
          <ul>
            {notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          {hidden && (
            <p className="mt-1">
              Findings that depend on configuration Magen could not see are marked Inconclusive.
            </p>
          )}
        </Alert>
      )}
    </>
  );
}

function Correlation({ session }: { session: Session }) {
  if (session.runtime_scan_id === null) return null;
  const c = session.correlation;
  return (
    <p className="text-sm text-fg-muted" role="status">
      Correlation: <span className="font-medium text-fg">{c.confirmed}</span> static findings
      confirmed at runtime · <span className="font-medium text-fg">{c.contradicted}</span> not
      observed at runtime · <span className="font-medium text-fg">{c.runtime_only}</span>{" "}
      runtime-only · <span className="font-medium text-fg">{c.static_only}</span> static-only
    </p>
  );
}

function Retest({ session }: { session: Session }) {
  const c = session.comparison;
  if (!c) return null;
  return (
    <Alert
      tone="info"
      title={`Retest against session #${c.baseline_id}: ${c.resolved.length} resolved · ${c.persists.length} persist · ${c.new.length} new`}
      action={
        <Button asChild variant="secondary" size="sm">
          <Link to={`/compare?base=${c.baseline_id}&head=${c.current_id}`}>
            <GitCompare aria-hidden className="size-4" />
            Compare
          </Link>
        </Button>
      }
    >
      {c.remediation_rate !== null &&
        `${Math.round(c.remediation_rate * 100)}% of the baseline's findings are resolved.`}
    </Alert>
  );
}

function sourceFor(f: Finding, statics: StaticInput[]): StaticInput | undefined {
  const file = f.evidence[0]?.location.file;
  return file ? statics.find((s) => s.filename.replace(/\\/g, "/") === file) : undefined;
}

export function FindingsPage() {
  const { state, retry, stop } = useScan();
  const rules = useRules();
  const [params, setParams] = useSearchParams();
  const paramString = params.toString();
  const filters = useMemo(() => filtersFromParams(new URLSearchParams(paramString)), [paramString]);
  const all = useMemo(
    () => (state.phase === "done" ? (state.session?.findings ?? []) : []),
    [state],
  );
  const visible = useMemo(() => applyFilters(all, filters), [all, filters]);
  const selectedParam = params.get("f");
  const selected = visible.find((f) => f.id === selectedParam) ?? visible[0] ?? null;

  const setFilters = (f: Filters) => {
    setParams(filtersToParams(f, params), { replace: true });
  };
  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("f", id);
    setParams(next, { replace: true });
  };

  if (state.phase === "idle") {
    return (
      <>
        <PageHeader title="Findings" />
        <EmptyState
          icon={ListChecks}
          title="No scan yet"
          description="Run a scan of an OpenAPI spec, an Nginx config or a live API to see findings here."
          action={
            <Button asChild>
              <Link to="/scan">
                <Play aria-hidden className="size-4" />
                New scan
              </Link>
            </Button>
          }
        />
      </>
    );
  }

  if (state.phase === "running") {
    return (
      <div className="flex flex-col gap-4">
        <PageHeader title="Findings" />
        <ScanProgress
          stage={state.stage}
          hasStatic={state.inputs.some((i) => i.kind !== "runtime")}
          hasRuntime={state.inputs.some((i) => i.kind === "runtime")}
          current={state.current}
          runtime={state.runtime}
          onStop={() => void stop()}
        />
        <div className="flex flex-col gap-2" aria-hidden>
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      </div>
    );
  }

  const { session, runtime, runtimeError } = state;
  if (!session) {
    return (
      <>
        <PageHeader title="Findings" />
        <Alert
          tone="danger"
          title="The scan failed"
          action={
            <Button variant="secondary" size="sm" onClick={() => void retry()}>
              <RefreshCw aria-hidden className="size-4" />
              Retry
            </Button>
          }
        >
          {state.error ?? runtimeError ?? "No inputs could be analyzed."}
        </Alert>
      </>
    );
  }

  const statics = state.request.inputs.filter((i): i is StaticInput => i.kind !== "runtime");
  const fixable = statics.filter(
    (s) =>
      session.inputs.some((i) => i.filename === s.filename && i.ok) &&
      all.some((f) => sourceFor(f, [s])),
  );
  const sources = [
    ...session.inputs.filter((i) => i.ok).map((i) => i.filename),
    ...(runtime?.base_url ? [runtime.base_url] : []),
  ];
  const newIds = new Set(session.comparison?.new.map((f) => f.id) ?? []);
  const allFailed = session.inputs.length > 0 && session.inputs.every((i) => !i.ok) && !runtime;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Findings"
        description={`Session #${session.id} · ${sources.join(", ")}`}
        actions={
          <Button asChild variant="secondary">
            <Link to={`/scan?baseline=${session.id}`}>
              <RotateCcw aria-hidden className="size-4" />
              Retest
            </Link>
          </Button>
        }
      />
      {allFailed ? (
        <Alert
          tone="danger"
          title="The scan failed"
          action={
            <Button variant="secondary" size="sm" onClick={() => void retry()}>
              <RefreshCw aria-hidden className="size-4" />
              Retry
            </Button>
          }
        >
          <ul>
            {session.inputs.map((i) => (
              <li key={i.filename}>
                <span className="font-mono">{i.filename}</span>: {i.error}
              </li>
            ))}
          </ul>
        </Alert>
      ) : (
        <Coverage
          session={session}
          runtime={runtime}
          runtimeError={runtimeError}
          onRetry={() => void retry()}
        />
      )}
      <Retest session={session} />
      <Correlation session={session} />
      {runtime && <ProbeLog scanId={runtime.id} />}
      {all.length === 0 && !allFailed ? (
        <EmptyState
          icon={CircleCheck}
          title="No findings"
          description="None of the rules matched. Review the coverage notes above, if any."
        />
      ) : all.length > 0 ? (
        <>
          <SummaryStrip findings={all} />
          {fixable.length > 0 && (
            <details className="rounded-md border border-border bg-surface">
              <summary className="cursor-pointer px-4 py-2 text-sm font-medium text-fg">
                Fix all findings in a file
              </summary>
              <div className="flex flex-col gap-4 border-t border-border p-4">
                {fixable.map((s) => (
                  <div key={s.filename} className="flex flex-col gap-2">
                    <span className="font-mono text-sm text-fg">{s.filename}</span>
                    <RemediationPanel
                      kind={s.kind}
                      filename={s.filename}
                      content={s.content}
                      label={`Generate corrected ${s.filename}`}
                    />
                  </div>
                ))}
              </div>
            </details>
          )}
          <FilterBar filters={filters} onChange={setFilters} />
          <p role="status" aria-live="polite" className="sr-only">
            Showing {visible.length} of {all.length} findings
          </p>
          {visible.length === 0 ? (
            <EmptyState
              icon={SearchX}
              title="No findings match the filters"
              description="Change or clear the filters to see more findings."
              action={
                <Button
                  variant="secondary"
                  onClick={() => {
                    setFilters(NO_FILTERS);
                  }}
                >
                  Clear filters
                </Button>
              }
            />
          ) : (
            <div className="grid gap-4 split:grid-cols-2">
              <div className="min-w-0">
                <FindingList
                  findings={visible}
                  selectedId={selected?.id ?? null}
                  onSelect={select}
                  newIds={newIds}
                />
              </div>
              <div className="min-w-0 rounded-md border border-border bg-surface p-6">
                {selected && (
                  <FindingDetail
                    key={selected.id}
                    finding={selected}
                    rule={rules === null ? undefined : (rules.get(selected.rule_id) ?? null)}
                    fixSource={sourceFor(selected, statics)}
                  />
                )}
              </div>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}
