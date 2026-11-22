import { CircleCheck, ListChecks, Play, RefreshCw, SearchX } from "lucide-react";
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { FilterBar } from "@/components/FilterBar";
import { FindingDetail } from "@/components/FindingDetail";
import { FindingList } from "@/components/FindingList";
import { PageHeader } from "@/components/layout/PageHeader";
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
import { inputLabel, useScan, type InputOutcome } from "@/lib/scan";
import { ProbeLog } from "@/components/ProbeLog";
import { ScanProgress } from "@/components/ScanProgress";

function Coverage({ outcomes, onRetry }: { outcomes: InputOutcome[]; onRetry: () => void }) {
  const hiddenConfig = outcomes.some(
    (o) =>
      o.ok &&
      "is_snippet" in o.result &&
      (o.result.is_snippet || o.result.unresolved_includes.length > 0),
  );
  const failed = outcomes.filter((o): o is Extract<InputOutcome, { ok: false }> => !o.ok);
  const notes = outcomes.flatMap((o) => {
    if (o.ok && o.input.kind === "runtime" && "notes" in o.result) return o.result.notes;
    if (!o.ok || !("is_snippet" in o.result)) return [];
    const r = o.result;
    const out: string[] = [];
    if (r.is_snippet)
      out.push(`${r.source_name} has no http block, so main-config settings could not be checked.`);
    if (r.unresolved_includes.length)
      out.push(
        `${r.source_name} includes ${r.unresolved_includes.map((i) => `${i.path} (line ${i.line})`).join(", ")}, which ${r.unresolved_includes.length === 1 ? "was" : "were"} not analyzed.`,
      );
    return out;
  });
  return (
    <>
      {failed.length > 0 && (
        <Alert
          tone="warning"
          title={`Partial results: ${failed.length} of ${outcomes.length} inputs could not be analyzed`}
          action={
            <Button variant="secondary" size="sm" onClick={onRetry}>
              <RefreshCw aria-hidden className="size-4" />
              Retry
            </Button>
          }
        >
          <ul>
            {failed.map((o) => (
              <li key={inputLabel(o.input)}>
                <span className="font-mono">{inputLabel(o.input)}</span>: {o.error}
              </li>
            ))}
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
          {hiddenConfig && (
            <p className="mt-1">
              Findings that depend on configuration Magen could not see are marked Inconclusive.
            </p>
          )}
        </Alert>
      )}
    </>
  );
}

export function FindingsPage() {
  const { state, retry, stop } = useScan();
  const rules = useRules();
  const [params, setParams] = useSearchParams();
  const paramString = params.toString();
  const filters = useMemo(() => filtersFromParams(new URLSearchParams(paramString)), [paramString]);
  const all = useMemo(() => (state.phase === "done" ? state.findings : []), [state]);
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
          description="Run a scan of an OpenAPI spec or Nginx config to see findings here."
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

  const allFailed = state.outcomes.every((o) => !o.ok);
  if (allFailed) {
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
          <ul>
            {state.outcomes.map((o) => (
              <li key={inputLabel(o.input)}>
                <span className="font-mono">{inputLabel(o.input)}</span>: {o.ok ? "" : o.error}
              </li>
            ))}
          </ul>
        </Alert>
      </>
    );
  }

  const sources = state.outcomes.filter((o) => o.ok).map((o) => inputLabel(o.input));
  const runtimeScan = state.outcomes.find((o) => o.ok && o.input.kind === "runtime");
  const runtimeScanId =
    runtimeScan?.ok && "status" in runtimeScan.result ? runtimeScan.result.id : null;
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Findings" description={`Results for ${sources.join(", ")}`} />
      <Coverage outcomes={state.outcomes} onRetry={() => void retry()} />
      {runtimeScanId !== null && <ProbeLog scanId={runtimeScanId} />}
      {all.length === 0 ? (
        <EmptyState
          icon={CircleCheck}
          title="No findings"
          description="None of the rules matched. Review the coverage notes above, if any."
        />
      ) : (
        <>
          <SummaryStrip findings={all} />
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
                />
              </div>
              <div className="min-w-0 rounded-md border border-border bg-surface p-6">
                {selected && (
                  <FindingDetail
                    finding={selected}
                    rule={rules === null ? undefined : (rules.get(selected.rule_id) ?? null)}
                  />
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
