import { GitCompare, RefreshCw } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CompareView } from "@/components/CompareView";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/layout/PageHeader";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { api, ApiError } from "@/lib/api";
import type { Comparison, SessionSummary } from "@/lib/types";

function label(s: SessionSummary): string {
  return `#${s.id} · ${s.inputs.join(", ") || "runtime only"} · ${s.total} findings · ${s.created_at.slice(0, 16).replace("T", " ")}`;
}

/** Retest / compare: pick a baseline and a later session (design-system §9 screen 6). */
export function ComparePage() {
  const id = useId();
  const [params, setParams] = useSearchParams();
  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .sessions()
      .then(setSessions)
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Could not load sessions");
      });
  }, []);

  const base = params.get("base") ? Number(params.get("base")) : (sessions?.[1]?.id ?? null);
  const head = params.get("head") ? Number(params.get("head")) : (sessions?.[0]?.id ?? null);

  useEffect(() => {
    if (base === null || head === null || base === head) return;
    let alive = true;
    api
      .compare(base, head)
      .then((c) => {
        if (alive) {
          setComparison(c);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (alive) setError(err instanceof ApiError ? err.message : "Could not compare");
      });
    return () => {
      alive = false;
    };
  }, [base, head]);

  const pick = (key: "base" | "head", value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    if (!next.get(key === "base" ? "head" : "base") && head !== null && base !== null)
      next.set(key === "base" ? "head" : "base", String(key === "base" ? head : base));
    setParams(next, { replace: true });
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Retest / compare"
        description="What was resolved, what persists and what is new between two sessions."
      />
      {error && (
        <Alert
          tone="danger"
          title="Comparison unavailable"
          action={
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                window.location.reload();
              }}
            >
              <RefreshCw aria-hidden className="size-4" />
              Retry
            </Button>
          }
        >
          {error}
        </Alert>
      )}
      {sessions === null && !error && <Skeleton className="h-24 w-full" />}
      {sessions !== null && sessions.length < 2 && (
        <EmptyState
          icon={GitCompare}
          title="Nothing to compare yet"
          description="Run at least two scans (use Retest on the Findings page after fixing) to compare results."
        />
      )}
      {sessions !== null && sessions.length >= 2 && (
        <>
          <div className="grid gap-4 split:grid-cols-2">
            {(["base", "head"] as const).map((key) => (
              <div key={key} className="flex flex-col gap-1">
                <label htmlFor={`${id}-${key}`} className="text-sm font-medium text-fg">
                  {key === "base" ? "Baseline (before)" : "Current (after)"}
                </label>
                <select
                  id={`${id}-${key}`}
                  className="h-9 rounded-md border border-border-strong bg-surface px-3 text-base text-fg"
                  value={(key === "base" ? base : head) ?? ""}
                  onChange={(e) => {
                    pick(key, e.target.value);
                  }}
                >
                  {sessions.map((s) => (
                    <option key={s.id} value={s.id}>
                      {label(s)}
                    </option>
                  ))}
                </select>
              </div>
            ))}
          </div>
          {base === head ? (
            <p className="text-sm text-fg-muted">Pick two different sessions.</p>
          ) : comparison ? (
            <CompareView comparison={comparison} />
          ) : (
            <Skeleton className="h-48 w-full" />
          )}
        </>
      )}
    </div>
  );
}
