import { Check, CircleDot, Loader2, Square } from "lucide-react";
import { useLayoutEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import type { RuntimeProgress } from "@/lib/scan";
import { cn } from "@/lib/utils";

type Stage = "static" | "runtime";

/**
 * Scan progress: stage stepper, determinate bar, polite live text, and an always-visible
 * Stop button while runtime probes are running (CLAUDE.md §7, design-system §8).
 */
export function ScanProgress({
  stage,
  hasStatic = true,
  hasRuntime,
  current,
  runtime,
  onStop,
}: {
  stage: Stage;
  /** Only stages that actually run are shown. */
  hasStatic?: boolean;
  hasRuntime: boolean;
  current: string;
  runtime: RuntimeProgress | null;
  onStop: () => void;
}) {
  const fill = useRef<HTMLDivElement>(null);
  const pct = runtime && runtime.total > 0 ? Math.round((runtime.done / runtime.total) * 100) : 0;
  useLayoutEffect(() => {
    // CSSOM write: allowed by the strict CSP (no inline style attribute).
    if (fill.current) fill.current.style.width = `${pct}%`;
  }, [pct]);

  const stages: { id: Stage; label: string }[] = [
    ...(hasStatic ? [{ id: "static" as const, label: "Static analysis" }] : []),
    ...(hasRuntime ? [{ id: "runtime" as const, label: "Runtime probes" }] : []),
  ];
  const status =
    stage === "runtime" && runtime
      ? runtime.stopping
        ? "Stopping… finishing the current request"
        : `Probing ${runtime.done}/${runtime.total || "…"} · ${runtime.current}`
      : `Analyzing ${current}…`;

  return (
    <section
      aria-label="Scan progress"
      className="flex flex-col gap-4 rounded-md border border-border bg-surface p-4"
    >
      <ol className="flex flex-wrap items-center gap-4">
        {stages.map((s) => {
          const active = s.id === stage;
          const finished = s.id === "static" && stage === "runtime";
          return (
            <li
              key={s.id}
              className={cn(
                "flex items-center gap-2 text-sm",
                active ? "font-medium text-fg" : "text-fg-muted",
              )}
            >
              {finished ? (
                <Check aria-hidden className="size-4 text-success" />
              ) : active ? (
                <Loader2 aria-hidden className="size-4 animate-spin motion-reduce:animate-none" />
              ) : (
                <CircleDot aria-hidden className="size-4" />
              )}
              {s.label}
              <span className="sr-only">
                {finished ? "(done)" : active ? "(in progress)" : "(pending)"}
              </span>
            </li>
          );
        })}
      </ol>
      {stage === "runtime" && (
        <div
          role="progressbar"
          aria-label="Runtime probes"
          aria-valuemin={0}
          aria-valuemax={runtime?.total ?? 0}
          aria-valuenow={runtime?.done ?? 0}
          className="progress-track"
        >
          <div ref={fill} className="progress-fill" />
        </div>
      )}
      <div className="flex items-center gap-4">
        <p
          role="status"
          aria-live="polite"
          className="min-w-0 flex-1 truncate font-mono text-sm text-fg"
        >
          {status}
        </p>
        {stage === "runtime" && (
          <Button
            variant="secondary"
            size="sm"
            onClick={onStop}
            disabled={runtime?.stopping ?? false}
          >
            <Square aria-hidden className="size-4" />
            {runtime?.stopping ? "Stopping…" : "Stop"}
          </Button>
        )}
      </div>
    </section>
  );
}
