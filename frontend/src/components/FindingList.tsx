import { useRef, type KeyboardEvent } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { formatLocation } from "@/lib/findings";
import type { Finding } from "@/lib/types";
import { cn, truncateMiddle } from "@/lib/utils";

/**
 * FindingTable (design-system §8) as a single-select listbox with roving focus:
 * ↑/↓ move, Home/End jump; selection follows focus so the detail pane updates.
 */
export function FindingList({
  findings,
  selectedId,
  onSelect,
}: {
  findings: readonly Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const index = Math.max(
    0,
    findings.findIndex((f) => f.id === selectedId),
  );

  const move = (to: number) => {
    const target = findings[Math.min(findings.length - 1, Math.max(0, to))];
    if (!target) return;
    onSelect(target.id);
    listRef.current?.querySelector<HTMLElement>(`[data-id="${target.id}"]`)?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const keys: Record<string, number> = {
      ArrowDown: index + 1,
      ArrowUp: index - 1,
      Home: 0,
      End: findings.length - 1,
    };
    const to = keys[e.key];
    if (to !== undefined) {
      e.preventDefault();
      move(to);
    }
  };

  return (
    <div className="overflow-hidden rounded-md border border-border bg-surface">
      <div
        aria-hidden
        className="flex items-center gap-3 border-b border-border px-3 py-2 text-sm font-medium text-fg-muted"
      >
        <span className="w-24 shrink-0">Severity</span>
        <span className="min-w-0 flex-1">Finding</span>
        <span className="w-32 shrink-0">Status</span>
      </div>
      <div
        ref={listRef}
        role="listbox"
        aria-label="Findings"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="max-h-full overflow-auto"
      >
        {findings.map((f, i) => {
          const selected = f.id === selectedId || (selectedId === null && i === 0);
          const loc = f.evidence[0] ? formatLocation(f.evidence[0].location) : "";
          return (
            <div
              key={f.id}
              data-id={f.id}
              role="option"
              aria-selected={selected}
              tabIndex={i === index ? 0 : -1}
              onClick={() => {
                onSelect(f.id);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(f.id);
                }
              }}
              className={cn(
                "cv-auto flex cursor-pointer items-center gap-3 border-b border-l-2 border-b-border border-l-transparent px-3 py-2 last:border-b-0",
                "transition-colors duration-fast hover:bg-surface-raised",
                selected && "border-l-primary bg-surface-raised",
              )}
            >
              <span className="w-24 shrink-0">
                <SeverityBadge severity={f.severity} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-base text-fg" title={f.title}>
                  {f.title}
                </span>
                <span className="flex min-w-0 items-center gap-2">
                  <span className="truncate font-mono text-xs text-fg-muted" title={loc}>
                    {f.rule_id} · {truncateMiddle(loc, 48)}
                  </span>
                  <SourceTag source={f.source} className="shrink-0 px-1 py-0" />
                </span>
              </span>
              <span className="w-32 shrink-0">
                <StatusBadge status={f.status} />
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
