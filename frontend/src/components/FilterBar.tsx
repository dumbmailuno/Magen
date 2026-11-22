import { FilterX } from "lucide-react";
import type { ReactNode } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { NO_FILTERS, type Filters } from "@/lib/findings";
import { FINDING_STATUSES, SEVERITIES, SOURCES } from "@/lib/types";
import { cn } from "@/lib/utils";

function Chip({
  pressed,
  onClick,
  label,
  children,
}: {
  pressed: boolean;
  onClick: () => void;
  label: string;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      aria-label={label}
      onClick={onClick}
      className={cn(
        "inline-flex h-8 items-center rounded-md border px-1 transition-colors duration-fast",
        pressed
          ? "border-primary bg-surface-raised"
          : "border-transparent hover:border-border-strong",
      )}
    >
      {children}
    </button>
  );
}

function toggle<T>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/** Severity / status / source toggles. State is owned by the caller (URL params). */
export function FilterBar({
  filters,
  onChange,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
}) {
  const active = filters.severity.length + filters.status.length + filters.source.length > 0;
  return (
    <div role="group" aria-label="Filters" className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex flex-wrap items-center gap-1">
        {SEVERITIES.map((s) => (
          <Chip
            key={s}
            label={`Severity ${s}`}
            pressed={filters.severity.includes(s)}
            onClick={() => {
              onChange({ ...filters, severity: toggle(filters.severity, s) });
            }}
          >
            <SeverityBadge severity={s} />
          </Chip>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        {FINDING_STATUSES.map((s) => (
          <Chip
            key={s}
            label={`Status ${s}`}
            pressed={filters.status.includes(s)}
            onClick={() => {
              onChange({ ...filters, status: toggle(filters.status, s) });
            }}
          >
            <StatusBadge status={s} />
          </Chip>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        {SOURCES.map((s) => (
          <Chip
            key={s}
            label={`Source ${s}`}
            pressed={filters.source.includes(s)}
            onClick={() => {
              onChange({ ...filters, source: toggle(filters.source, s) });
            }}
          >
            <SourceTag source={s} />
          </Chip>
        ))}
      </div>
      {active && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            onChange(NO_FILTERS);
          }}
        >
          <FilterX aria-hidden className="size-4" />
          Clear filters
        </Button>
      )}
    </div>
  );
}
