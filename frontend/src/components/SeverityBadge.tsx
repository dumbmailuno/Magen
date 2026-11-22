import {
  CircleAlert,
  CircleDot,
  Info,
  OctagonAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const CONFIG: Record<Severity, { label: string; icon: LucideIcon; className: string }> = {
  critical: {
    label: "Critical",
    icon: OctagonAlert,
    className: "bg-sev-bg-critical text-sev-critical",
  },
  high: { label: "High", icon: TriangleAlert, className: "bg-sev-bg-high text-sev-high" },
  medium: { label: "Medium", icon: CircleAlert, className: "bg-sev-bg-medium text-sev-medium" },
  low: { label: "Low", icon: Info, className: "bg-sev-bg-low text-sev-low" },
  info: { label: "Info", icon: CircleDot, className: "bg-sev-bg-info text-sev-info" },
};

/** Severity: icon + text label + tint. Never color-only (design-system §2). */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const { label, icon: Icon, className: tone } = CONFIG[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm px-2 py-0.5 text-xs font-medium tracking-wide",
        tone,
        className,
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={1.75} />
      {label}
    </span>
  );
}
