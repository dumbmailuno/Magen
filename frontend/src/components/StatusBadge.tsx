import { CircleCheck, CircleHelp, CircleMinus, type LucideIcon } from "lucide-react";
import type { FindingStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const CONFIG: Record<FindingStatus, { label: string; icon: LucideIcon; className: string }> = {
  // Solid / outline / dashed are distinct even in grayscale.
  confirmed: { label: "Confirmed", icon: CircleCheck, className: "border-fg bg-fg text-bg" },
  potential: { label: "Potential", icon: CircleHelp, className: "border-border-strong text-fg" },
  inconclusive: {
    label: "Inconclusive",
    icon: CircleMinus,
    className: "border-dashed border-border-strong text-fg-muted",
  },
};

/** Finding certainty: confirmed (solid), potential (outline), inconclusive (dashed). */
export function StatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  const { label, icon: Icon, className: tone } = CONFIG[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 text-xs font-medium tracking-wide",
        tone,
        className,
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={1.75} />
      {label}
    </span>
  );
}
