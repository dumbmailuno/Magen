import { FileCode, GitMerge, Radio, type LucideIcon } from "lucide-react";
import type { Source } from "@/lib/types";
import { cn } from "@/lib/utils";

const CONFIG: Record<Source, { label: string; icon: LucideIcon }> = {
  static: { label: "Static", icon: FileCode },
  runtime: { label: "Runtime", icon: Radio },
  correlated: { label: "Correlated", icon: GitMerge },
};

/** Evidence origin tag: icon + label, neutral color (source is not a severity). */
export function SourceTag({ source, className }: { source: Source; className?: string }) {
  const { label, icon: Icon } = CONFIG[source];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm bg-surface-raised px-2 py-0.5 text-xs font-medium text-fg-muted",
        className,
      )}
    >
      <Icon aria-hidden className="size-3.5" strokeWidth={1.75} />
      {label}
    </span>
  );
}
