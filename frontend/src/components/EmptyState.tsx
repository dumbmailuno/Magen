import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

/** Per-page empty state: icon, one-line explanation, single primary action. */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-md border border-dashed border-border p-12 text-center">
      <Icon aria-hidden className="size-8 text-fg-muted" strokeWidth={1.5} />
      <h2 className="text-lg font-semibold text-fg">{title}</h2>
      <p className="max-w-md text-base text-fg-muted">{description}</p>
      {action}
    </div>
  );
}
