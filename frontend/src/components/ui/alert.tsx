import { CircleX, Info, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

type Tone = "info" | "warning" | "danger";

const TONES: Record<Tone, { icon: LucideIcon; className: string; iconClass: string }> = {
  info: { icon: Info, className: "border-border bg-surface", iconClass: "text-fg-muted" },
  warning: {
    icon: TriangleAlert,
    className: "border-warning bg-warning-bg",
    iconClass: "text-warning",
  },
  danger: { icon: CircleX, className: "border-danger bg-danger-bg", iconClass: "text-danger" },
};

/** Feedback message: tint + icon + text. Errors are announced (`role=alert`). */
export function Alert({
  tone,
  title,
  children,
  action,
}: {
  tone: Tone;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  const { icon: Icon, className, iconClass } = TONES[tone];
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-md border p-3", className)}
    >
      <Icon aria-hidden className={cn("mt-0.5 size-4 shrink-0", iconClass)} />
      <div className="min-w-0 flex-1">
        <p className="text-base font-medium text-fg">{title}</p>
        {children && <div className="mt-1 text-sm text-fg-muted">{children}</div>}
      </div>
      {action}
    </div>
  );
}
