import {
  FlaskConical,
  GitCompare,
  ListChecks,
  Play,
  Server,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { LogoMark } from "@/components/Logo";
import { BackendStatus } from "@/components/layout/BackendStatus";
import { cn } from "@/lib/utils";

const NAV: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/targets", label: "Targets", icon: Server },
  { to: "/scan", label: "New scan", icon: Play },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/compare", label: "Retest / compare", icon: GitCompare },
  { to: "/settings", label: "Settings", icon: Settings },
];

/** Fixed left sidebar + main content (design-system §4). */
export function AppShell() {
  return (
    <div className="flex h-full">
      <aside className="flex w-sidebar shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 px-4 py-4 text-accent">
          <LogoMark className="size-6" />
          <span className="text-lg font-semibold text-fg">Magen</span>
        </div>
        <nav aria-label="Main" className="flex flex-1 flex-col gap-1 px-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  "flex h-9 items-center gap-3 rounded-md px-3 text-base text-fg-muted transition-colors duration-fast hover:bg-surface-raised hover:text-fg",
                  isActive && "bg-surface-raised font-medium text-fg",
                )
              }
            >
              <Icon aria-hidden className="size-5" strokeWidth={1.5} />
              {label}
            </NavLink>
          ))}
          {import.meta.env.DEV && (
            <NavLink
              to="/dev/components"
              className="mt-auto flex h-9 items-center gap-3 rounded-md px-3 text-sm text-fg-muted hover:bg-surface-raised hover:text-fg"
            >
              <FlaskConical aria-hidden className="size-5" strokeWidth={1.5} />
              Components
            </NavLink>
          )}
        </nav>
        <div className="border-t border-border px-4 py-3">
          <BackendStatus />
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-auto">
        <div className="mx-auto max-w-content p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
