import { CircleCheck, CircleX, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Health } from "@/lib/types";

type State =
  { kind: "checking" } | { kind: "ok"; health: Health } | { kind: "error"; message: string };

/** Sidebar footer showing whether the local backend is reachable (icon + text). */
export function BackendStatus() {
  const [state, setState] = useState<State>({ kind: "checking" });

  useEffect(() => {
    let cancelled = false;
    const check = () => {
      api
        .health()
        .then((health) => {
          if (!cancelled) setState({ kind: "ok", health });
        })
        .catch((err: unknown) => {
          if (!cancelled)
            setState({
              kind: "error",
              message: err instanceof ApiError ? err.message : "Unknown error",
            });
        });
    };
    check();
    const id = window.setInterval(check, 10_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return (
    <div className="flex items-center gap-2 text-xs text-fg-muted" role="status" aria-live="polite">
      {state.kind === "checking" && (
        <>
          <Loader2 aria-hidden className="size-4 animate-spin motion-reduce:animate-none" />
          Connecting to backend…
        </>
      )}
      {state.kind === "ok" && (
        <>
          <CircleCheck aria-hidden className="size-4 text-success" />
          <span title={state.health.generated_by}>
            Backend {state.health.version} · {state.health.commit}
          </span>
        </>
      )}
      {state.kind === "error" && (
        <>
          <CircleX aria-hidden className="size-4 text-danger" />
          Backend offline: {state.message}
        </>
      )}
    </div>
  );
}
