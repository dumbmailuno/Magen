import {
  CircleCheck,
  CircleSlash,
  CircleX,
  Download,
  Loader2,
  RefreshCw,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, ApiError } from "@/lib/api";
import type { AiState, AiStatus } from "@/lib/types";

const STATE: Record<AiState, { icon: LucideIcon; label: string; tone: string }> = {
  ready: { icon: CircleCheck, label: "Ready", tone: "text-success" },
  disabled: { icon: CircleSlash, label: "Turned off", tone: "text-fg-muted" },
  not_running: { icon: CircleX, label: "Ollama is not running", tone: "text-danger" },
  model_missing: { icon: TriangleAlert, label: "Model not installed", tone: "text-warning" },
  downloading: { icon: Loader2, label: "Downloading model", tone: "text-fg" },
};

/** Local AI (Ollama) settings and status (design-system §8 AiSettings). */
export function AiSettings({ pollMs = 1000 }: { pollMs?: number }) {
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [model, setModel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const fill = useRef<HTMLDivElement>(null);

  const refresh = useCallback(() => {
    api
      .aiStatus()
      .then((s) => {
        setStatus(s);
        setModel((m) => m || s.model);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Could not reach the backend");
      });
  }, []);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    if (status?.state !== "downloading") return;
    const id = window.setTimeout(refresh, pollMs);
    return () => {
      window.clearTimeout(id);
    };
  }, [status, refresh, pollMs]);
  const pct = status?.pull?.percent ?? 0;
  useLayoutEffect(() => {
    if (fill.current) fill.current.style.width = `${pct}%`;
  }, [pct]);

  const act = async (fn: () => Promise<AiStatus>) => {
    try {
      setStatus(await fn());
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Request failed");
    }
  };

  const meta = status ? STATE[status.state] : null;
  return (
    <section
      aria-label="AI assistant"
      className="flex flex-col gap-4 rounded-md border border-border bg-surface p-4"
    >
      <h2 className="text-lg font-semibold">AI assistant (local)</h2>
      <p className="text-sm text-fg-muted">
        Optional. Explanations and fix suggestions come from a model running on this computer
        through Ollama. Nothing is sent to the cloud, and detection never depends on it.
      </p>
      {error && <Alert tone="danger" title={error} />}
      {status && meta && (
        <>
          <p
            role="status"
            aria-live="polite"
            className={`flex items-center gap-2 text-base font-medium ${meta.tone}`}
          >
            <meta.icon
              aria-hidden
              className={`size-4 ${status.state === "downloading" ? "animate-spin motion-reduce:animate-none" : ""}`}
            />
            {meta.label}
            {status.version && (
              <span className="font-normal text-fg-muted">· Ollama {status.version}</span>
            )}
          </p>
          {status.state === "not_running" && (
            <p className="text-sm text-fg-muted">
              Install Ollama from ollama.com and start it, then check again. Magen keeps working
              without it.
            </p>
          )}
          {status.state === "downloading" && (
            <div
              role="progressbar"
              aria-label="Model download"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={pct}
              className="progress-track"
            >
              <div ref={fill} className="progress-fill" />
            </div>
          )}
          {status.pull?.error && (
            <Alert tone="warning" title="Model download failed">
              {status.pull.error}
            </Alert>
          )}
          <label className="flex items-center gap-2 text-base text-fg">
            <input
              type="checkbox"
              className="size-4 accent-primary"
              checked={status.enabled}
              onChange={(e) => void act(() => api.aiSettings({ enabled: e.target.checked }))}
            />
            Use AI explanations and fix suggestions
          </label>
          <div className="grid gap-4 split:grid-cols-2">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Input
                  label="Model"
                  mono
                  value={model}
                  onChange={(e) => {
                    setModel(e.target.value);
                  }}
                  helper={
                    status.models.length
                      ? `Installed: ${status.models.join(", ")}`
                      : "Default: qwen3:4b (alternative: phi4-mini)"
                  }
                />
              </div>
              <Button
                variant="secondary"
                disabled={!model.trim() || model === status.model}
                onClick={() => void act(() => api.aiSettings({ model }))}
              >
                Save
              </Button>
            </div>
            <Input
              label="Ollama URL"
              mono
              readOnly
              value={status.url}
              helper="Loopback only — cloud endpoints are refused."
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {status.state === "model_missing" && (
              <Button onClick={() => void act(() => api.aiPull())}>
                <Download aria-hidden className="size-4" />
                Download {status.model}
              </Button>
            )}
            <Button variant="ghost" onClick={refresh}>
              <RefreshCw aria-hidden className="size-4" />
              Check again
            </Button>
          </div>
        </>
      )}
    </section>
  );
}
