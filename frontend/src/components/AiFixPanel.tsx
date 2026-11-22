import { Download, ShieldCheck, ShieldX, Sparkles, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { AI_CAPTION } from "@/components/AiPanel";
import { DiffView } from "@/components/DiffView";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import type { StaticInput } from "@/lib/scan";
import type { AiFixResult } from "@/lib/types";

function download(text: string, filename: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** AI-proposed rewrite of the finding's own lines — validated like template fixes, never applied. */
export function AiFixPanel({
  sessionId,
  findingId,
  source,
}: {
  sessionId: number;
  findingId: string;
  source: StaticInput;
}) {
  const [state, setState] = useState<
    { s: "idle" | "busy" } | { s: "done"; r: AiFixResult } | { s: "failed"; m: string }
  >({ s: "idle" });

  const run = async () => {
    setState({ s: "busy" });
    try {
      const r = await api.aiFix({
        session_id: sessionId,
        finding_id: findingId,
        kind: source.kind,
        filename: source.filename,
        content: source.content,
      });
      setState({ s: "done", r });
    } catch (err) {
      setState({ s: "failed", m: err instanceof ApiError ? err.message : "Request failed" });
    }
  };

  if (state.s === "idle" || state.s === "busy")
    return (
      <Button
        variant="ghost"
        size="sm"
        className="w-fit text-ai"
        onClick={() => void run()}
        loading={state.s === "busy"}
      >
        <Sparkles aria-hidden className="size-4" />
        Ask AI for a fix
      </Button>
    );

  const result = state.s === "done" ? state.r : null;
  const message =
    state.s === "failed"
      ? state.m
      : result && result.state !== "ready"
        ? `${result.state === "unavailable" ? "AI unavailable" : "AI fix failed"}: ${result.message ?? ""} Use the template fix above.`
        : null;
  return (
    <section
      aria-label="AI-suggested fix"
      className="flex flex-col gap-3 rounded-md border border-ai bg-ai-bg p-4"
      aria-live="polite"
    >
      <h4 className="flex items-center gap-2 text-sm font-medium text-ai">
        <Sparkles aria-hidden className="size-4" />
        AI-suggested fix
      </h4>
      {message ? (
        <p className="flex items-start gap-2 text-sm text-fg">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
          {message}
        </p>
      ) : state.s === "done" ? (
        <>
          {state.r.explanation && <p className="text-base text-fg">{state.r.explanation}</p>}
          {state.r.validated ? (
            <p className="inline-flex items-center gap-1 text-sm font-medium text-success">
              <ShieldCheck aria-hidden className="size-4" />
              Validated: the file still parses, this finding is gone and nothing new was introduced.
            </p>
          ) : (
            <p className="inline-flex items-start gap-1 text-sm font-medium text-danger">
              <ShieldX aria-hidden className="mt-0.5 size-4 shrink-0" />
              Not validated:{" "}
              {state.r.validation && !state.r.validation.parsed
                ? "the corrected file does not parse."
                : state.r.validation?.introduced.length
                  ? `it would introduce ${state.r.validation.introduced.map((f) => f.rule_id).join(", ")}.`
                  : "the finding is still present."}{" "}
              Do not use it as is.
            </p>
          )}
          {state.r.injection_suspected && (
            <p role="note" className="flex items-start gap-2 text-sm text-warning">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
              The scanned lines contain text that looks like instructions to an AI. Review this
              suggestion carefully.
            </p>
          )}
          <DiffView diff={state.r.diff} filename={source.filename} />
          {state.r.validated && (
            <Button
              variant="secondary"
              size="sm"
              className="w-fit"
              onClick={() => {
                download(state.r.patched_content, state.r.patched_filename);
              }}
            >
              <Download aria-hidden className="size-4" />
              Export {state.r.patched_filename}
            </Button>
          )}
          <p className="flex flex-wrap gap-x-2 text-xs text-ai">
            <span className="font-medium">{AI_CAPTION}</span>
            <span className="text-fg-muted">· {state.r.model}</span>
            <span className="text-fg-muted">· prompt {state.r.prompt_version}</span>
          </p>
        </>
      ) : null}
    </section>
  );
}
