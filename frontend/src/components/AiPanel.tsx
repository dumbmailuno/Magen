import { ChevronDown, ChevronRight, RefreshCw, Sparkles, TriangleAlert } from "lucide-react";
import { useId, useState } from "react";
import { CopyButton } from "@/components/CopyButton";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export type AiPanelState = "collapsed" | "loading" | "ready" | "unavailable" | "error";

export const AI_CAPTION = "AI-generated — review before use";

export interface AiPanelProps {
  state: AiPanelState;
  /** AI output (state "ready"). */
  text?: string;
  /** Provenance, recorded with every output (CLAUDE.md §8). */
  model?: string;
  promptVersion?: string;
  /** Deterministic template explanation, shown when AI is unavailable or failed. */
  fallback: string;
  errorMessage?: string;
  /** Why AI is unavailable (AI off, Ollama not running, model missing, downloading). */
  unavailableMessage?: string;
  /** The scanned content looks like it addresses an AI: warn the reader. */
  injectionSuspected?: boolean;
  onRegenerate?: () => void;
  onExpand?: () => void;
}

/**
 * The ONLY place AI-generated text is rendered. Uses the reserved `ai` tint, sparkles icon
 * and caption so machine prose is never confused with deterministic findings.
 */
export function AiPanel({
  state,
  text,
  model,
  promptVersion,
  fallback,
  errorMessage,
  unavailableMessage,
  injectionSuspected = false,
  onRegenerate,
  onExpand,
}: AiPanelProps) {
  const bodyId = useId();
  const [open, setOpen] = useState(state !== "collapsed");
  const expanded = state === "collapsed" ? open : true;

  if (state === "unavailable" || state === "error") {
    return (
      <section className="rounded-md border border-border bg-surface p-4" aria-label="Explanation">
        <div className="mb-2 flex items-center gap-2 text-sm text-fg-muted">
          <TriangleAlert aria-hidden className="size-4 text-warning" />
          {state === "unavailable"
            ? `AI explanation unavailable — ${unavailableMessage ?? "Ollama is not running. Start Ollama to enable AI explanations."}`
            : `AI explanation failed${errorMessage ? `: ${errorMessage}` : ""}. Showing the template explanation.`}
        </div>
        <p className="text-base text-fg">{fallback}</p>
        {state === "error" && onRegenerate && (
          <Button variant="secondary" size="sm" className="mt-3" onClick={onRegenerate}>
            <RefreshCw aria-hidden className="size-4" />
            Retry
          </Button>
        )}
      </section>
    );
  }

  return (
    <section className="rounded-md border border-ai bg-ai-bg" aria-label="AI explanation">
      <header className="flex items-center gap-2 px-4 py-2">
        <button
          type="button"
          className="flex flex-1 items-center gap-2 text-left text-sm font-medium text-ai"
          aria-expanded={expanded}
          aria-controls={bodyId}
          onClick={() => {
            if (state === "collapsed") {
              if (!open) onExpand?.();
              setOpen(!open);
            }
          }}
        >
          {state === "collapsed" &&
            (expanded ? (
              <ChevronDown aria-hidden className="size-4" />
            ) : (
              <ChevronRight aria-hidden className="size-4" />
            ))}
          <Sparkles aria-hidden className="size-4" />
          AI explanation
        </button>
        {state === "ready" && text && <CopyButton text={text} label="Copy AI explanation" />}
        {state === "ready" && onRegenerate && (
          <Button
            variant="ghost"
            size="icon"
            aria-label="Regenerate AI explanation"
            title="Regenerate"
            onClick={onRegenerate}
          >
            <RefreshCw aria-hidden className="size-4" />
          </Button>
        )}
      </header>
      <div id={bodyId} hidden={!expanded} className="px-4 pb-4">
        <div aria-live="polite" aria-busy={state === "loading"}>
          {state === "loading" ? (
            <div className="flex flex-col gap-2">
              <span className="text-sm text-fg-muted">Generating explanation…</span>
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-5/6" />
              <Skeleton className="h-3 w-2/3" />
            </div>
          ) : (
            <p className="whitespace-pre-wrap text-base text-fg">{text ?? fallback}</p>
          )}
        </div>
        {injectionSuspected && state === "ready" && (
          <p role="note" className="mt-3 flex items-start gap-2 text-sm text-warning">
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
            The scanned content contains text that looks like instructions to an AI. It was treated
            as data, but read this explanation with extra care.
          </p>
        )}
        <p className="mt-3 flex flex-wrap items-center gap-x-2 text-xs text-ai">
          <span className="font-medium">{AI_CAPTION}</span>
          {model && <span className="text-fg-muted">· {model}</span>}
          {promptVersion && <span className="text-fg-muted">· prompt {promptVersion}</span>}
        </p>
      </div>
    </section>
  );
}
