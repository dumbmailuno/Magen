import { useState } from "react";
import { AiPanel, type AiPanelState } from "@/components/AiPanel";
import { api, ApiError } from "@/lib/api";
import type { AiExplainResult, Finding } from "@/lib/types";

/**
 * Fetches (and caches on the backend) the AI explanation for a stored finding. Collapsed
 * until the user asks; the deterministic rule description above it is always shown.
 */
export function AiExplanation({
  sessionId,
  finding,
  fallback,
}: {
  sessionId: number;
  finding: Finding;
  fallback: string;
}) {
  const [result, setResult] = useState<AiExplainResult | null>(null);
  const [state, setState] = useState<AiPanelState>(finding.ai_explanation ? "ready" : "collapsed");
  const [failure, setFailure] = useState<string | null>(null);

  const load = async (force: boolean) => {
    setState("loading");
    try {
      const r = await api.aiExplain(sessionId, finding.id, force);
      setResult(r);
      setState(r.state);
    } catch (err) {
      setFailure(err instanceof ApiError ? err.message : "Request failed");
      setState("error");
    }
  };

  const ai = result?.finding.ai_explanation ?? finding.ai_explanation;
  return (
    <AiPanel
      state={state}
      fallback={result?.fallback ?? fallback}
      injectionSuspected={result?.injection_suspected ?? false}
      onExpand={() => void load(false)}
      onRegenerate={() => void load(true)}
      {...(ai ? { text: ai.text, model: ai.model, promptVersion: ai.prompt_version } : {})}
      {...(result?.message && state === "unavailable"
        ? { unavailableMessage: result.message }
        : {})}
      {...((result?.message ?? failure) && state === "error"
        ? { errorMessage: result?.message ?? failure ?? "" }
        : {})}
    />
  );
}
