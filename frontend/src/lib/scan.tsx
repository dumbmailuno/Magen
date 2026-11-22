import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { api, ApiError } from "./api";
import { sortFindings } from "./findings";
import type { Finding, InputKind, NginxResult, OpenApiResult } from "./types";

export interface ScanInput {
  kind: InputKind;
  filename: string;
  content: string;
}

export type InputOutcome =
  | { input: ScanInput; ok: true; result: OpenApiResult | NginxResult }
  | { input: ScanInput; ok: false; error: string };

export type ScanState =
  | { phase: "idle" }
  | { phase: "running"; inputs: ScanInput[]; current: string }
  | { phase: "done"; inputs: ScanInput[]; outcomes: InputOutcome[]; findings: Finding[] };

interface ScanApi {
  state: ScanState;
  run: (inputs: ScanInput[]) => Promise<void>;
  retry: () => Promise<void>;
  reset: () => void;
}

const ScanContext = createContext<ScanApi | null>(null);

async function analyze(input: ScanInput): Promise<InputOutcome> {
  try {
    const result =
      input.kind === "openapi"
        ? await api.analyzeOpenapi(input.filename, input.content)
        : await api.analyzeNginx(input.filename, input.content);
    return { input, ok: true, result };
  } catch (err) {
    const message = err instanceof ApiError ? err.message : "Unexpected error";
    return { input, ok: false, error: message };
  }
}

/**
 * Holds the current scan session in memory. Static analysis is stateless on the backend;
 * persisted scans arrive with the retest flow (roadmap wk 9–10).
 */
export function ScanProvider({
  children,
  initial = { phase: "idle" },
}: {
  children: ReactNode;
  initial?: ScanState;
}) {
  const [state, setState] = useState<ScanState>(initial);

  const run = useCallback(async (inputs: ScanInput[]) => {
    const outcomes: InputOutcome[] = [];
    for (const input of inputs) {
      setState({ phase: "running", inputs, current: input.filename });
      outcomes.push(await analyze(input));
    }
    const findings = sortFindings(outcomes.flatMap((o) => (o.ok ? o.result.findings : [])));
    setState({ phase: "done", inputs, outcomes, findings });
  }, []);

  const retry = useCallback(async () => {
    if (state.phase === "done") await run(state.inputs);
  }, [state, run]);

  const reset = useCallback(() => {
    setState({ phase: "idle" });
  }, []);

  const value = useMemo(() => ({ state, run, retry, reset }), [state, run, retry, reset]);
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useScan(): ScanApi {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used inside <ScanProvider>");
  return ctx;
}
