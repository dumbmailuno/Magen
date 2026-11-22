import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api, ApiError } from "./api";
import { sortFindings } from "./findings";
import type {
  Finding,
  InputKind,
  NginxResult,
  OpenApiResult,
  RuntimeScan,
  RuntimeScanRequest,
} from "./types";

export interface StaticInput {
  kind: InputKind;
  filename: string;
  content: string;
}

/**
 * A live API scan. The auth header value lives only here, in renderer memory, for the
 * session (it is sent to the loopback backend once per scan and never persisted).
 */
export interface RuntimeInput {
  kind: "runtime";
  request: RuntimeScanRequest;
  /** Display name, e.g. the base URL. */
  label: string;
}

export type ScanInput = StaticInput | RuntimeInput;

export type InputOutcome =
  | { input: StaticInput; ok: true; result: OpenApiResult | NginxResult }
  | { input: RuntimeInput; ok: true; result: RuntimeScan }
  | { input: ScanInput; ok: false; error: string };

export interface RuntimeProgress {
  scanId: number | null;
  done: number;
  total: number;
  current: string;
  stopping: boolean;
}

export type ScanState =
  | { phase: "idle" }
  | {
      phase: "running";
      inputs: ScanInput[];
      stage: "static" | "runtime";
      current: string;
      runtime: RuntimeProgress | null;
    }
  | { phase: "done"; inputs: ScanInput[]; outcomes: InputOutcome[]; findings: Finding[] };

interface ScanApi {
  state: ScanState;
  run: (inputs: ScanInput[]) => Promise<void>;
  retry: () => Promise<void>;
  stop: () => Promise<void>;
  reset: () => void;
}

const ScanContext = createContext<ScanApi | null>(null);
const FINAL = new Set(["done", "failed", "cancelled", "interrupted"]);
export const POLL_MS = 400;

function message(err: unknown): string {
  return err instanceof ApiError ? err.message : "Unexpected error";
}

async function analyzeStatic(input: StaticInput): Promise<InputOutcome> {
  try {
    const result =
      input.kind === "openapi"
        ? await api.analyzeOpenapi(input.filename, input.content)
        : await api.analyzeNginx(input.filename, input.content);
    return { input, ok: true, result };
  } catch (err) {
    return { input, ok: false, error: message(err) };
  }
}

const sleep = (ms: number) =>
  new Promise<void>((r) => {
    window.setTimeout(r, ms);
  });

/** Holds the current scan session (static results + one optional runtime scan). */
export function ScanProvider({
  children,
  initial = { phase: "idle" },
}: {
  children: ReactNode;
  initial?: ScanState;
}) {
  const [state, setState] = useState<ScanState>(initial);
  const runtimeId = useRef<number | null>(null);

  const run = useCallback(async (inputs: ScanInput[]) => {
    const outcomes: InputOutcome[] = [];
    for (const input of inputs) {
      if (input.kind === "runtime") continue;
      setState({
        phase: "running",
        inputs,
        stage: "static",
        current: input.filename,
        runtime: null,
      });
      outcomes.push(await analyzeStatic(input));
    }
    const runtime = inputs.find((i): i is RuntimeInput => i.kind === "runtime");
    if (runtime) {
      const progress: RuntimeProgress = {
        scanId: null,
        done: 0,
        total: 0,
        current: "Starting",
        stopping: false,
      };
      const show = (p: RuntimeProgress) => {
        setState({
          phase: "running",
          inputs,
          stage: "runtime",
          current: runtime.label,
          runtime: { ...p },
        });
      };
      show(progress);
      try {
        let scan = await api.startRuntimeScan(runtime.request);
        runtimeId.current = scan.id;
        while (!FINAL.has(scan.status)) {
          Object.assign(progress, {
            scanId: scan.id,
            done: scan.progress?.done ?? 0,
            total: scan.progress?.total ?? 0,
            current: scan.progress?.current ?? "",
            stopping: scan.status === "cancelling",
          });
          show(progress);
          await sleep(POLL_MS);
          scan = await api.scan(scan.id);
        }
        outcomes.push(
          scan.status === "failed"
            ? { input: runtime, ok: false, error: scan.error ?? "Runtime scan failed" }
            : { input: runtime, ok: true, result: scan },
        );
      } catch (err) {
        outcomes.push({ input: runtime, ok: false, error: message(err) });
      } finally {
        runtimeId.current = null;
      }
    }
    const findings = sortFindings(outcomes.flatMap((o) => (o.ok ? o.result.findings : [])));
    setState({ phase: "done", inputs, outcomes, findings });
  }, []);

  const stop = useCallback(async () => {
    const id = runtimeId.current;
    if (id === null) return;
    setState((s) =>
      s.phase === "running" && s.runtime ? { ...s, runtime: { ...s.runtime, stopping: true } } : s,
    );
    try {
      await api.stopScan(id);
    } catch {
      /* the poll loop reports the final state */
    }
  }, []);

  const retry = useCallback(async () => {
    if (state.phase === "done") await run(state.inputs);
  }, [state, run]);

  const reset = useCallback(() => {
    setState({ phase: "idle" });
  }, []);

  const value = useMemo(
    () => ({ state, run, retry, stop, reset }),
    [state, run, retry, stop, reset],
  );
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useScan(): ScanApi {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used inside <ScanProvider>");
  return ctx;
}

/** Display name of an input (file name or runtime base URL). */
// eslint-disable-next-line react-refresh/only-export-components
export function inputLabel(input: ScanInput): string {
  return input.kind === "runtime" ? input.label : input.filename;
}
