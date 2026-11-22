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
import type { InputKind, RuntimeScan, RuntimeScanRequest, Session } from "./types";

export interface StaticInput {
  kind: InputKind;
  filename: string;
  /** Kept in renderer memory so fixes can be generated; never persisted by the backend. */
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

export interface RuntimeProgress {
  scanId: number | null;
  done: number;
  total: number;
  current: string;
  stopping: boolean;
}

export interface ScanRequest {
  inputs: ScanInput[];
  baselineId: number | null;
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
  | {
      phase: "done";
      request: ScanRequest;
      /** Null when the session could not be created (see ``error``). */
      session: Session | null;
      runtime: RuntimeScan | null;
      runtimeError: string | null;
      error: string | null;
    };

interface ScanApi {
  state: ScanState;
  run: (request: ScanRequest) => Promise<void>;
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

const sleep = (ms: number) =>
  new Promise<void>((r) => {
    window.setTimeout(r, ms);
  });

/** Display name of an input (file name or runtime base URL). */
// eslint-disable-next-line react-refresh/only-export-components
export function inputLabel(input: ScanInput): string {
  return input.kind === "runtime" ? input.label : input.filename;
}

/**
 * Runs a scan: the runtime scan first (polled, stoppable), then one session request that
 * analyses the static inputs, correlates them with the runtime scan and persists results.
 */
export function ScanProvider({
  children,
  initial = { phase: "idle" },
}: {
  children: ReactNode;
  initial?: ScanState;
}) {
  const [state, setState] = useState<ScanState>(initial);
  const runtimeId = useRef<number | null>(null);

  const run = useCallback(async (request: ScanRequest) => {
    const { inputs } = request;
    const statics = inputs.filter((i): i is StaticInput => i.kind !== "runtime");
    const runtimeInput = inputs.find((i): i is RuntimeInput => i.kind === "runtime");
    let runtime: RuntimeScan | null = null;
    let runtimeError: string | null = null;

    if (runtimeInput) {
      const progress: RuntimeProgress = {
        scanId: null,
        done: 0,
        total: 0,
        current: "Starting",
        stopping: false,
      };
      const show = () => {
        setState({
          phase: "running",
          inputs,
          stage: "runtime",
          current: runtimeInput.label,
          runtime: { ...progress },
        });
      };
      show();
      try {
        let scan = await api.startRuntimeScan(runtimeInput.request);
        runtimeId.current = scan.id;
        while (!FINAL.has(scan.status)) {
          Object.assign(progress, {
            scanId: scan.id,
            done: scan.progress?.done ?? 0,
            total: scan.progress?.total ?? 0,
            current: scan.progress?.current ?? "",
            stopping: scan.status === "cancelling",
          });
          show();
          await sleep(POLL_MS);
          scan = await api.scan(scan.id);
        }
        if (scan.status === "failed") runtimeError = scan.error ?? "Runtime scan failed";
        else runtime = scan;
      } catch (err) {
        runtimeError = message(err);
      } finally {
        runtimeId.current = null;
      }
    }

    const label = statics.map((s) => s.filename).join(", ") || runtimeInput?.label || "";
    setState({ phase: "running", inputs, stage: "static", current: label, runtime: null });
    let session: Session | null = null;
    let error: string | null = null;
    if (statics.length > 0 || runtime) {
      try {
        session = await api.createSession({
          inputs: statics.map(({ kind, filename, content }) => ({ kind, filename, content })),
          ...(runtime ? { runtime_scan_id: runtime.id } : {}),
          ...(request.baselineId !== null ? { baseline_id: request.baselineId } : {}),
        });
      } catch (err) {
        error = message(err);
      }
    }
    setState({ phase: "done", request, session, runtime, runtimeError, error });
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
    if (state.phase === "done") await run(state.request);
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
