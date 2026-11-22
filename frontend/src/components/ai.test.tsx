import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import correlated from "@/test/fixtures/session-correlated.json";
import remediation from "@/test/fixtures/remediation-legacy.json";
import { AiExplanation } from "@/components/AiExplanation";
import { AI_CAPTION } from "@/components/AiPanel";
import { AiFixPanel } from "@/components/AiFixPanel";
import { AiSettings } from "@/components/AiSettings";
import type { AiExplainResult, AiFixResult, AiStatus, Finding, Session } from "@/lib/types";

const FINDING = (correlated as Session).findings.find((f) => f.rule_id === "NGX-TLS-001")!;
const EXPLAINED: Finding = {
  ...FINDING,
  ai_explanation: {
    text: "TLS 1.0 is enabled.\n\nImpact: downgrade attacks.\n\nSteps:\n1. Use TLS 1.2+.",
    model: "qwen3:4b@abcdef012345",
    prompt_version: "explain-v1",
    generated_at: "2026-11-22T10:00:00+00:00",
  },
};
const READY: AiExplainResult = {
  state: "ready",
  message: null,
  fallback: "Template text.",
  injection_suspected: false,
  cached: false,
  finding: EXPLAINED,
};

let calls: { url: string; init: RequestInit }[];
function respond(handler: (url: string, init: RequestInit) => unknown) {
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, init });
      return Promise.resolve(new Response(JSON.stringify(handler(url, init)), { status: 200 }));
    }),
  );
}
const body = (i: number) => JSON.parse(calls[i]!.init.body as string) as Record<string, unknown>;

beforeEach(() => {
  vi.stubEnv("VITE_MAGEN_API_URL", "http://127.0.0.1:9");
  vi.stubEnv("VITE_MAGEN_TOKEN", "t");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("AiExplanation", () => {
  it("fetches on expand, shows provenance, and regenerates with force", async () => {
    respond(() => READY);
    render(<AiExplanation sessionId={3} finding={FINDING} fallback="Template text." />);
    expect(calls).toHaveLength(0); // nothing is sent until the user asks
    await userEvent.click(screen.getByRole("button", { name: /AI explanation/ }));
    expect(await screen.findByText(/TLS 1.0 is enabled/)).toBeInTheDocument();
    expect(screen.getByText(AI_CAPTION)).toBeInTheDocument();
    expect(screen.getByText(/qwen3:4b@abcdef012345/)).toBeInTheDocument();
    expect(screen.getByText(/prompt explain-v1/)).toBeInTheDocument();
    expect(body(0)).toEqual({ session_id: 3, finding_id: FINDING.id, force: false });
    await userEvent.click(screen.getByRole("button", { name: "Regenerate AI explanation" }));
    await waitFor(() => {
      expect(calls).toHaveLength(2);
    });
    expect(body(1).force).toBe(true);
  });

  it("shows a stored explanation without a request", () => {
    respond(() => READY);
    render(<AiExplanation sessionId={3} finding={EXPLAINED} fallback="x" />);
    expect(screen.getByText(/TLS 1.0 is enabled/)).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });

  it("falls back to the deterministic text, without the AI caption, when unavailable", async () => {
    respond(() => ({
      ...READY,
      state: "unavailable",
      message: "Model qwen3:4b is not installed",
      finding: FINDING,
    }));
    render(<AiExplanation sessionId={3} finding={FINDING} fallback="Template text." />);
    await userEvent.click(screen.getByRole("button", { name: /AI explanation/ }));
    expect(await screen.findByText(/Model qwen3:4b is not installed/)).toBeInTheDocument();
    expect(screen.getByText("Template text.")).toBeInTheDocument();
    expect(screen.queryByText(AI_CAPTION)).toBeNull();
  });

  it("warns when the scanned content looks like it addresses an AI", async () => {
    respond(() => ({ ...READY, injection_suspected: true }));
    render(<AiExplanation sessionId={3} finding={FINDING} fallback="x" />);
    await userEvent.click(screen.getByRole("button", { name: /AI explanation/ }));
    expect(await screen.findByRole("note")).toHaveTextContent("looks like instructions to an AI");
  });

  it("reports errors with a retry", async () => {
    respond(() => ({
      ...READY,
      state: "error",
      message: "The model's answer did not match the required format",
      finding: FINDING,
    }));
    render(<AiExplanation sessionId={3} finding={FINDING} fallback="Template text." />);
    await userEvent.click(screen.getByRole("button", { name: /AI explanation/ }));
    expect(await screen.findByText(/did not match the required format/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

const FIX: AiFixResult = {
  state: "ready",
  message: null,
  fallback: "x",
  injection_suspected: false,
  explanation: "Only modern TLS versions remain enabled.",
  diff: (remediation as { diff: string }).diff,
  patched_content: "events {}",
  patched_filename: "legacy-tls.magen-fixed.conf",
  validated: true,
  validation: {
    parsed: true,
    error: null,
    introduced: [],
    syntax: { status: "unavailable", message: "" },
  },
  model: "qwen3:4b@abcdef012345",
  prompt_version: "fix-v1",
};
const SOURCE = { kind: "nginx" as const, filename: "legacy-tls.conf", content: "events {}" };

describe("AiFixPanel", () => {
  it("shows a validated suggestion with export and AI provenance", async () => {
    respond(() => FIX);
    render(<AiFixPanel sessionId={3} findingId={FINDING.id} source={SOURCE} />);
    await userEvent.click(screen.getByRole("button", { name: /Ask AI for a fix/ }));
    const panel = await screen.findByRole("region", { name: "AI-suggested fix" });
    expect(within(panel).getByText(/Validated: the file still parses/)).toBeInTheDocument();
    expect(
      within(panel).getByRole("button", { name: /Export legacy-tls.magen-fixed.conf/ }),
    ).toBeInTheDocument();
    expect(within(panel).getByText(AI_CAPTION)).toBeInTheDocument();
    expect(body(0)).toEqual({
      session_id: 3,
      finding_id: FINDING.id,
      kind: "nginx",
      filename: "legacy-tls.conf",
      content: "events {}",
    });
  });

  it("refuses to offer an unvalidated suggestion for export", async () => {
    respond(() => ({
      ...FIX,
      validated: false,
      validation: { ...FIX.validation!, introduced: [FINDING] },
    }));
    render(<AiFixPanel sessionId={3} findingId={FINDING.id} source={SOURCE} />);
    await userEvent.click(screen.getByRole("button", { name: /Ask AI for a fix/ }));
    expect(await screen.findByText(/would introduce NGX-TLS-001/)).toBeInTheDocument();
    expect(screen.getByText(/Do not use it as is/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Export/ })).toBeNull();
  });

  it("points back to the template fix when AI is unavailable", async () => {
    respond(() => ({ ...FIX, state: "unavailable", message: "Ollama is not running" }));
    render(<AiFixPanel sessionId={3} findingId={FINDING.id} source={SOURCE} />);
    await userEvent.click(screen.getByRole("button", { name: /Ask AI for a fix/ }));
    expect(await screen.findByText(/AI unavailable: Ollama is not running/)).toBeInTheDocument();
  });
});

const STATUS: AiStatus = {
  state: "ready",
  enabled: true,
  url: "http://127.0.0.1:11434",
  model: "qwen3:4b",
  version: "0.9.0",
  models: ["qwen3:4b"],
  pull: null,
};

describe("AiSettings", () => {
  it.each([
    ["ready", "Ready"],
    ["disabled", "Turned off"],
    ["not_running", "Ollama is not running"],
    ["model_missing", "Model not installed"],
  ] as const)("shows state %s with icon and text", async (state, label) => {
    respond(() => ({ ...STATUS, state }));
    render(<AiSettings />);
    expect(await screen.findByRole("status")).toHaveTextContent(label);
  });

  it("downloads a missing model and polls progress until ready", async () => {
    let polls = 0;
    respond((url) => {
      if (url.endsWith("/api/ai/pull"))
        return {
          ...STATUS,
          state: "downloading",
          pull: { model: "qwen3:4b", status: "downloading", percent: 40, error: null, done: false },
        };
      polls += 1;
      return polls === 1 ? { ...STATUS, state: "model_missing", models: [] } : STATUS;
    });
    render(<AiSettings pollMs={10} />);
    await userEvent.click(await screen.findByRole("button", { name: /Download qwen3:4b/ }));
    expect(await screen.findByRole("progressbar", { name: "Model download" })).toHaveAttribute(
      "aria-valuenow",
      "40",
    );
    expect(await screen.findByText("Ready")).toBeInTheDocument();
  });

  it("toggles AI and keeps the URL read-only (no cloud)", async () => {
    respond((_url, init) =>
      init.method === "PUT" ? { ...STATUS, state: "disabled", enabled: false } : STATUS,
    );
    render(<AiSettings />);
    await userEvent.click(await screen.findByLabelText("Use AI explanations and fix suggestions"));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Turned off");
    });
    expect(body(1)).toEqual({ enabled: false });
    expect(screen.getByLabelText("Ollama URL")).toHaveAttribute("readonly");
  });
});
