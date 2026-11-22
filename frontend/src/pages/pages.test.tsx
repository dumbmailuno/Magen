import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import correlated from "@/test/fixtures/session-correlated.json";
import mixed from "@/test/fixtures/session-mixed.json";
import retestFixture from "@/test/fixtures/session-retest.json";
import snippet from "@/test/fixtures/session-snippet.json";
import remediation from "@/test/fixtures/remediation-legacy.json";
import { resetRulesCache } from "@/lib/rules";
import { ScanProvider, type ScanState, type StaticInput } from "@/lib/scan";
import type { Session } from "@/lib/types";
import { FindingsPage } from "./FindingsPage";
import { NewScanPage } from "./NewScanPage";

const MIXED = mixed as Session;
const SNIPPET = snippet as Session;
const CORRELATED = correlated as Session;
const RETEST = retestFixture as Session;

const NO_AUTH: StaticInput = {
  kind: "openapi",
  filename: "no-auth.yaml",
  content: "openapi: 3.1.0",
};
const LEGACY: StaticInput = { kind: "nginx", filename: "legacy-tls.conf", content: "events {}" };

function done(
  session: Session | null,
  inputs: StaticInput[] = [NO_AUTH, LEGACY],
  extra: Partial<Extract<ScanState, { phase: "done" }>> = {},
): ScanState {
  return {
    phase: "done",
    request: { inputs, baselineId: null },
    session,
    runtime: null,
    runtimeError: null,
    error: null,
    ...extra,
  };
}

function LocationProbe() {
  const loc = useLocation();
  return <output data-testid="location">{`${loc.pathname}${loc.search}`}</output>;
}

function renderAt(path: string, initial: ScanState) {
  return render(
    <ScanProvider initial={initial}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/scan" element={<NewScanPage />} />
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    </ScanProvider>,
  );
}

let fetchMock: ReturnType<typeof vi.fn<(url: string, init: RequestInit) => Promise<Response>>>;

/** Parsed JSON body of the first request matching `pred`. */
function sentBody(pred: (url: string, init: RequestInit) => boolean): Record<string, unknown> {
  const call = fetchMock.mock.calls.find(([u, i]) => pred(u, i));
  if (!call) throw new Error("request not sent");
  return JSON.parse(call[1].body as string) as Record<string, unknown>;
}
function routes(handler: (url: string, init: RequestInit) => unknown) {
  fetchMock = vi.fn((url: string, init: RequestInit) => {
    const body = handler(url, init);
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  });
  vi.stubGlobal("fetch", fetchMock);
}

beforeEach(() => {
  vi.stubEnv("VITE_MAGEN_API_URL", "http://127.0.0.1:9");
  vi.stubEnv("VITE_MAGEN_TOKEN", "test-token");
  resetRulesCache();
  routes(() => []);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("FindingsPage", () => {
  it("shows an empty state before any scan", () => {
    renderAt("/findings", { phase: "idle" });
    expect(screen.getByText("No scan yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /New scan/ })).toHaveAttribute("href", "/scan");
  });

  it("announces progress while running", () => {
    renderAt("/findings", {
      phase: "running",
      inputs: [],
      stage: "static",
      current: "petstore.yaml",
      runtime: null,
    });
    expect(screen.getByText("Analyzing petstore.yaml…")).toHaveAttribute("aria-live", "polite");
  });

  it("renders the session's findings, summary and the first finding's detail", () => {
    renderAt("/findings", done(MIXED));
    const options = within(screen.getByRole("listbox", { name: "Findings" })).getAllByRole(
      "option",
    );
    expect(options).toHaveLength(MIXED.findings.length);
    expect(options[0]).toHaveAttribute("aria-selected", "true");
    expect(options[0]).toHaveTextContent("NGX-TLS-"); // high severity first
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(MIXED.findings[0]!.title);
    expect(
      screen.getByText(`Session #${MIXED.id} · no-auth.yaml, legacy-tls.conf`, { exact: false }),
    ).toBeInTheDocument();
  });

  it("never offers to apply a fix to the user's files (Option B)", () => {
    renderAt("/findings", done(MIXED));
    expect(screen.queryByRole("button", { name: /apply/i })).toBeNull();
    expect(screen.getByRole("button", { name: /Export fix/ })).toBeInTheDocument();
  });

  it("filters via chips and persists filters in the URL", async () => {
    renderAt("/findings", done(MIXED));
    await userEvent.click(screen.getByRole("button", { name: "Severity low" }));
    expect(screen.getByTestId("location")).toHaveTextContent("sev=low");
    expect(screen.getAllByRole("option")).toHaveLength(
      MIXED.findings.filter((f) => f.severity === "low").length,
    );
  });

  it("restores filters from the URL and offers to clear when nothing matches", async () => {
    renderAt("/findings?sev=critical", done(MIXED));
    expect(screen.getByText("No findings match the filters")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]!);
    expect(screen.getAllByRole("option")).toHaveLength(MIXED.findings.length);
  });

  it("moves selection with the keyboard and keeps it in the URL", async () => {
    renderAt("/findings", done(MIXED));
    screen.getAllByRole("option")[0]!.focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    expect(document.activeElement).toBe(screen.getAllByRole("option")[1]);
    expect(screen.getByTestId("location")).toHaveTextContent(`f=${MIXED.findings[1]!.id}`);
    await userEvent.keyboard("{End}");
    expect(screen.getAllByRole("option").at(-1)).toHaveAttribute("aria-selected", "true");
  });

  it("shows a partial-results warning when one input failed", () => {
    const partial: Session = {
      ...MIXED,
      inputs: [
        ...MIXED.inputs,
        {
          kind: "nginx",
          filename: "bad.conf",
          sha256: "x",
          ok: false,
          error: "line 1: unexpected '}'",
          notes: [],
        },
      ],
    };
    renderAt("/findings", done(partial));
    expect(screen.getByText(/Partial results/)).toBeInTheDocument();
    expect(screen.getByText(/unexpected '}'/)).toBeInTheDocument();
  });

  it("shows an error with retry when the session could not be created, and retry re-runs", async () => {
    routes((url) => (url.endsWith("/api/sessions") ? MIXED : []));
    renderAt("/findings", done(null, [NO_AUTH, LEGACY], { error: "Backend is not reachable" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Backend is not reachable");
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getAllByRole("option")).toHaveLength(MIXED.findings.length);
    });
    const body = sentBody((u) => u.endsWith("/api/sessions")) as {
      inputs: { filename: string }[];
    };
    expect(body.inputs.map((i) => i.filename)).toEqual(["no-auth.yaml", "legacy-tls.conf"]);
  });

  it("explains inconclusive findings when config was not visible", () => {
    renderAt(
      "/findings",
      done(SNIPPET, [{ kind: "nginx", filename: "site-snippet.conf", content: "server {}" }]),
    );
    expect(screen.getByText("Coverage notes")).toBeInTheDocument();
    expect(screen.getByText(/snippets\/security-headers.conf \(line 7\)/)).toBeInTheDocument();
    expect(screen.getByText(/marked Inconclusive/)).toBeInTheDocument();
  });

  it("shows correlation counts for a session with a runtime scan", () => {
    renderAt("/findings", done(CORRELATED, [LEGACY]));
    expect(screen.getByText(/Correlation:/)).toHaveTextContent(
      "2 static findings confirmed at runtime",
    );
    expect(screen.getAllByText("Correlated").length).toBeGreaterThan(0);
  });

  it("shows the retest summary, marks new findings, and links to Compare", () => {
    renderAt("/findings", done(RETEST, [LEGACY]));
    const c = RETEST.comparison!;
    expect(
      screen.getByText(
        new RegExp(`Retest against session #${c.baseline_id}: 1 resolved · 2 persist · 0 new`),
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Compare/ })).toHaveAttribute(
      "href",
      `/compare?base=${c.baseline_id}&head=${c.current_id}`,
    );
    expect(screen.getByRole("link", { name: /Retest/ })).toHaveAttribute(
      "href",
      `/scan?baseline=${RETEST.id}`,
    );
  });

  it("generates a corrected copy for the selected finding and shows a validated diff", async () => {
    routes((url) => (url.endsWith("/api/remediation/preview") ? remediation : []));
    const tls = CORRELATED.findings.find((f) => f.rule_id === "NGX-TLS-001")!;
    renderAt(`/findings?f=${tls.id}`, done(CORRELATED, [LEGACY]));
    await userEvent.click(screen.getByRole("button", { name: "Generate corrected file" }));
    const panel = await screen.findByRole("region", { name: "Generated fix" });
    expect(within(panel).getAllByText(/Fixed · Validated/).length).toBeGreaterThan(0);
    expect(
      within(panel).getByRole("button", { name: /Export legacy-tls.magen-fixed.conf/ }),
    ).toBeInTheDocument();
    expect(within(panel).getAllByLabelText(/^added: /).length).toBeGreaterThan(0);
    const sent = sentBody((u) => u.endsWith("/api/remediation/preview"));
    expect(sent.finding_ids).toEqual([tls.id]);
    expect(sent.content).toBe("events {}");
  });

  it("shows a success empty state when nothing matched", () => {
    renderAt("/findings", done({ ...MIXED, findings: [] }));
    expect(screen.getByText("No findings")).toBeInTheDocument();
  });
});

describe("NewScanPage", () => {
  it("disables Start until a file is chosen, then creates a session and shows findings", async () => {
    routes((url, init) => (url.endsWith("/api/sessions") && init.method === "POST" ? MIXED : []));
    render(
      <ScanProvider>
        <MemoryRouter initialEntries={["/scan"]}>
          <Routes>
            <Route path="/scan" element={<NewScanPage />} />
            <Route path="/findings" element={<FindingsPage />} />
          </Routes>
        </MemoryRouter>
      </ScanProvider>,
    );
    const start = screen.getByRole("button", { name: /Start scan/ });
    expect(start).toBeDisabled();
    await userEvent.upload(
      screen.getByLabelText("OpenAPI spec"),
      new File(["openapi: 3.0.0"], "spec.yaml"),
    );
    await userEvent.click(start);
    await waitFor(() => {
      expect(screen.getAllByRole("option")).toHaveLength(MIXED.findings.length);
    });
    expect(sentBody((u, i) => u.endsWith("/api/sessions") && i.method === "POST")).toEqual({
      inputs: [{ kind: "openapi", filename: "spec.yaml", content: "openapi: 3.0.0" }],
    });
  });

  it("sends the chosen baseline for a retest", async () => {
    routes((url, init) => {
      if (url.endsWith("/api/sessions") && init.method === "POST") return RETEST;
      if (url.endsWith("/api/sessions"))
        return [
          {
            id: 4,
            created_at: "2026-11-22T10:00:00+00:00",
            inputs: ["legacy-tls.conf"],
            runtime_scan_id: null,
            baseline_id: null,
            total: 3,
            by_severity: {},
          },
        ];
      return [];
    });
    renderAt("/scan?baseline=4", { phase: "idle" });
    expect(await screen.findByRole("option", { name: /#4 · legacy-tls.conf/ })).toBeInTheDocument();
    expect(screen.getByLabelText("Compare with a previous session")).toHaveValue("4");
    await userEvent.upload(
      screen.getByLabelText("Nginx config"),
      new File(["events {}"], "legacy-tls.conf"),
    );
    await userEvent.click(screen.getByRole("button", { name: /Start scan/ }));
    await waitFor(() => {
      expect(
        sentBody((u, i) => u.endsWith("/api/sessions") && i.method === "POST").baseline_id,
      ).toBe(4);
    });
  });

  it("rejects files over 5 MB before sending anything", async () => {
    renderAt("/scan", { phase: "idle" });
    const big = new File(["x"], "big.yaml");
    Object.defineProperty(big, "size", { value: 6 * 1024 * 1024 });
    await userEvent.upload(screen.getByLabelText("OpenAPI spec"), big);
    expect(screen.getByText("File is larger than 5 MB.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Start scan/ })).toBeDisabled();
  });
});

describe("RemediationPanel template-only", () => {
  it("explains when no automatic fix exists", async () => {
    const { RemediationPanel } = await import("@/components/RemediationPanel");
    const { default: cors } = await import("@/test/fixtures/remediation-cors.json");
    routes(() => cors);
    render(<RemediationPanel kind="nginx" filename="cors.conf" content="x" />);
    await userEvent.click(screen.getByRole("button", { name: "Generate corrected file" }));
    expect((await screen.findAllByText(/Template only — needs your decision/)).length).toBe(2);
    expect(screen.queryByRole("button", { name: /Export/ })).toBeNull(); // nothing applied, nothing to export
  });
});
