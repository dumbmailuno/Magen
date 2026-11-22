import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import legacy from "@/test/fixtures/nginx-legacy-tls.json";
import snippet from "@/test/fixtures/nginx-site-snippet.json";
import noAuth from "@/test/fixtures/openapi-no-auth.json";
import { sortFindings } from "@/lib/findings";
import { resetRulesCache } from "@/lib/rules";
import { ScanProvider, type ScanState } from "@/lib/scan";
import type { NginxResult, OpenApiResult } from "@/lib/types";
import { FindingsPage } from "./FindingsPage";
import { NewScanPage } from "./NewScanPage";

const OAS = noAuth as OpenApiResult;
const NGX = legacy as NginxResult;
const SNIP = snippet as NginxResult;

function done(outcomes: Extract<ScanState, { phase: "done" }>["outcomes"]): ScanState {
  return {
    phase: "done",
    inputs: outcomes.map((o) => o.input),
    outcomes,
    findings: sortFindings(outcomes.flatMap((o) => (o.ok ? o.result.findings : []))),
  };
}

const oasOk = {
  input: { kind: "openapi" as const, filename: "no-auth.yaml", content: "x" },
  ok: true as const,
  result: OAS,
};
const ngxOk = {
  input: { kind: "nginx" as const, filename: "legacy-tls.conf", content: "y" },
  ok: true as const,
  result: NGX,
};
const ngxFail = {
  input: { kind: "nginx" as const, filename: "bad.conf", content: "z" },
  ok: false as const,
  error: "line 1: unexpected '}'",
};

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

function mockFetch(handler: (url: string, init: RequestInit) => unknown) {
  const fetchMock = vi.fn((url: string, init: RequestInit) => {
    const body = handler(url, init);
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(() => {
  vi.stubEnv("VITE_MAGEN_API_URL", "http://127.0.0.1:9");
  vi.stubEnv("VITE_MAGEN_TOKEN", "test-token");
  resetRulesCache();
  mockFetch((url) => (url.endsWith("/api/rules") ? [] : {}));
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
    renderAt("/findings", { phase: "running", inputs: [], current: "petstore.yaml" });
    expect(screen.getByText("Analyzing petstore.yaml…")).toHaveAttribute("aria-live", "polite");
  });

  it("renders merged findings, summary and the first finding's detail", () => {
    renderAt("/findings", done([oasOk, ngxOk]));
    const list = screen.getByRole("listbox", { name: "Findings" });
    expect(within(list).getAllByRole("option")).toHaveLength(
      OAS.findings.length + NGX.findings.length,
    );
    const first = within(list).getAllByRole("option")[0]!;
    expect(first).toHaveAttribute("aria-selected", "true");
    // High-severity nginx findings sort before medium OpenAPI ones.
    expect(first).toHaveTextContent("NGX-TLS-");
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(NGX.findings[0]!.title);
    expect(screen.getByText("Template fix")).toBeInTheDocument();
    expect(screen.getByText("Not validated")).toBeInTheDocument();
  });

  it("never offers to apply a fix to the user's files (Option B)", () => {
    renderAt("/findings", done([oasOk, ngxOk]));
    expect(screen.queryByRole("button", { name: /apply/i })).toBeNull();
    expect(screen.getByRole("button", { name: /Export fix/ })).toBeInTheDocument();
  });

  it("filters via chips and persists filters in the URL", async () => {
    renderAt("/findings", done([oasOk, ngxOk]));
    await userEvent.click(screen.getByRole("button", { name: "Severity low" }));
    expect(screen.getByTestId("location")).toHaveTextContent("sev=low");
    const options = within(screen.getByRole("listbox")).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(
      expect.arrayContaining([expect.stringContaining("API-OAS-008")]),
    );
    expect(options).toHaveLength(OAS.findings.filter((f) => f.severity === "low").length);
  });

  it("restores filters from the URL and offers to clear when nothing matches", async () => {
    renderAt("/findings?sev=critical", done([oasOk]));
    expect(screen.getByText("No findings match the filters")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]!);
    expect(screen.getAllByRole("option").length).toBe(OAS.findings.length);
  });

  it("moves selection with the keyboard and keeps it in the URL", async () => {
    renderAt("/findings", done([oasOk]));
    const options = screen.getAllByRole("option");
    options[0]!.focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    expect(document.activeElement).toBe(screen.getAllByRole("option")[1]);
    expect(screen.getByTestId("location")).toHaveTextContent(`f=${OAS.findings[1]!.id}`);
    await userEvent.keyboard("{End}");
    expect(screen.getAllByRole("option").at(-1)).toHaveAttribute("aria-selected", "true");
  });

  it("shows a partial-results warning with retry when one input failed", () => {
    renderAt("/findings", done([oasOk, ngxFail]));
    expect(screen.getByText(/Partial results: 1 of 2 inputs/)).toBeInTheDocument();
    expect(screen.getByText(/unexpected '}'/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows an error with retry when every input failed, and retrying re-runs the scan", async () => {
    const fetchMock = mockFetch((url) => (url.endsWith("/api/rules") ? [] : NGX));
    renderAt("/findings", done([ngxFail]));
    expect(screen.getByRole("alert")).toHaveTextContent("The scan failed");
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getAllByRole("option")).toHaveLength(NGX.findings.length);
    });
    expect(fetchMock.mock.calls.some(([u]) => u.endsWith("/api/analyze/nginx"))).toBe(true);
  });

  it("explains inconclusive findings when config was not visible", () => {
    const snipOk = {
      input: { kind: "nginx" as const, filename: "site-snippet.conf", content: "s" },
      ok: true as const,
      result: SNIP,
    };
    renderAt("/findings", done([snipOk]));
    expect(screen.getByText("Some configuration was not visible")).toBeInTheDocument();
    expect(screen.getByText(/snippets\/security-headers.conf \(line 7\)/)).toBeInTheDocument();
    expect(screen.getAllByText("Inconclusive").length).toBeGreaterThan(0);
  });

  it("shows a success empty state when nothing matched", () => {
    const clean = { ...oasOk, result: { ...OAS, findings: [] } };
    renderAt("/findings", done([clean]));
    expect(screen.getByText("No findings")).toBeInTheDocument();
  });
});

describe("NewScanPage", () => {
  it("disables Start until a file is chosen, then analyzes and shows findings", async () => {
    const fetchMock = mockFetch((url) => {
      if (url.endsWith("/api/analyze/openapi")) return OAS;
      return [];
    });
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
    const file = new File(["openapi: 3.0.0"], "spec.yaml", { type: "application/yaml" });
    await userEvent.upload(screen.getByLabelText("OpenAPI spec"), file);
    expect(start).toBeEnabled();
    await userEvent.click(start);
    await waitFor(() => {
      expect(screen.getAllByRole("option")).toHaveLength(OAS.findings.length);
    });
    const call = fetchMock.mock.calls.find(([u]) => u.endsWith("/api/analyze/openapi"));
    expect(JSON.parse(call![1].body as string)).toEqual({
      filename: "spec.yaml",
      content: "openapi: 3.0.0",
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
