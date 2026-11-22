import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import legacy from "@/test/fixtures/nginx-legacy-tls.json";
import correlated from "@/test/fixtures/session-correlated.json";
import { resetRulesCache } from "@/lib/rules";
import { ScanProvider } from "@/lib/scan";
import type { Finding, NginxResult, RuntimeScan, Session, Target } from "@/lib/types";
import { FindingsPage } from "./FindingsPage";
import { NewScanPage } from "./NewScanPage";
import { TargetsPage } from "./TargetsPage";

const TARGET: Target = {
  id: 7,
  host: "127.0.0.1",
  is_local: true,
  authorized_at: "2026-11-22T10:00:00+00:00",
  created_at: "2026-11-22T10:00:00+00:00",
};
const RUNTIME_FINDING: Finding = {
  ...(legacy as NginxResult).findings[0]!,
  id: "rt0000000000000000aa",
  rule_id: "API-RT-006",
  title: "Software version is disclosed (Server: TestServer/1.2.3)",
  status: "confirmed",
  source: "runtime",
  evidence: [
    {
      kind: "http",
      location: {
        file: null,
        line: null,
        end_line: null,
        pointer: "probe:base-get",
        url: "http://127.0.0.1:5000/",
      },
      excerpt: "Server: TestServer/1.2.3",
      request: "GET http://127.0.0.1:5000/\nAuthorization: ••••",
      response: "HTTP 200\nserver: TestServer/1.2.3",
    },
  ],
};

const RUNTIME_SESSION: Session = {
  ...(correlated as Session),
  inputs: [],
  runtime_scan_id: 42,
  findings: [RUNTIME_FINDING],
};

function scan(
  status: RuntimeScan["status"],
  done: number,
  extra: Partial<RuntimeScan> = {},
): RuntimeScan {
  return {
    id: 42,
    status,
    target_host: "127.0.0.1",
    base_url: "http://127.0.0.1:5000/",
    progress: { done, total: 9, current: "GET /.git/HEAD" },
    started_at: "2026-11-22T10:00:00+00:00",
    finished_at: status === "running" ? null : "2026-11-22T10:00:03+00:00",
    error: null,
    notes: [],
    findings: [],
    ...extra,
  };
}

type Route_ = (url: string, init: RequestInit) => unknown;
let routes: Route_;
let calls: { url: string; init: RequestInit }[];

beforeEach(() => {
  vi.stubEnv("VITE_MAGEN_API_URL", "http://127.0.0.1:9");
  vi.stubEnv("VITE_MAGEN_TOKEN", "t");
  resetRulesCache();
  calls = [];
  routes = (url) => (url.endsWith("/api/targets") || url.endsWith("/api/rules") ? [] : {});
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, init });
      const body = routes(url, init);
      if (body instanceof Response) return Promise.resolve(body);
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function app(path: string) {
  return render(
    <ScanProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/scan" element={<NewScanPage />} />
          <Route path="/findings" element={<FindingsPage />} />
        </Routes>
      </MemoryRouter>
    </ScanProvider>,
  );
}

describe("TargetsPage", () => {
  it("requires the authorization checkbox before a host can be added", async () => {
    routes = (url, init) => {
      if (url.endsWith("/api/targets") && init.method === "POST") return TARGET;
      return [];
    };
    app("/targets");
    expect(await screen.findByText("No targets yet")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Host"), "127.0.0.1");
    const add = screen.getByRole("button", { name: /Add target/ });
    expect(add).toBeDisabled();
    expect(screen.getByText(/Only scan systems you own/)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText(/Local lab target/));
    await userEvent.click(screen.getByLabelText(/I own this host or have written permission/));
    await userEvent.click(add);
    expect(await screen.findByRole("cell", { name: "127.0.0.1" })).toBeInTheDocument();
    const post = calls.find((c) => c.init.method === "POST");
    expect(JSON.parse(post!.init.body as string)).toEqual({
      host: "127.0.0.1",
      is_local: true,
      authorization_confirmed: true,
    });
  });

  it("shows the backend's validation message", async () => {
    routes = (_url, init) => {
      if (init.method === "POST")
        return new Response(
          JSON.stringify({
            code: "validation_failed",
            message: "10.0.0.5 is an internal address",
            detail: null,
          }),
          { status: 422 },
        );
      return [];
    };
    app("/targets");
    await userEvent.type(screen.getByLabelText("Host"), "10.0.0.5");
    await userEvent.click(screen.getByLabelText(/I own this host/));
    await userEvent.click(screen.getByRole("button", { name: /Add target/ }));
    expect(await screen.findByText("10.0.0.5 is an internal address")).toBeInTheDocument();
  });

  it("asks for confirmation before removing a target", async () => {
    routes = (url, init) =>
      init.method === "DELETE" ? null : url.endsWith("/api/targets") ? [TARGET] : [];
    app("/targets");
    await userEvent.click(await screen.findByRole("button", { name: "Remove 127.0.0.1" }));
    expect(calls.some((c) => c.init.method === "DELETE")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Confirm remove" }));
    await waitFor(() => {
      expect(
        calls.some((c) => c.init.method === "DELETE" && c.url.endsWith("/api/targets/7")),
      ).toBe(true);
    });
  });
});

describe("Runtime scan flow", () => {
  it("validates that the base URL is on the chosen target", async () => {
    routes = (url) => (url.endsWith("/api/targets") ? [TARGET] : []);
    app("/scan");
    await userEvent.selectOptions(await screen.findByLabelText("Target"), "7");
    await userEvent.type(screen.getByLabelText("Base URL"), "http://evil.example.com/");
    expect(screen.getByText("The URL must be on 127.0.0.1.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Start scan/ })).toBeDisabled();
  });

  it("starts, shows live progress with Stop, then shows runtime findings and the probe log", async () => {
    let polls = 0;
    routes = (url, init) => {
      if (url.endsWith("/api/targets")) return [TARGET];
      if (url.endsWith("/api/scans/runtime")) return scan("running", 0);
      if (url.endsWith("/api/scans/42/audit"))
        return [
          {
            sent_at: "2026-11-22T10:00:01.123+00:00",
            method: "GET",
            url: "http://127.0.0.1:5000/",
            status_code: 200,
            error: null,
          },
        ];
      if (url.endsWith("/api/scans/42/stop")) return scan("cancelling", 3);
      if (url.endsWith("/api/sessions") && init.method === "POST") return RUNTIME_SESSION;
      if (url.endsWith("/api/scans/42")) {
        polls += 1;
        return polls < 3
          ? scan("running", polls * 3)
          : scan("done", 9, { findings: [RUNTIME_FINDING] });
      }
      return [];
    };
    app("/scan");
    await userEvent.selectOptions(await screen.findByLabelText("Target"), "7");
    await userEvent.type(screen.getByLabelText("Base URL"), "http://127.0.0.1:5000/");
    await userEvent.type(screen.getByLabelText(/Auth header value/), "Bearer xyz");
    await userEvent.click(screen.getByRole("button", { name: /Start scan/ }));

    expect(await screen.findByRole("button", { name: "Stop" })).toBeInTheDocument();
    expect(await screen.findByText(/Probing \d\/9 · GET \/\.git\/HEAD/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Runtime probes" })).toHaveAttribute(
      "aria-valuemax",
      "9",
    );

    const start = calls.find((c) => c.url.endsWith("/api/scans/runtime"));
    expect(JSON.parse(start!.init.body as string)).toEqual({
      target_id: 7,
      base_url: "http://127.0.0.1:5000/",
      rate_per_second: 5,
      request_cap: 50,
      auth_header: { name: "Authorization", value: "Bearer xyz" },
    });

    const list = await screen.findByRole("listbox", {}, { timeout: 4000 });
    expect(within(list).getByText(/Software version is disclosed/)).toBeInTheDocument();
    const post = calls.find((c) => c.url.endsWith("/api/sessions") && c.init.method === "POST");
    expect(JSON.parse(post!.init.body as string)).toEqual({ inputs: [], runtime_scan_id: 42 });
    expect(screen.getByText(/Probe log/)).toBeInTheDocument();
    expect(await screen.findByText("(1 requests)", { exact: false })).toBeInTheDocument();
  });

  it("Stop calls the stop endpoint and shows the stopping state", async () => {
    routes = (url) => {
      if (url.endsWith("/api/targets")) return [TARGET];
      if (url.endsWith("/api/scans/runtime")) return scan("running", 1);
      if (url.endsWith("/api/scans/42/stop")) return scan("cancelling", 1);
      if (url.endsWith("/api/scans/42")) return scan("running", 1);
      return [];
    };
    app("/scan");
    await userEvent.selectOptions(await screen.findByLabelText("Target"), "7");
    await userEvent.type(screen.getByLabelText("Base URL"), "http://127.0.0.1:5000/");
    await userEvent.click(screen.getByRole("button", { name: /Start scan/ }));
    await userEvent.click(await screen.findByRole("button", { name: "Stop" }));
    expect(
      calls.some((c) => c.url.endsWith("/api/scans/42/stop") && c.init.method === "POST"),
    ).toBe(true);
    expect(await screen.findByText(/Stopping…/, { selector: "p" })).toBeInTheDocument();
  });

  it("reports a failed runtime scan with its reason", async () => {
    routes = (url) => {
      if (url.endsWith("/api/targets")) return [TARGET];
      if (url.endsWith("/api/scans/runtime"))
        return scan("failed", 0, {
          error: "localhost resolves to an internal address (127.0.0.1).",
        });
      return [];
    };
    app("/scan");
    await userEvent.selectOptions(await screen.findByLabelText("Target"), "7");
    await userEvent.type(screen.getByLabelText("Base URL"), "http://127.0.0.1:5000/");
    await userEvent.click(screen.getByRole("button", { name: /Start scan/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("internal address");
  });
});
