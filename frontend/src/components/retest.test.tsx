import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import remediation from "@/test/fixtures/remediation-legacy.json";
import retestFixture from "@/test/fixtures/session-retest.json";
import sessions from "@/test/fixtures/sessions.json";
import { CompareView } from "@/components/CompareView";
import { DiffView, parseUnifiedDiff } from "@/components/DiffView";
import type { Session } from "@/lib/types";
import { ComparePage } from "@/pages/ComparePage";

const DIFF = (remediation as { diff: string }).diff;
const COMPARISON = (retestFixture as Session).comparison!;
const REMOVED = DIFF.split("\n").filter((l) => l.startsWith("-") && !l.startsWith("---")).length;

describe("DiffView", () => {
  it("parses line numbers from hunk headers", () => {
    const rows = parseUnifiedDiff("--- a/x\n+++ b/x\n@@ -3,2 +3,3 @@\n keep\n-old\n+new\n+extra");
    expect(rows.map((r) => r.kind)).toEqual(["hunk", "context", "del", "add", "add"]);
    expect(rows[1]).toMatchObject({ oldNo: 3, newNo: 3 });
    expect(rows[2]).toMatchObject({ oldNo: 4, newNo: null });
    expect(rows[4]).toMatchObject({ oldNo: null, newNo: 5 });
  });

  it("marks changes with glyphs and accessible labels, not only colour", () => {
    render(<DiffView diff={DIFF} filename="legacy-tls.conf" />);
    expect(screen.getAllByLabelText(/^removed: /).length).toBe(REMOVED);
    expect(screen.getAllByLabelText(/^added: /).length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("−").length).toBe(REMOVED);
    expect(REMOVED).toBeGreaterThan(0);
  });

  it("switches to split view", async () => {
    render(<DiffView diff={DIFF} filename="legacy-tls.conf" />);
    await userEvent.click(screen.getByLabelText("Split"));
    expect(screen.getByLabelText("Split")).toBeChecked();
    expect(screen.getAllByLabelText(/^removed: /).length).toBe(REMOVED);
  });

  it("handles an empty diff", () => {
    render(<DiffView diff="" filename="x" />);
    expect(screen.getByText("No changes.")).toBeInTheDocument();
  });
});

describe("CompareView", () => {
  it("shows resolved / persists / new with counts and the remediation rate", () => {
    render(<CompareView comparison={COMPARISON} />);
    expect(screen.getByRole("status")).toHaveTextContent(
      "33% of baseline findings resolved (1 of 3)",
    );
    expect(screen.getByRole("status")).toHaveTextContent("Changed inputs: legacy-tls.conf");
    const resolved = screen.getByRole("region", { name: "Resolved" });
    expect(within(resolved).getByText(/Obsolete protocols/)).toBeInTheDocument();
    expect(
      within(screen.getByRole("region", { name: "New" })).getByText("No new findings."),
    ).toBeInTheDocument();
  });
});

describe("CompareView still observed", () => {
  it("warns when a config fix is not visible in the live system", () => {
    const finding = COMPARISON.persists[0]!;
    render(<CompareView comparison={{ ...COMPARISON, still_observed: [finding] }} />);
    expect(screen.getByText(/still observed live — not redeployed yet?/)).toBeInTheDocument();
    expect(screen.getByText(finding.title, { selector: "li", exact: false })).toBeInTheDocument();
  });
});

describe("ComparePage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("defaults to the two latest sessions and compares them", async () => {
    vi.stubEnv("VITE_MAGEN_API_URL", "http://127.0.0.1:9");
    vi.stubEnv("VITE_MAGEN_TOKEN", "t");
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        calls.push(url);
        const body = url.includes("/compare?") ? COMPARISON : sessions;
        return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
      }),
    );
    render(
      <MemoryRouter initialEntries={["/compare"]}>
        <Routes>
          <Route path="/compare" element={<ComparePage />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByRole("region", { name: "Resolved" })).toBeInTheDocument();
    const list = sessions as { id: number }[];
    await waitFor(() => {
      expect(
        calls.some((u) =>
          u.endsWith(`/api/sessions/compare?base=${list[1]!.id}&head=${list[0]!.id}`),
        ),
      ).toBe(true);
    });
    expect(screen.getByLabelText("Baseline (before)")).toHaveValue(String(list[1]!.id));
  });
});
