import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, request } from "@/lib/api";
import { ThemeProvider, useTheme } from "@/lib/theme";
import { cn, truncateMiddle } from "@/lib/utils";

describe("cn", () => {
  it("keeps custom font-size and color utilities side by side", () => {
    expect(cn("text-md", "text-fg-muted")).toBe("text-md text-fg-muted");
    expect(cn("p-2", "p-4")).toBe("p-4");
  });
});

describe("truncateMiddle", () => {
  it("keeps short values and middle-truncates long ones", () => {
    expect(truncateMiddle("short", 10)).toBe("short");
    const out = truncateMiddle("a".repeat(30) + "END", 11);
    expect(out).toHaveLength(11);
    expect(out.endsWith("END")).toBe(true);
    expect(out).toContain("…");
  });
});

describe("request", () => {
  const conn = { baseUrl: "http://127.0.0.1:1", token: "tok" };
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the session token", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await request("/api/health", {}, conn);
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(init.headers).get("X-Magen-Token")).toBe("tok");
  });

  it("maps the backend error shape to ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ code: "not_found", message: "Nope", detail: null }), {
          status: 404,
        }),
      ),
    );
    await expect(request("/x", {}, conn)).rejects.toMatchObject({
      status: 404,
      code: "not_found",
      message: "Nope",
    });
  });

  it("reports an unreachable backend", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("failed")));
    await expect(request("/x", {}, conn)).rejects.toBeInstanceOf(ApiError);
  });

  it("fails clearly when not configured", async () => {
    await expect(request("/x", {}, null)).rejects.toMatchObject({ code: "not_configured" });
  });
});

function ThemeProbe() {
  const { setTheme } = useTheme();
  return (
    <button
      type="button"
      onClick={() => {
        setTheme("system");
      }}
    >
      system
    </button>
  );
}

describe("ThemeProvider", () => {
  it("resolves 'system' to a concrete theme tokens.css understands", async () => {
    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "system" }));
    expect(["dark", "light"]).toContain(document.documentElement.dataset.theme);
  });
});
