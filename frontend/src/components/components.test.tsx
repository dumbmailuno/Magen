import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AI_CAPTION, AiPanel } from "@/components/AiPanel";
import { EvidenceBlock, REDACTED } from "@/components/EvidenceBlock";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SourceTag } from "@/components/SourceTag";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FINDING_STATUSES, SEVERITIES, SOURCES } from "@/lib/types";

describe("badges are never color-only", () => {
  it.each(SEVERITIES)("severity %s has an icon and a text label", (severity) => {
    const { container } = render(<SeverityBadge severity={severity} />);
    expect(container.textContent.toLowerCase()).toBe(severity);
    expect(container.querySelector("svg")).not.toBeNull();
  });

  it.each(FINDING_STATUSES)("status %s has an icon and a text label", (status) => {
    const { container } = render(<StatusBadge status={status} />);
    expect(container.textContent.toLowerCase()).toBe(status);
    expect(container.querySelector("svg")).not.toBeNull();
  });

  it("statuses use distinct border treatments", () => {
    const classes = FINDING_STATUSES.map((s) => {
      const { container } = render(<StatusBadge status={s} />);
      return container.firstElementChild?.className ?? "";
    });
    expect(classes[0]).toContain("bg-fg");
    expect(classes[1]).not.toContain("border-dashed");
    expect(classes[2]).toContain("border-dashed");
  });

  it.each(SOURCES)("source %s has an icon and label", (source) => {
    const { container } = render(<SourceTag source={source} />);
    expect(container.textContent.toLowerCase()).toBe(source);
  });
});

describe("Button", () => {
  it("loading disables and keeps the label", () => {
    render(<Button loading>Start scan</Button>);
    const btn = screen.getByRole("button", { name: "Start scan" });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("aria-busy", "true");
  });

  it("calls onClick", async () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Go</Button>);
    await userEvent.click(screen.getByRole("button", { name: "Go" }));
    expect(onClick).toHaveBeenCalledOnce();
  });
});

describe("Input", () => {
  it("wires label, helper and error for assistive tech", () => {
    render(<Input label="Base URL" helper="Allowlisted hosts only" error="Invalid URL" />);
    const input = screen.getByLabelText("Base URL");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("Allowlisted hosts only Invalid URL");
  });
});

describe("AiPanel", () => {
  it("always shows the AI caption with provenance when ready", () => {
    render(
      <AiPanel
        state="ready"
        text="Explained."
        model="qwen3:4b"
        promptVersion="v1"
        fallback="Template."
      />,
    );
    expect(screen.getByText(AI_CAPTION)).toBeInTheDocument();
    expect(screen.getByText(/qwen3:4b/)).toBeInTheDocument();
    expect(screen.getByText("Explained.")).toBeInTheDocument();
  });

  it("falls back to the template explanation when Ollama is unavailable", () => {
    render(<AiPanel state="unavailable" fallback="Template explanation." />);
    expect(screen.getByText("Template explanation.")).toBeInTheDocument();
    expect(screen.getByText(/Ollama is not running/)).toBeInTheDocument();
    // Template text is deterministic, so it must NOT carry the AI caption.
    expect(screen.queryByText(AI_CAPTION)).toBeNull();
  });

  it("collapsed panel expands on click", async () => {
    const onExpand = vi.fn();
    render(<AiPanel state="collapsed" fallback="x" onExpand={onExpand} />);
    const toggle = screen.getByRole("button", { name: /AI explanation/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(onExpand).toHaveBeenCalledOnce();
  });
});

describe("EvidenceBlock", () => {
  it("renders line numbers, highlights and redaction markers", () => {
    const { container } = render(
      <EvidenceBlock
        variant="http"
        content={`GET / HTTP/1.1\nAuthorization: ${REDACTED}`}
        startLine={10}
        highlight={[11]}
      />,
    );
    expect(screen.getByRole("img", { name: "redacted secret" })).toHaveTextContent(REDACTED);
    expect(screen.getByText("Highlighted line 11:")).toBeInTheDocument();
    expect(container.querySelectorAll("[data-highlighted]")).toHaveLength(1);
  });

  it("normalizes CRLF line endings", () => {
    const { container } = render(
      <EvidenceBlock variant="code" content={"a\r\nb\r\nc"} startLine={1} />,
    );
    expect(container.querySelectorAll("code > div")).toHaveLength(3);
  });
});
