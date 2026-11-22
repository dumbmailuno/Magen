import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ThemeProvider } from "@/lib/theme";
import { DevComponentsPage } from "./DevComponents";

describe("/dev/components", () => {
  it("renders every component section without errors", () => {
    render(
      <ThemeProvider>
        <DevComponentsPage />
      </ThemeProvider>,
    );
    for (const title of [
      "Button",
      "Input",
      "SeverityBadge",
      "StatusBadge & SourceTag",
      "EvidenceBlock",
      "AiPanel",
      "FileField",
      "Alert",
      "SummaryStrip, FilterBar & FindingList",
      "FixCard",
      "ScanProgress",
      "TargetAllowlistForm & ProbeLog",
      "Skeleton & EmptyState",
    ]) {
      expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
    }
  });
});
