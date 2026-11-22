import { describe, expect, it } from "vitest";
import legacy from "@/test/fixtures/nginx-legacy-tls.json";
import noAuth from "@/test/fixtures/openapi-no-auth.json";
import {
  applyFilters,
  countBy,
  filtersFromParams,
  filtersToParams,
  formatLocation,
  NO_FILTERS,
  sortFindings,
} from "./findings";
import type { Finding, NginxResult, OpenApiResult } from "./types";

const oas = (noAuth as OpenApiResult).findings;
const ngx = (legacy as NginxResult).findings;

describe("sortFindings", () => {
  it("reproduces the backend's canonical order for each input", () => {
    expect(sortFindings([...oas].reverse()).map((f) => f.id)).toEqual(oas.map((f) => f.id));
    expect(sortFindings([...ngx].reverse()).map((f) => f.id)).toEqual(ngx.map((f) => f.id));
  });

  it("merges inputs by severity first and collapses duplicate ids", () => {
    const merged = sortFindings([...oas, ...ngx, ...oas]);
    expect(merged).toHaveLength(oas.length + ngx.length);
    const ranks = merged.map((f) =>
      ["info", "low", "medium", "high", "critical"].indexOf(f.severity),
    );
    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
  });

  it("orders lines numerically, not lexically", () => {
    const at = (line: number): Finding => ({
      ...oas[0]!,
      id: `id${line}`,
      evidence: [{ ...oas[0]!.evidence[0]!, location: { ...oas[0]!.evidence[0]!.location, line } }],
    });
    expect(sortFindings([at(10), at(9)]).map((f) => f.id)).toEqual(["id9", "id10"]);
  });
});

describe("filters", () => {
  it("round-trips through URL params and ignores junk values", () => {
    const params = filtersToParams(
      { severity: ["high", "low"], status: [], source: ["static"] },
      new URLSearchParams("f=abc"),
    );
    expect(params.toString()).toBe("f=abc&sev=high%2Clow&source=static");
    expect(filtersFromParams(new URLSearchParams("sev=high,bogus&status=nope"))).toEqual({
      severity: ["high"],
      status: [],
      source: [],
    });
  });

  it("applies AND across groups, OR within a group", () => {
    const all = [...oas, ...ngx];
    expect(applyFilters(all, NO_FILTERS)).toHaveLength(all.length);
    const highOrLow = applyFilters(all, { ...NO_FILTERS, severity: ["high", "low"] });
    expect(highOrLow.every((f) => ["high", "low"].includes(f.severity))).toBe(true);
    expect(applyFilters(all, { severity: ["high"], status: ["confirmed"], source: [] })).toEqual(
      [],
    );
  });

  it("counts", () => {
    expect(countBy(ngx, (f) => f.severity).get("high")).toBe(2);
  });
});

describe("formatLocation", () => {
  it("formats line ranges and pointer-only locations", () => {
    expect(
      formatLocation({ file: "a.conf", line: 3, end_line: null, pointer: "/x", url: null }),
    ).toBe("a.conf:3");
    expect(formatLocation({ file: "a.yaml", line: 3, end_line: 9, pointer: "/x", url: null })).toBe(
      "a.yaml:3-9",
    );
    expect(
      formatLocation({ file: "a.json", line: null, end_line: null, pointer: "/paths", url: null }),
    ).toBe("a.json /paths");
  });
});
