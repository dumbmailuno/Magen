import { useId, useState } from "react";
import { cn } from "@/lib/utils";

type Row =
  | { kind: "hunk"; text: string }
  | { kind: "context" | "add" | "del"; text: string; oldNo: number | null; newNo: number | null };

const HUNK = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

/** Parse a unified diff (as produced by difflib on the backend). */
// eslint-disable-next-line react-refresh/only-export-components
export function parseUnifiedDiff(diff: string): Row[] {
  const rows: Row[] = [];
  let oldNo = 0;
  let newNo = 0;
  for (const line of diff.split("\n")) {
    if (line.startsWith("---") || line.startsWith("+++")) continue;
    const hunk = HUNK.exec(line);
    if (hunk) {
      oldNo = Number(hunk[1]);
      newNo = Number(hunk[2]);
      rows.push({ kind: "hunk", text: line });
    } else if (line.startsWith("+")) {
      rows.push({ kind: "add", text: line.slice(1), oldNo: null, newNo: newNo++ });
    } else if (line.startsWith("-")) {
      rows.push({ kind: "del", text: line.slice(1), oldNo: oldNo++, newNo: null });
    } else if (rows.length > 0) {
      rows.push({ kind: "context", text: line.slice(1), oldNo: oldNo++, newNo: newNo++ });
    }
  }
  return rows;
}

const GLYPH = { add: "+", del: "−", context: " " } as const;
const LABEL = { add: "added", del: "removed", context: "unchanged" } as const;

function Line({ row }: { row: Extract<Row, { kind: "add" | "del" | "context" }> }) {
  return (
    <div
      className={cn(
        "flex",
        row.kind === "add" && "bg-diff-add",
        row.kind === "del" && "bg-diff-del",
      )}
      aria-label={row.kind === "context" ? undefined : `${LABEL[row.kind]}: ${row.text}`}
    >
      <span aria-hidden className="w-10 shrink-0 select-none pr-2 text-right text-fg-muted">
        {row.oldNo ?? ""}
      </span>
      <span aria-hidden className="w-10 shrink-0 select-none pr-2 text-right text-fg-muted">
        {row.newNo ?? ""}
      </span>
      <span aria-hidden className="w-5 shrink-0 select-none text-center font-semibold text-fg">
        {GLYPH[row.kind]}
      </span>
      <span className="whitespace-pre pr-4">{row.text || " "}</span>
    </div>
  );
}

function splitPairs(rows: Row[]): { left: Row | null; right: Row | null }[] {
  const out: { left: Row | null; right: Row | null }[] = [];
  let dels: Row[] = [];
  let adds: Row[] = [];
  const flush = () => {
    for (let i = 0; i < Math.max(dels.length, adds.length); i++) {
      out.push({ left: dels[i] ?? null, right: adds[i] ?? null });
    }
    dels = [];
    adds = [];
  };
  for (const r of rows) {
    if (r.kind === "del") dels.push(r);
    else if (r.kind === "add") adds.push(r);
    else {
      flush();
      out.push({ left: r, right: r });
    }
  }
  flush();
  return out;
}

/** Before/after diff (design-system §8). Changes are marked by glyphs, not only by color. */
export function DiffView({ diff, filename }: { diff: string; filename: string }) {
  const id = useId();
  const [mode, setMode] = useState<"unified" | "split">("unified");
  const rows = parseUnifiedDiff(diff);
  if (rows.length === 0) {
    return <p className="text-sm text-fg-muted">No changes.</p>;
  }
  return (
    <figure className="overflow-hidden rounded-md border border-border bg-bg">
      <figcaption className="flex items-center gap-3 border-b border-border bg-surface px-3 py-1">
        <span className="text-xs font-medium uppercase tracking-wide text-fg-muted">Diff</span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{filename}</span>
        <fieldset className="flex gap-1 text-xs">
          <legend className="sr-only">Diff layout</legend>
          {(["unified", "split"] as const).map((m) => (
            <label
              key={m}
              className={cn(
                "cursor-pointer rounded-sm px-2 py-0.5 text-fg-muted focus-within:outline focus-within:outline-2 focus-within:outline-focus",
                mode === m && "bg-surface-raised text-fg",
              )}
            >
              <input
                type="radio"
                className="sr-only"
                name={`${id}-mode`}
                checked={mode === m}
                onChange={() => {
                  setMode(m);
                }}
              />
              {m === "unified" ? "Unified" : "Split"}
            </label>
          ))}
        </fieldset>
      </figcaption>
      <div className="max-h-96 overflow-auto py-1 font-mono text-sm leading-relaxed">
        {mode === "unified"
          ? rows.map((r, i) =>
              r.kind === "hunk" ? (
                <div key={i} className="px-3 py-1 text-xs text-fg-muted">
                  {r.text}
                </div>
              ) : (
                <Line key={i} row={r} />
              ),
            )
          : splitPairs(rows).map((p, i) =>
              p.left?.kind === "hunk" ? (
                <div key={i} className="px-3 py-1 text-xs text-fg-muted">
                  {p.left.text}
                </div>
              ) : (
                <div key={i} className="grid grid-cols-2">
                  <div className="min-w-0 border-r border-border">
                    {p.left ? <Line row={{ ...p.left, newNo: null }} /> : null}
                  </div>
                  <div className="min-w-0">
                    {p.right && p.right.kind !== "hunk" ? (
                      <Line row={{ ...p.right, oldNo: null }} />
                    ) : null}
                  </div>
                </div>
              ),
            )}
      </div>
    </figure>
  );
}
