import { Fragment, type ReactNode } from "react";
import { CopyButton } from "@/components/CopyButton";
import { cn, truncateMiddle } from "@/lib/utils";

export type EvidenceVariant = "code" | "http" | "config";

/** Must match backend/app/core/redaction.py REDACTED. */
export const REDACTED = "••••";

export interface EvidenceBlockProps {
  variant: EvidenceVariant;
  content: string;
  /** File path / URL / JSON pointer shown in the header (middle-truncated). */
  location?: string;
  /** Line number of the first line; omit to hide the gutter (e.g. HTTP excerpts). */
  startLine?: number;
  /** Absolute line numbers to highlight. */
  highlight?: readonly number[];
}

const VARIANT_LABEL: Record<EvidenceVariant, string> = {
  code: "Code",
  http: "HTTP",
  config: "Config",
};

function renderRedactions(line: string): ReactNode {
  if (!line.includes(REDACTED)) return line;
  return line.split(REDACTED).map((part, i) => (
    <Fragment key={i}>
      {i > 0 && (
        <span
          className="rounded-sm bg-surface-raised px-1 text-fg-muted"
          role="img"
          aria-label="redacted secret"
        >
          {REDACTED}
        </span>
      )}
      {part}
    </Fragment>
  ));
}

/** Evidence excerpt: mono, line numbers, highlighted lines, copy, `••••` redactions. */
export function EvidenceBlock({
  variant,
  content,
  location,
  startLine,
  highlight = [],
}: EvidenceBlockProps) {
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  const showGutter = startLine !== undefined;
  const marked = new Set(highlight);
  return (
    <figure className="overflow-hidden rounded-md border border-border bg-bg">
      <figcaption className="flex items-center gap-2 border-b border-border bg-surface px-3 py-1">
        <span className="text-xs font-medium uppercase tracking-wide text-fg-muted">
          {VARIANT_LABEL[variant]}
        </span>
        {location && (
          <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={location}>
            {truncateMiddle(location, 72)}
          </span>
        )}
        <span className={cn(!location && "flex-1")} />
        <CopyButton text={content} label="Copy evidence" />
      </figcaption>
      <pre className="overflow-x-auto py-2 font-mono text-sm tabular-nums leading-relaxed">
        <code>
          {lines.map((line, i) => {
            const n = (startLine ?? 1) + i;
            const isMarked = marked.has(n);
            return (
              <div
                key={n}
                className={cn("flex", isMarked && "bg-warning-bg")}
                data-highlighted={isMarked || undefined}
              >
                {showGutter && (
                  <span
                    aria-hidden
                    className={cn(
                      "w-12 shrink-0 select-none pr-3 text-right text-fg-muted",
                      isMarked && "text-warning",
                    )}
                  >
                    {n}
                  </span>
                )}
                {/* Highlight is also announced as text, not color-only. */}
                {isMarked && <span className="sr-only">Highlighted line {n}: </span>}
                <span className={cn("whitespace-pre pr-4", !showGutter && "pl-3")}>
                  {renderRedactions(line) || " "}
                </span>
              </div>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}
