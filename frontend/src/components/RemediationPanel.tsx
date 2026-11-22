import {
  CircleSlash,
  Download,
  FileDiff,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  Wand2,
} from "lucide-react";
import { useState } from "react";
import { DiffView } from "@/components/DiffView";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import type { InputKind, RemediationPreview } from "@/lib/types";

function download(text: string, filename: string, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function Outcome({ fix }: { fix: RemediationPreview["fixes"][number] }) {
  if (fix.outcome === "template_only")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-fg-muted">
        <CircleSlash aria-hidden className="size-3.5" />
        Template only — needs your decision
      </span>
    );
  if (fix.outcome === "conflict")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-warning">
        <ShieldQuestion aria-hidden className="size-3.5" />
        Overlaps another fix — generate it on its own
      </span>
    );
  return fix.validated ? (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-success">
      <ShieldCheck aria-hidden className="size-3.5" />
      Fixed · Validated
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-danger">
      <ShieldX aria-hidden className="size-3.5" />
      Fixed · Not validated
    </span>
  );
}

const SYNTAX: Record<string, string> = {
  passed: "nginx -t passed.",
  failed: "nginx -t failed on the corrected file.",
  inconclusive: "nginx -t could not judge (it also fails on the original).",
  unavailable: "nginx is not installed here: validated by re-parsing and re-running the rules.",
  not_applicable: "Validated by re-parsing and re-running the rules.",
};

/**
 * Generate a corrected *copy* of one input (Option B). Magen never writes to the user's
 * files: the result can only be reviewed, copied or exported.
 */
export function RemediationPanel({
  kind,
  filename,
  content,
  findingIds,
  label = "Generate corrected file",
}: {
  kind: InputKind;
  filename: string;
  content: string;
  /** Omit to fix every finding in the file. */
  findingIds?: string[];
  label?: string;
}) {
  const [state, setState] = useState<
    | { s: "idle" }
    | { s: "busy" }
    | { s: "ready"; p: RemediationPreview }
    | { s: "error"; m: string }
  >({ s: "idle" });

  const generate = async () => {
    setState({ s: "busy" });
    try {
      const p = await api.remediationPreview({
        kind,
        filename,
        content,
        ...(findingIds ? { finding_ids: findingIds } : {}),
      });
      setState({ s: "ready", p });
    } catch (err) {
      setState({
        s: "error",
        m: err instanceof ApiError ? err.message : "Could not generate the fix",
      });
    }
  };

  if (state.s === "idle" || state.s === "busy")
    return (
      <Button
        variant="secondary"
        size="sm"
        onClick={() => void generate()}
        loading={state.s === "busy"}
      >
        <Wand2 aria-hidden className="size-4" />
        {label}
      </Button>
    );
  if (state.s === "error")
    return (
      <Alert
        tone="danger"
        title="Could not generate a fix"
        action={
          <Button variant="secondary" size="sm" onClick={() => void generate()}>
            Retry
          </Button>
        }
      >
        {state.m}
      </Alert>
    );

  const { p } = state;
  const applied = p.fixes.filter((f) => f.outcome === "applied");
  return (
    <section aria-label="Generated fix" className="flex flex-col gap-3" aria-live="polite">
      <ul className="flex flex-col gap-1">
        {p.fixes.map((f) => (
          <li key={f.finding_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
            <span className="font-mono text-xs text-fg-muted">{f.rule_id}</span>
            <span className="min-w-0 flex-1 truncate text-fg" title={f.title}>
              {f.title}
            </span>
            <Outcome fix={f} />
          </li>
        ))}
      </ul>
      {!p.validation.parsed && (
        <Alert tone="danger" title="The corrected file does not parse">
          {p.validation.error}
        </Alert>
      )}
      {p.validation.introduced.length > 0 && (
        <Alert tone="warning" title="The changes would introduce new findings">
          <ul>
            {p.validation.introduced.map((f) => (
              <li key={f.id}>
                <span className="font-mono">{f.rule_id}</span> {f.title}
              </li>
            ))}
          </ul>
        </Alert>
      )}
      {applied.length > 0 && (
        <>
          <p className="text-xs text-fg-muted">
            {SYNTAX[p.validation.syntax.status] ?? p.validation.syntax.message}
          </p>
          <DiffView diff={p.diff} filename={p.filename} />
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                download(p.patched_content, p.patched_filename);
              }}
            >
              <Download aria-hidden className="size-4" />
              Export {p.patched_filename}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                download(p.diff, `${p.filename}.patch`, "text/x-diff");
              }}
            >
              <FileDiff aria-hidden className="size-4" />
              Export patch
            </Button>
          </div>
          <p className="text-xs text-fg-muted">
            Your original file is unchanged. Review the diff, apply it yourself, then retest.
          </p>
        </>
      )}
    </section>
  );
}
