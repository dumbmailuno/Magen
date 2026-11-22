import { Download, ShieldCheck, ShieldQuestion } from "lucide-react";
import { CopyButton } from "@/components/CopyButton";
import { Button } from "@/components/ui/button";
import type { Remediation } from "@/lib/types";

function exportFix(text: string, filename: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Suggested fix (Option B): copy or export for the user to apply themselves.
 * There is deliberately NO "Apply to file" action anywhere in Magen.
 */
export function FixCard({ remediation, ruleId }: { remediation: Remediation; ruleId: string }) {
  const fix = remediation.template_fix;
  if (!fix)
    return <p className="text-base text-fg-muted">No template fix is available for this rule.</p>;
  return (
    <figure className="overflow-hidden rounded-md border border-border bg-bg">
      <figcaption className="flex items-center gap-2 border-b border-border bg-surface px-3 py-1">
        <span className="text-xs font-medium uppercase tracking-wide text-fg-muted">
          Template fix
        </span>
        {remediation.validated ? (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-success">
            <ShieldCheck aria-hidden className="size-3.5" />
            Validated
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-fg-muted">
            <ShieldQuestion aria-hidden className="size-3.5" />
            Not validated
          </span>
        )}
        <span className="flex-1" />
        <CopyButton text={fix} label="Copy fix" />
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            exportFix(fix, `${ruleId}-fix.txt`);
          }}
        >
          <Download aria-hidden className="size-4" />
          Export fix
        </Button>
      </figcaption>
      <pre className="overflow-x-auto p-3 font-mono text-sm leading-relaxed">
        <code>{fix}</code>
      </pre>
    </figure>
  );
}
