import { RefreshCw, Server, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/layout/PageHeader";
import { TargetAllowlistForm } from "@/components/TargetAllowlistForm";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { api, ApiError } from "@/lib/api";
import type { Target } from "@/lib/types";

function RemoveButton({ target, onRemoved }: { target: Target; onRemoved: () => void }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming)
    return (
      <Button
        variant="ghost"
        size="sm"
        aria-label={`Remove ${target.host}`}
        onClick={() => {
          setConfirming(true);
        }}
      >
        <Trash2 aria-hidden className="size-4" />
        Remove
      </Button>
    );
  return (
    <span className="flex items-center gap-2">
      <Button
        variant="danger"
        size="sm"
        onClick={() => {
          void api.deleteTarget(target.id).then(onRemoved);
        }}
      >
        Confirm remove
      </Button>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => {
          setConfirming(false);
        }}
      >
        Cancel
      </Button>
    </span>
  );
}

export function TargetsPage() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .targets()
      .then((t) => {
        setTargets(t);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Could not load targets");
      });
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <PageHeader
        title="Targets"
        description="Hosts you are authorized to probe. Runtime scans only run against these."
      />
      <div className="grid gap-6 split:grid-cols-2">
        <section aria-label="Allowlist" className="flex flex-col gap-3">
          {error && (
            <Alert
              tone="danger"
              title="Could not load targets"
              action={
                <Button variant="secondary" size="sm" onClick={load}>
                  <RefreshCw aria-hidden className="size-4" />
                  Retry
                </Button>
              }
            >
              {error}
            </Alert>
          )}
          {!error && targets === null && (
            <div className="flex flex-col gap-2" aria-hidden>
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          )}
          {targets?.length === 0 && (
            <EmptyState
              icon={Server}
              title="No targets yet"
              description="Add a host you own or have written permission to test."
            />
          )}
          {targets && targets.length > 0 && (
            <table className="w-full overflow-hidden rounded-md border border-border bg-surface text-base">
              <thead className="text-left text-sm text-fg-muted">
                <tr>
                  <th scope="col" className="px-4 py-2 font-medium">
                    Host
                  </th>
                  <th scope="col" className="px-4 py-2 font-medium">
                    Type
                  </th>
                  <th scope="col" className="px-4 py-2 font-medium">
                    Authorized
                  </th>
                  <th scope="col" className="px-4 py-2 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id} className="border-t border-border">
                    <td className="px-4 py-2 font-mono text-sm text-fg">{t.host}</td>
                    <td className="px-4 py-2 text-sm text-fg-muted">
                      {t.is_local ? "Local lab" : "Public"}
                    </td>
                    <td
                      className="px-4 py-2 font-mono text-xs tabular-nums text-fg-muted"
                      title={t.authorized_at}
                    >
                      {t.authorized_at.slice(0, 16).replace("T", " ")}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <RemoveButton target={t} onRemoved={load} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
        <TargetAllowlistForm
          onAdded={(t) => {
            setTargets((prev) => [...(prev ?? []), t].sort((a, b) => a.host.localeCompare(b.host)));
          }}
        />
      </div>
    </>
  );
}
