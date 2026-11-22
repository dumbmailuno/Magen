import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ProbeAudit } from "@/lib/types";

/** Every request Magen sent during a runtime scan (from the audit log), for transparency. */
export function ProbeLog({ scanId }: { scanId: number }) {
  const [entries, setEntries] = useState<ProbeAudit[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let alive = true;
    api
      .audit(scanId)
      .then((e) => {
        if (alive) setEntries(e);
      })
      .catch(() => {
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, [scanId]);

  return (
    <details className="rounded-md border border-border bg-surface">
      <summary className="cursor-pointer px-4 py-2 text-sm font-medium text-fg">
        Probe log{entries ? ` (${entries.length} requests)` : ""}
      </summary>
      <div className="overflow-x-auto border-t border-border">
        {failed && <p className="p-4 text-sm text-fg-muted">The probe log could not be loaded.</p>}
        {entries?.length === 0 && (
          <p className="p-4 text-sm text-fg-muted">No requests were sent.</p>
        )}
        {entries && entries.length > 0 && (
          <table className="w-full font-mono text-xs">
            <thead className="text-left text-fg-muted">
              <tr>
                <th scope="col" className="px-4 py-2 font-medium">
                  Time (UTC)
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  Method
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  URL
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  Result
                </th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="whitespace-nowrap px-4 py-1 tabular-nums text-fg-muted">
                    {e.sent_at.slice(11, 23)}
                  </td>
                  <td className="px-4 py-1 text-fg">{e.method}</td>
                  <td className="max-w-md truncate px-4 py-1 text-fg" title={e.url}>
                    {e.url}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1 tabular-nums text-fg">
                    {e.status_code ?? e.error ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </details>
  );
}
