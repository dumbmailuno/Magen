import { ShieldAlert } from "lucide-react";
import { useId, useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, ApiError } from "@/lib/api";
import type { Target } from "@/lib/types";

/** design-system §10 authorization copy, shown before any runtime scan. */
export const AUTHORIZATION_NOTICE =
  "Only scan systems you own or have written permission to test. Magen sends safe, rate-limited requests to the host you add.";

/** Add a host to the allowlist. The authorization checkbox is required; the backend records the time. */
export function TargetAllowlistForm({ onAdded }: { onAdded: (t: Target) => void }) {
  const id = useId();
  const [host, setHost] = useState("");
  const [isLocal, setIsLocal] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const t = await api.addTarget(host.trim(), isLocal);
      setHost("");
      setIsLocal(false);
      setAuthorized(false);
      onAdded(t);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the target");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="flex flex-col gap-4 rounded-md border border-border bg-surface p-6"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <h2 className="text-lg font-semibold">Add target</h2>
      <Input
        label="Host"
        mono
        placeholder="api.example.com"
        value={host}
        onChange={(e) => {
          setHost(e.target.value);
        }}
        helper="A bare host name or IP address — no scheme, port or path."
        {...(error ? { error } : {})}
      />
      <label htmlFor={`${id}-local`} className="flex items-start gap-2 text-base text-fg">
        <input
          id={`${id}-local`}
          type="checkbox"
          className="mt-1 size-4 accent-primary"
          checked={isLocal}
          onChange={(e) => {
            setIsLocal(e.target.checked);
          }}
        />
        <span>
          Local lab target
          <span className="block text-sm text-fg-muted">
            Allows localhost and private network addresses (e.g. a Docker lab). Cloud metadata
            addresses are always blocked.
          </span>
        </span>
      </label>
      <Alert tone="warning" title="Authorization required">
        {AUTHORIZATION_NOTICE}
      </Alert>
      <label
        htmlFor={`${id}-auth`}
        className="flex items-start gap-2 text-base font-medium text-fg"
      >
        <input
          id={`${id}-auth`}
          type="checkbox"
          required
          className="mt-1 size-4 accent-primary"
          checked={authorized}
          onChange={(e) => {
            setAuthorized(e.target.checked);
          }}
        />
        I own this host or have written permission to test it.
      </label>
      <div>
        <Button type="submit" disabled={!authorized || host.trim() === ""} loading={busy}>
          <ShieldAlert aria-hidden className="size-4" />
          Add target
        </Button>
      </div>
    </form>
  );
}
