import { Play } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FileField } from "@/components/FileField";
import { PageHeader } from "@/components/layout/PageHeader";
import { AUTHORIZATION_NOTICE } from "@/components/TargetAllowlistForm";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { useScan, type ScanInput } from "@/lib/scan";
import type { InputKind, Target } from "@/lib/types";

/** Must match the backend loaders' MAX_BYTES. */
const MAX_BYTES = 5 * 1024 * 1024;

function validateFile(file: File | null): string | undefined {
  if (file && file.size > MAX_BYTES) return "File is larger than 5 MB.";
  if (file?.size === 0) return "File is empty.";
  return undefined;
}

function hostOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    return null;
  }
}

function validateBaseUrl(url: string, target: Target | undefined): string | undefined {
  if (!url) return undefined;
  const host = hostOf(url);
  if (host === null) return "Enter a full http:// or https:// URL.";
  if (target && host !== target.host) return `The URL must be on ${target.host}.`;
  return undefined;
}

export function NewScanPage() {
  const navigate = useNavigate();
  const ids = useId();
  const { state, run } = useScan();
  const [openapi, setOpenapi] = useState<File | null>(null);
  const [nginx, setNginx] = useState<File | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [headerName, setHeaderName] = useState("Authorization");
  const [headerValue, setHeaderValue] = useState("");
  const [rate, setRate] = useState("5");
  const [cap, setCap] = useState("50");
  const [readError, setReadError] = useState<string | null>(null);

  useEffect(() => {
    api
      .targets()
      .then(setTargets)
      .catch(() => {
        setTargets([]);
      });
  }, []);

  const target = targets?.find((t) => t.id === targetId);
  const runtimeWanted = targetId !== null || baseUrl !== "";
  const rateN = Number(rate);
  const capN = Number(cap);
  const errors = {
    openapi: validateFile(openapi),
    nginx: validateFile(nginx),
    target: runtimeWanted && targetId === null ? "Choose an allowlisted target." : undefined,
    baseUrl:
      runtimeWanted && !baseUrl ? "Enter the API base URL." : validateBaseUrl(baseUrl, target),
    rate: rateN > 0 && rateN <= 5 ? undefined : "Between 0.1 and 5 requests per second.",
    cap: Number.isInteger(capN) && capN >= 1 && capN <= 200 ? undefined : "Between 1 and 200.",
  };
  const running = state.phase === "running";
  const hasInput = openapi !== null || nginx !== null || runtimeWanted;
  const valid = Object.values(errors).every((e) => e === undefined);
  const canStart = hasInput && valid && !running;

  const start = async () => {
    setReadError(null);
    const picked: [InputKind, File | null][] = [
      ["openapi", openapi],
      ["nginx", nginx],
    ];
    let inputs: ScanInput[];
    try {
      inputs = await Promise.all(
        picked
          .filter((p): p is [InputKind, File] => p[1] !== null)
          .map(async ([kind, file]) => ({ kind, filename: file.name, content: await file.text() })),
      );
    } catch {
      setReadError("Could not read the selected file.");
      return;
    }
    if (runtimeWanted && targetId !== null) {
      inputs.push({
        kind: "runtime",
        label: baseUrl,
        request: {
          target_id: targetId,
          base_url: baseUrl,
          rate_per_second: rateN,
          request_cap: capN,
          ...(headerValue ? { auth_header: { name: headerName.trim(), value: headerValue } } : {}),
        },
      });
    }
    setHeaderValue(""); // the value now lives only in the scan session's memory
    void navigate("/findings");
    await run(inputs);
  };

  return (
    <>
      <PageHeader
        title="New scan"
        description="Analyze an OpenAPI spec and/or an Nginx config, and optionally probe a live API. Files are read locally and never modified."
      />
      <form
        className="flex max-w-3xl flex-col gap-6"
        onSubmit={(e) => {
          e.preventDefault();
          void start();
        }}
      >
        <fieldset className="flex flex-col gap-4 rounded-md border border-border bg-surface p-6">
          <legend className="px-1 text-lg font-semibold">Static analysis</legend>
          <FileField
            label="OpenAPI spec"
            accept=".yaml,.yml,.json"
            file={openapi}
            onChange={setOpenapi}
            helper="OpenAPI 3.x, YAML or JSON. External $refs are not fetched."
            error={errors.openapi}
            disabled={running}
          />
          <FileField
            label="Nginx config"
            accept=".conf,.txt,text/plain"
            file={nginx}
            onChange={setNginx}
            helper="nginx.conf or a site file. include directives are reported, not followed."
            error={errors.nginx}
            disabled={running}
          />
        </fieldset>

        <fieldset className="flex flex-col gap-4 rounded-md border border-border bg-surface p-6">
          <legend className="px-1 text-lg font-semibold">Live API (optional)</legend>
          <Alert tone="warning" title="Authorization required">
            {AUTHORIZATION_NOTICE}
          </Alert>
          {targets?.length === 0 ? (
            <p className="text-base text-fg-muted">
              No allowlisted targets yet.{" "}
              <Link to="/targets" className="text-accent underline underline-offset-2">
                Add a target
              </Link>{" "}
              to enable live probes.
            </p>
          ) : (
            <>
              <div className="flex flex-col gap-1">
                <label htmlFor={`${ids}-target`} className="text-sm font-medium text-fg">
                  Target
                </label>
                <select
                  id={`${ids}-target`}
                  className="h-9 rounded-md border border-border-strong bg-surface px-3 text-base text-fg"
                  value={targetId ?? ""}
                  disabled={running || targets === null}
                  aria-invalid={errors.target ? true : undefined}
                  onChange={(e) => {
                    setTargetId(e.target.value ? Number(e.target.value) : null);
                  }}
                >
                  <option value="">None (static only)</option>
                  {targets?.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.host}
                      {t.is_local ? " (local lab)" : ""}
                    </option>
                  ))}
                </select>
                {errors.target && <p className="text-xs text-danger">{errors.target}</p>}
              </div>
              <Input
                label="Base URL"
                mono
                placeholder={target ? `https://${target.host}/` : "https://api.example.com/v1/"}
                value={baseUrl}
                disabled={running}
                onChange={(e) => {
                  setBaseUrl(e.target.value.trim());
                }}
                {...(errors.baseUrl ? { error: errors.baseUrl } : {})}
              />
              <div className="grid grid-cols-3 gap-4">
                <Input
                  label="Auth header name"
                  mono
                  value={headerName}
                  disabled={running}
                  onChange={(e) => {
                    setHeaderName(e.target.value);
                  }}
                />
                <div className="col-span-2">
                  <Input
                    label="Auth header value (optional)"
                    mono
                    type="password"
                    autoComplete="off"
                    placeholder="Bearer …"
                    value={headerValue}
                    disabled={running}
                    helper="Kept in memory for this scan only. Never saved or logged; redacted everywhere."
                    onChange={(e) => {
                      setHeaderValue(e.target.value);
                    }}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="Rate (requests / second)"
                  type="number"
                  min={0.1}
                  max={5}
                  step={0.1}
                  value={rate}
                  disabled={running}
                  onChange={(e) => {
                    setRate(e.target.value);
                  }}
                  {...(errors.rate ? { error: errors.rate } : {})}
                />
                <Input
                  label="Request cap"
                  type="number"
                  min={1}
                  max={200}
                  value={cap}
                  disabled={running}
                  onChange={(e) => {
                    setCap(e.target.value);
                  }}
                  {...(errors.cap ? { error: errors.cap } : {})}
                />
              </div>
              <p className="text-sm text-fg-muted">
                Safe, read-only requests only (GET, HEAD, OPTIONS and TLS handshakes) — about 13 per
                scan. You can stop at any time.
              </p>
            </>
          )}
        </fieldset>

        {readError && <Alert tone="danger" title={readError} />}
        <div>
          <Button type="submit" disabled={!canStart} loading={running}>
            <Play aria-hidden className="size-4" />
            Start scan
          </Button>
        </div>
      </form>
    </>
  );
}
