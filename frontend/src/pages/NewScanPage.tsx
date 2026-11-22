import { Play } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FileField } from "@/components/FileField";
import { PageHeader } from "@/components/layout/PageHeader";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useScan, type ScanInput } from "@/lib/scan";
import type { InputKind } from "@/lib/types";

/** Must match the backend loaders' MAX_BYTES. */
const MAX_BYTES = 5 * 1024 * 1024;

function validate(file: File | null): string | undefined {
  if (file && file.size > MAX_BYTES) return "File is larger than 5 MB.";
  if (file?.size === 0) return "File is empty.";
  return undefined;
}

export function NewScanPage() {
  const navigate = useNavigate();
  const { state, run } = useScan();
  const [openapi, setOpenapi] = useState<File | null>(null);
  const [nginx, setNginx] = useState<File | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const errors = { openapi: validate(openapi), nginx: validate(nginx) };
  const running = state.phase === "running";
  const canStart = (openapi ?? nginx) !== null && !errors.openapi && !errors.nginx && !running;

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
    void navigate("/findings");
    await run(inputs);
  };

  return (
    <>
      <PageHeader
        title="New scan"
        description="Analyze an OpenAPI spec and/or an Nginx config. Files are read locally and never modified."
      />
      <form
        className="flex max-w-2xl flex-col gap-6 rounded-md border border-border bg-surface p-6"
        onSubmit={(e) => {
          e.preventDefault();
          void start();
        }}
      >
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
        <Alert tone="info" title="Runtime probes are not available yet">
          Live API checks against allowlisted targets arrive in a later release. This scan is static
          only.
        </Alert>
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
