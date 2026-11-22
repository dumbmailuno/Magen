import { FileUp, X } from "lucide-react";
import { useId, useRef } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface FileFieldProps {
  label: string;
  accept: string;
  file: File | null;
  onChange: (file: File | null) => void;
  helper?: string;
  error?: string | undefined;
  disabled?: boolean;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Labelled local file picker. The file is read in the renderer; nothing leaves the machine. */
export function FileField({
  label,
  accept,
  file,
  onChange,
  helper,
  error,
  disabled = false,
}: FileFieldProps) {
  const id = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const describedBy = [helper ? `${id}-helper` : null, error ? `${id}-error` : null]
    .filter(Boolean)
    .join(" ");
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
      </label>
      <div
        className={cn(
          "flex h-9 items-center gap-2 rounded-md border border-border-strong bg-surface pl-3 pr-1 focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-focus",
          error && "border-danger",
          disabled && "opacity-60",
        )}
      >
        <FileUp aria-hidden className="size-4 shrink-0 text-fg-muted" />
        <input
          ref={inputRef}
          id={id}
          type="file"
          accept={accept}
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          className="min-w-0 flex-1 text-sm text-fg file:mr-3 file:cursor-pointer file:rounded-sm file:border-0 file:bg-surface-raised file:px-2 file:py-1 file:text-sm file:text-fg"
          onChange={(e) => {
            onChange(e.target.files?.[0] ?? null);
          }}
        />
        {file && (
          <>
            <span className="shrink-0 font-mono text-xs tabular-nums text-fg-muted">
              {formatSize(file.size)}
            </span>
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Clear ${label}`}
              disabled={disabled}
              onClick={() => {
                if (inputRef.current) inputRef.current.value = "";
                onChange(null);
              }}
            >
              <X aria-hidden className="size-4" />
            </Button>
          </>
        )}
      </div>
      {helper && (
        <p id={`${id}-helper`} className="text-xs text-fg-muted">
          {helper}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
