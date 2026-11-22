import { forwardRef, useId, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  /** Always-visible label above the control (design-system §8). */
  label: string;
  helper?: string;
  error?: string;
  /** Use mono font, e.g. for URLs and headers. */
  mono?: boolean;
}

/** Labelled text input with helper/error text wired via `aria-describedby`. */
export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, helper, error, mono = false, className, readOnly, ...props }, ref) => {
    const id = useId();
    const helperId = `${id}-helper`;
    const errorId = `${id}-error`;
    const describedBy = [helper ? helperId : null, error ? errorId : null]
      .filter(Boolean)
      .join(" ");
    return (
      <div className="flex flex-col gap-1">
        <label htmlFor={id} className="text-sm font-medium text-fg">
          {label}
        </label>
        <input
          ref={ref}
          id={id}
          readOnly={readOnly}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          className={cn(
            "h-9 rounded-md border border-border-strong bg-surface px-3 text-base text-fg placeholder:text-fg-muted",
            "transition-colors duration-fast disabled:cursor-not-allowed disabled:text-fg-disabled disabled:opacity-60",
            readOnly && "bg-bg text-fg-muted",
            error && "border-danger",
            mono && "font-mono text-sm",
            className,
          )}
          {...props}
        />
        {helper && (
          <p id={helperId} className="text-xs text-fg-muted">
            {helper}
          </p>
        )}
        {error && (
          <p id={errorId} className="text-xs text-danger">
            {error}
          </p>
        )}
      </div>
    );
  },
);
Input.displayName = "Input";
