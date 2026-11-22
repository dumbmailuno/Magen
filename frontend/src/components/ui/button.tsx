import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { Loader2 } from "lucide-react";
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex select-none items-center justify-center gap-2 whitespace-nowrap rounded-md border font-medium transition-colors duration-fast ease-standard disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "border-transparent bg-primary text-primary-fg hover:bg-primary-hover active:bg-primary-active",
        secondary: "border-border-strong bg-surface text-fg hover:bg-surface-raised",
        ghost: "border-transparent bg-transparent text-fg hover:bg-surface-raised",
        danger: "border-transparent bg-danger-bg text-danger hover:border-danger",
      },
      size: {
        sm: "h-8 px-3 text-sm",
        md: "h-9 px-4 text-base",
        icon: "size-8 p-0",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  /** Render as the child element (e.g. a router link) instead of a <button>. */
  asChild?: boolean;
  /** Shows a spinner, keeps the label (so width is stable) and disables the button. */
  loading?: boolean;
}

/**
 * Button — design-system §8. Danger actions must be wrapped in a confirm dialog by callers.
 * Icon-only buttons (`size="icon"`) must pass `aria-label`.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    { className, variant, size, asChild = false, loading = false, disabled, children, ...props },
    ref,
  ) => {
    if (asChild) {
      return (
        <Slot ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props}>
          {children}
        </Slot>
      );
    }
    return (
      <button
        ref={ref}
        type="button"
        className={cn(buttonVariants({ variant, size }), className)}
        disabled={disabled === true || loading}
        aria-busy={loading || undefined}
        {...props}
      >
        {loading && (
          <Loader2 aria-hidden className="size-4 animate-spin motion-reduce:animate-none" />
        )}
        {children}
      </button>
    );
  },
);
Button.displayName = "Button";

// eslint-disable-next-line react-refresh/only-export-components
export { buttonVariants };
