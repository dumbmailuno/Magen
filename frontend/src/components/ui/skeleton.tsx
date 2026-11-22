import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Loading placeholder. Decorative: pair with an aria-live status text in the parent. */
export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden
      className={cn(
        "animate-pulse rounded-md bg-surface-raised motion-reduce:animate-none",
        className,
      )}
      {...props}
    />
  );
}
