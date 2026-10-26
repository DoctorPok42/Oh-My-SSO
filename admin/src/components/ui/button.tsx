import { Loader2 } from "lucide-react";
import { Slot } from "radix-ui";
import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/utils";

// DS "Bouton": primary (accent), secondary (outlined), danger (revocations).
// Built like shadcn/ui's Button (cva variants + asChild), restyled with the
// OMSSO tokens. https://ui.shadcn.com/docs/components/button
const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap font-semibold transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-accent-soft disabled:pointer-events-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        primary: "bg-accent text-on-accent hover:bg-accent-hover disabled:bg-neutral-soft disabled:text-text-muted",
        secondary:
          "border border-border bg-transparent text-text-primary hover:border-border-strong hover:bg-surface-alt disabled:text-text-muted",
        danger: "border border-danger-soft bg-transparent text-danger hover:bg-danger-soft disabled:opacity-50",
        destructive: "bg-danger text-on-accent hover:opacity-90 disabled:opacity-50",
        ghost: "text-text-secondary hover:bg-surface-alt hover:text-text-primary disabled:text-text-muted",
        link: "h-auto p-0 font-medium text-accent underline-offset-4 hover:underline",
      },
      size: {
        md: "h-10 rounded-md px-5 text-[14px]",
        sm: "h-9 rounded-md px-4 text-[13px]",
        xs: "h-7 rounded-sm px-3 text-[12px]",
        icon: "size-9 rounded-md",
      },
    },
    defaultVariants: { variant: "primary", size: "sm" },
  },
);

type ButtonProps = React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    /** An action is running: a spinner before the label, and the button is disabled. */
    loading?: boolean;
  };

function Button({
  className,
  variant,
  size,
  asChild = false,
  type,
  loading,
  disabled,
  children,
  ...props
}: ButtonProps) {
  if (asChild) {
    return (
      <Slot.Root data-slot="button" className={cn(buttonVariants({ variant, size }), className)} {...props}>
        {children}
      </Slot.Root>
    );
  }
  return (
    <button
      data-slot="button"
      type={type ?? "button"}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading && <Loader2 className="animate-spin motion-reduce:animate-none" aria-hidden />}
      {children}
    </button>
  );
}

export { Button, buttonVariants };
