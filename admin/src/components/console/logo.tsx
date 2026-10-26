import { cn } from "@/lib/utils";

// DS logo: 28 px square, radius 7, accent, with "O"; then the wordmark.
export function Logo({
  className,
  wordmark = true,
  wordmarkClassName,
}: {
  className?: string;
  wordmark?: boolean;
  wordmarkClassName?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <span
        aria-hidden
        className="grid size-7 place-items-center rounded-[7px] bg-accent text-[15px] font-bold text-on-accent"
      >
        O
      </span>
      {wordmark && <span className={cn("text-[15px] font-bold tracking-wide", wordmarkClassName)}>OMSSO</span>}
    </span>
  );
}
