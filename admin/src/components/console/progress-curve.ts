// How far the progress bar is after t ms (0 to 1). Used by the worker that
// draws it (progress-worker.ts); kept apart so it can be tested.
//
// Quick at first (the click visibly did something), then always creeping
// towards 95 %: the curve never goes flat, even for a long wait. The bar
// only reaches 100 % when the page is ready.
export function progressAt(t: number): number {
  const s = Math.max(0, t) / 1000;
  return Math.min(0.95, 0.08 + 0.6 * (1 - Math.exp(-s / 0.9)) + 0.27 * (1 - Math.exp(-s / 6)));
}
