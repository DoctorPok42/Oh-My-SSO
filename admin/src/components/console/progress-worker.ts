// The progress bar's drawing, in a Web Worker: its own thread, with its own
// requestAnimationFrame. The page (main thread) only says "start" and
// "done"; while it is busy (React rendering a big page, a long script), the
// bar keeps moving.
//
// It draws on an OffscreenCanvas: a <canvas> of the page whose drawing was
// handed over to this worker (transferControlToOffscreen). Its frames go
// straight to the screen, without the main thread.
// https://developer.mozilla.org/en-US/docs/Web/API/OffscreenCanvas
// https://developer.mozilla.org/en-US/docs/Web/API/DedicatedWorkerGlobalScope/requestAnimationFrame

import { progressAt } from "./progress-curve";

export type ProgressMessage =
  | { type: "init"; canvas: OffscreenCanvas; width: number; dpr: number }
  | { type: "resize"; width: number; dpr: number }
  | { type: "start"; color: string; reducedMotion: boolean }
  | { type: "done" };

const HEIGHT = 3; // CSS pixels
const SHOW_DELAY = 150; // ms: a fast navigation shows nothing
const FINISH_MS = 180; // run to 100 %
const FADE_MS = 220; // then fade out
const SHIMMER_MS = 1100; // a light band runs along the bar: always some motion

// The worker's global scope, typed by hand: the "webworker" type library
// would clash with the DOM types of the rest of the console.
const scope = self as unknown as {
  requestAnimationFrame?: (cb: (now: number) => void) => number;
  onmessage: ((e: MessageEvent<ProgressMessage>) => void) | null;
};

let canvas: OffscreenCanvas | null = null;
let ctx: OffscreenCanvasRenderingContext2D | null = null;
let cssWidth = 0;
let dpr = 1;

let state: "idle" | "running" | "finishing" = "idle";
let color = "#3557d6";
let reducedMotion = false;
let startedAt = 0;
let finishedAt = 0;
let finishFrom = 0;
let scheduled = false;

// requestAnimationFrame in a worker (Chrome, Firefox, Safari 16.4+), else a
// 60 Hz timer.
const raf = scope.requestAnimationFrame?.bind(scope);
const nextFrame: (cb: (now: number) => void) => void = raf
  ? (cb) => void raf(cb)
  : (cb) => void setTimeout(() => cb(performance.now()), 16);

function schedule() {
  if (scheduled) return;
  scheduled = true;
  nextFrame((now) => {
    scheduled = false;
    draw(now);
  });
}

function resize(width: number, ratio: number) {
  if (!canvas) return;
  cssWidth = width;
  dpr = ratio;
  canvas.width = Math.max(1, Math.round(width * ratio));
  canvas.height = Math.round(HEIGHT * ratio);
  if (state !== "idle") schedule();
}

function draw(now: number) {
  if (!ctx || !canvas) return;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (state === "idle") return;

  const elapsed = now - startedAt - SHOW_DELAY;
  if (state === "running" && elapsed < 0) {
    schedule(); // not visible yet
    return;
  }

  let p = reducedMotion ? 0.6 : progressAt(elapsed);
  let alpha = 1;
  if (state === "finishing") {
    const t = now - finishedAt;
    p = finishFrom + (1 - finishFrom) * Math.min(1, t / FINISH_MS);
    alpha = t <= FINISH_MS ? 1 : Math.max(0, 1 - (t - FINISH_MS) / FADE_MS);
    if (alpha === 0) {
      state = "idle";
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }
  }

  ctx.scale(dpr, dpr);
  const w = cssWidth * p;
  ctx.globalAlpha = alpha;
  ctx.fillStyle = color;
  ctx.fillRect(0, 0, w, HEIGHT);

  if (!reducedMotion && state === "running") {
    const band = Math.min(160, w / 2);
    const x = (((now - startedAt) % SHIMMER_MS) / SHIMMER_MS) * (w + band) - band;
    const g = ctx.createLinearGradient(x, 0, x + band, 0);
    g.addColorStop(0, "rgba(255,255,255,0)");
    g.addColorStop(0.5, "rgba(255,255,255,0.55)");
    g.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = g;
    ctx.fillRect(Math.max(0, x), 0, Math.min(band, w - Math.max(0, x)), HEIGHT);
  }
  ctx.globalAlpha = 1;
  schedule();
}

scope.onmessage = (e: MessageEvent<ProgressMessage>) => {
  const m = e.data;
  const now = performance.now();
  switch (m.type) {
    case "init":
      canvas = m.canvas;
      ctx = canvas.getContext("2d");
      resize(m.width, m.dpr);
      break;
    case "resize":
      resize(m.width, m.dpr);
      break;
    case "start":
      color = m.color || color;
      reducedMotion = m.reducedMotion;
      if (state !== "running") {
        state = "running";
        startedAt = now;
      }
      schedule();
      break;
    case "done":
      if (state !== "running") break;
      if (now - startedAt < SHOW_DELAY) {
        state = "idle"; // never shown: nothing to finish
      } else {
        state = "finishing";
        finishedAt = now;
        finishFrom = reducedMotion ? 0.6 : progressAt(now - startedAt - SHOW_DELAY);
      }
      schedule();
      break;
  }
};
