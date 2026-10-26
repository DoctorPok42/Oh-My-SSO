"use client";

import type { ProgressMessage } from "./progress-worker";

// The progress bar's controller, on the main thread. It creates a <canvas>
// once per page load, hands its drawing to a Web Worker
// (progress-worker.ts), and from then on only posts "start" and "done": no
// React render, no style recalculation, no animation on this thread.
//
// Browsers without OffscreenCanvas in workers keep the CSS bar
// (NavigationProgress): `workerBar()` returns false.
// https://developer.mozilla.org/en-US/docs/Web/API/HTMLCanvasElement/transferControlToOffscreen

let worker: Worker | null = null;
let tried = false;

/** Sets the worker bar up (once); false when the browser cannot. */
export function workerBar(): boolean {
  if (tried) return worker !== null;
  tried = true;
  if (typeof window === "undefined" || typeof Worker === "undefined") return false;
  const canvas = document.createElement("canvas");
  if (!("transferControlToOffscreen" in canvas)) return false;
  try {
    // The bundler turns this into a worker file served by this site
    // (worker-src 'self' in the CSP).
    // https://nextjs.org/docs/app/api-reference/config/next-config-js/turbopack
    const w = new Worker(new URL("./progress-worker.ts", import.meta.url), { type: "module" });
    canvas.className = "nav-progress-canvas";
    canvas.setAttribute("aria-hidden", "true");
    canvas.dataset.progressCanvas = "";
    document.body.append(canvas);
    const offscreen = canvas.transferControlToOffscreen();
    post(w, { type: "init", canvas: offscreen, width: window.innerWidth, dpr: window.devicePixelRatio || 1 }, [
      offscreen,
    ]);
    window.addEventListener("resize", () =>
      post(w, { type: "resize", width: window.innerWidth, dpr: window.devicePixelRatio || 1 }),
    );
    w.addEventListener("error", () => {
      // The worker could not start (blocked script...): back to CSS.
      canvas.remove();
      worker = null;
      document.documentElement.dataset.progressRenderer = "css";
    });
    worker = w;
    document.documentElement.dataset.progressRenderer = "worker";
    return true;
  } catch {
    canvas.remove();
    return false;
  }
}

function post(w: Worker, m: ProgressMessage, transfer: Transferable[] = []) {
  w.postMessage(m, transfer);
}

/** Something started loading. */
export function progressStart() {
  if (!worker) return;
  const color = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  post(worker, { type: "start", color, reducedMotion });
}

/** Everything finished loading. */
export function progressDone() {
  if (worker) post(worker, { type: "done" });
}
