"use client";

import { Toaster as Sonner } from "sonner";

// Short confirmations ("Client saved") and errors, bottom right.
// https://sonner.emilkowal.ski
function Toaster() {
  return (
    <Sonner
      position="bottom-right"
      closeButton
      toastOptions={{
        style: {
          background: "var(--surface)",
          color: "var(--text-primary)",
          border: "1px solid var(--border)",
          boxShadow: "var(--shadow-md)",
          fontFamily: "var(--font-sans)",
          fontSize: "13px",
        },
      }}
    />
  );
}

export { toast } from "sonner";
export { Toaster };
