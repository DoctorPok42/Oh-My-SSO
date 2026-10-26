import type { ApiErrorBody } from "@/lib/types";

// Shared by the server (thrown by lib/api.ts) and the browser (the plain
// objects Server Actions return): a stable error code the UI switches on,
// and a sentence it can show as is.

export type ApiFailure = ApiErrorBody & { ok: false; status: number; message: string };
export type ApiResult<T> = { ok: true; data: T } | ApiFailure;

export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message ?? body.error);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }

  get code(): string {
    return this.body.error;
  }

  toJSON(): Omit<ApiFailure, "ok"> {
    return { ...this.body, status: this.status, message: this.message };
  }
}

/** Errors that a new sign-in with the second factor fixes. */
export function needsStepUp(r: { error?: string }): boolean {
  return r.error === "step_up_required" || r.error === "mfa_enrollment_required";
}

/** Errors that only a new sign-in fixes. */
export function needsSignIn(r: { error?: string; status?: number }): boolean {
  return r.status === 401 || r.error === "unauthenticated" || r.error === "invalid_token";
}
