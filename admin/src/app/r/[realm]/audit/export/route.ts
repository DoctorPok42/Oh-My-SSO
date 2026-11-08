import { NextResponse, type NextRequest } from "next/server";
import { apiDownload, apiPath } from "@/lib/api";
import { getI18n } from "@/i18n/server";

// GET /r/{realm}/audit/export?format=csv|json&action=...&from=...: the audit
// log entries matching the filters, as a file. The Admin API streams it
// (GET /realms/{realm}/audit-logs/export) and records the export in the log;
// this route only adds the admin's token, which the browser never sees.
// POST takes the same fields as a form: an export of selected entries (ids)
// would not fit in a URL once the bulk limit is raised.

const FILTERS = ["format", "action", "actor", "user", "client", "operation", "ids", "status", "level", "from", "to"];

export async function GET(req: NextRequest, { params }: { params: Promise<{ realm: string }> }) {
  return exportAudit(req, (await params).realm, (k) => req.nextUrl.searchParams.get(k));
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ realm: string }> }) {
  const form = await req.formData().catch(() => null);
  if (!form) return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  return exportAudit(req, (await params).realm, (k) => {
    const v = form.get(k);
    return typeof v === "string" ? v : null;
  });
}

async function exportAudit(req: NextRequest, realm: string, get: (key: string) => string | null) {
  // A link clicked on another site must not start an export (it would be
  // recorded under this admin's name): same-origin navigations only.
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    const { t } = await getI18n();
    return NextResponse.json(
      { error: "forbidden", message: t("audit.export.other_site", "Start the export from the console.") },
      { status: 403 },
    );
  }
  const query: Record<string, string> = {};
  for (const k of FILTERS) {
    const v = get(k);
    if (v) query[k] = v;
  }
  let path: string;
  try {
    path = apiPath(["realms", realm, "audit-logs", "export"], query);
  } catch {
    return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  }

  let res: Response | null;
  try {
    res = await apiDownload(path, req.headers);
  } catch (err) {
    console.error("audit export: admin api unreachable", err);
    return NextResponse.json({ error: "api_unreachable" }, { status: 502 });
  }
  if (!res) {
    return NextResponse.redirect(new URL(`/auth/login?returnTo=${encodeURIComponent(`/r/${realm}/audit`)}`, req.url));
  }
  if (!res.ok || !res.body) {
    const body = await res.json().catch(() => ({}));
    return NextResponse.json(body, { status: res.status });
  }
  const headers = new Headers({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  for (const h of ["content-type", "content-disposition"]) {
    const v = res.headers.get(h);
    if (v) headers.set(h, v);
  }
  return new Response(res.body, { status: 200, headers });
}
