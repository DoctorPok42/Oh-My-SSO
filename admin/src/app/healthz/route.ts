// GET /healthz: liveness probe for Docker and load balancers. Answers without
// a session and without calling anything else.
export const dynamic = "force-dynamic";

export function GET() {
  return Response.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
