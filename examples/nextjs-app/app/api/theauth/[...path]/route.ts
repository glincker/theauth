// TheAuth Next.js App Router catch-all route.
//
// Mounts at /api/theauth/[...path] and forwards every request to the
// kavachNextjs adapter, which handles all TheAuth REST routes.
//
// Routes handled:
//   GET/POST        /api/theauth/agents
//   GET/PATCH/DELETE /api/theauth/agents/:id
//   POST            /api/theauth/agents/:id/rotate
//   POST            /api/theauth/authorize
//   POST            /api/theauth/authorize/token
//   POST            /api/theauth/delegations
//   GET/DELETE      /api/theauth/delegations/:id
//   GET             /api/theauth/audit
//   GET             /api/theauth/audit/export
//   GET             /api/theauth/dashboard/stats
//   GET             /api/theauth/dashboard/agents
//   GET             /api/theauth/dashboard/audit

import { kavachNextjs } from "@glinr/theauth-nextjs";
import { getKavach } from "@/lib/kavach";

// Build handlers lazily so the singleton is created on first request, not at
// module evaluation time (which would run during the build step).
async function getHandlers() {
	const kavach = await getKavach();
	return kavachNextjs(kavach, { basePath: "/api/theauth" });
}

export async function GET(request: Request): Promise<Response> {
	const handlers = await getHandlers();
	return handlers.GET(request);
}

export async function POST(request: Request): Promise<Response> {
	const handlers = await getHandlers();
	return handlers.POST(request);
}

export async function PATCH(request: Request): Promise<Response> {
	const handlers = await getHandlers();
	return handlers.PATCH(request);
}

export async function DELETE(request: Request): Promise<Response> {
	const handlers = await getHandlers();
	return handlers.DELETE(request);
}

export async function OPTIONS(request: Request): Promise<Response> {
	const handlers = await getHandlers();
	return handlers.OPTIONS(request);
}
