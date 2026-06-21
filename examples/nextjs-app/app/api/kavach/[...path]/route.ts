// TheAuth Next.js App Router catch-all route.
//
// Mounts at /api/kavach/[...path] and forwards every request to the
// kavachNextjs adapter, which handles all TheAuth REST routes.
//
// Routes handled:
//   GET/POST        /api/kavach/agents
//   GET/PATCH/DELETE /api/kavach/agents/:id
//   POST            /api/kavach/agents/:id/rotate
//   POST            /api/kavach/authorize
//   POST            /api/kavach/authorize/token
//   POST            /api/kavach/delegations
//   GET/DELETE      /api/kavach/delegations/:id
//   GET             /api/kavach/audit
//   GET             /api/kavach/audit/export
//   GET             /api/kavach/dashboard/stats
//   GET             /api/kavach/dashboard/agents
//   GET             /api/kavach/dashboard/audit

import { kavachNextjs } from "@glinr/theauth-nextjs";
import { getKavach } from "@/lib/kavach";

// Build handlers lazily so the singleton is created on first request, not at
// module evaluation time (which would run during the build step).
async function getHandlers() {
	const kavach = await getKavach();
	return kavachNextjs(kavach, { basePath: "/api/kavach" });
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
