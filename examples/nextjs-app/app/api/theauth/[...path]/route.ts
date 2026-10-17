// Catch-all route. Every TheAuth REST path (agents, authorize, delegations, audit, dashboard) goes to theAuthNextjs.

import { theAuthNextjs } from "@glinr/theauth-nextjs";
import { getTheAuth } from "@/lib/theauth";

// Lazy so the singleton is created on first request, not during the build step.
async function getHandlers() {
	const auth = await getTheAuth();
	// Demo only: no authentication on the management routes. Real apps pass
	// `authenticate` (see the adapter docs).
	return theAuthNextjs(auth, { basePath: "/api/theauth", allowUnauthenticated: true });
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
