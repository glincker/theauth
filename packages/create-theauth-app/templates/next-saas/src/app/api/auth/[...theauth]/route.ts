import { theAuthNextjs } from "@glinr/theauth-nextjs";
import { getTheAuth } from "@/lib/theauth";

// Build the handlers on first request so the database connection is not opened
// while `next build` evaluates this module.
type Handlers = ReturnType<typeof theAuthNextjs>;
let handlers: Handlers | null = null;

async function getHandlers(): Promise<Handlers> {
	if (!handlers) {
		handlers = theAuthNextjs(await getTheAuth(), { basePath: "/api/auth" });
	}
	return handlers;
}

export async function GET(request: Request): Promise<Response> {
	return (await getHandlers()).GET(request);
}

export async function POST(request: Request): Promise<Response> {
	return (await getHandlers()).POST(request);
}
