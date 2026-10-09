import { createTheAuth } from "@glinr/theauth";

// Initialised lazily so Next.js doesn't try to open a DB connection at build
// time. Import `getTheAuth()` from your server components or route handlers.
let instance: Awaited<ReturnType<typeof createTheAuth>> | null = null;

export async function getTheAuth() {
	if (!instance) {
		instance = await createTheAuth({
			database: {
				provider: "__DB_DRIVER__" === "pg" ? "postgres" : "sqlite",
				url: process.env["DATABASE_URL"] ?? "./theauth.db",
			},
			secret: process.env["THEAUTH_SECRET"] ?? "dev-secret-change-me-at-least-32-chars",
			// Sessions are what the API routes use to tell who is calling. The
			// theAuthNextjs adapter rejects /agents, /audit and the other
			// management routes unless the caller has a valid session. Any
			// signed-in user passes, so pass your own `authenticate` to the
			// adapter if only admins should reach them.
			auth: {
				session: {
					secret: process.env["THEAUTH_SECRET"] ?? "dev-secret-change-me-at-least-32-chars",
				},
			},
		});
	}
	return instance;
}
