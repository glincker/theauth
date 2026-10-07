import { createTheAuth } from "@glinr/theauth";

// Initialised lazily so Next.js doesn't try to open a DB connection at build
// time. Import `getTheAuth()` from your server components or route handlers.
let instance: Awaited<ReturnType<typeof createTheAuth>> | null = null;

export async function getTheAuth() {
	if (!instance) {
		instance = await createTheAuth({
			database: {
				provider: "__DB_DRIVER__" === "pg" ? "postgres" : "sqlite",
				url: process.env["DATABASE_URL"] ?? "file:./theauth.db",
			},
			secret: process.env["THEAUTH_SECRET"] ?? "dev-secret-change-me",
		});
	}
	return instance;
}
