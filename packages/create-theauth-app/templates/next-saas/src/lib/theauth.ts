import { createTheAuth } from "@glinr/theauth";

// Initialised lazily so Next.js doesn't try to open a DB connection at build
// time. Import `getTheAuth()` from your server components or route handlers.
let instance: Awaited<ReturnType<typeof createTheAuth>> | null = null;

const DRIVER = "__DB_DRIVER__" as string;
// SQLite uses a file on disk (better-sqlite3), so data survives restarts.
const PROVIDER = DRIVER === "pg" ? "postgres" : DRIVER === "sql.js" ? "sqlite" : "sqlite-native";

function requireSecret(): string {
	const value = process.env["THEAUTH_SECRET"];
	if (!value) throw new Error("THEAUTH_SECRET is not set. Fill it in .env.");
	return value;
}

export async function getTheAuth() {
	if (!instance) {
		const secret = requireSecret();
		instance = await createTheAuth({
			database: {
				provider: PROVIDER,
				url: process.env["DATABASE_URL"] ?? "./theauth.db",
			},
			secret,
			// Sessions are what the API routes use to tell who is calling. The
			// theAuthNextjs adapter rejects /agents, /audit and the other
			// management routes unless the caller has a valid session. Any
			// signed-in user passes, so pass your own `authenticate` to the
			// adapter if only admins should reach them.
			auth: {
				session: {
					secret,
				},
			},
		});
	}
	return instance;
}
