import { createKavach } from "kavachos";

// Initialised lazily so Next.js doesn't try to open a DB connection at build
// time. Import `getKavach()` from your server components or route handlers.
let instance: Awaited<ReturnType<typeof createKavach>> | null = null;

export async function getKavach() {
	if (!instance) {
		instance = await createKavach({
			database: {
				provider: "__DB_DRIVER__" === "pg" ? "postgres" : "sqlite",
				url: process.env["DATABASE_URL"] ?? "file:./kavach.db",
			},
			secret: process.env["KAVACHOS_SECRET"] ?? "dev-secret-change-me",
		});
	}
	return instance;
}
