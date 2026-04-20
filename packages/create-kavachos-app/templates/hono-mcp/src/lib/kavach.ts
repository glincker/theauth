import { createKavach } from "kavachos";

// Lazy singleton so tests and scripts that import this file do not open a
// DB connection just from the import graph.
let instance: Awaited<ReturnType<typeof createKavach>> | null = null;

export async function getKavach() {
	if (!instance) {
		instance = await createKavach({
			database: {
				provider: "__DB_DRIVER__" === "pg" ? "postgres" : "sqlite",
				url: process.env["DATABASE_URL"] ?? "file:./kavach.db",
			},
			secret: process.env["KAVACHOS_SECRET"] ?? "dev-secret-change-me-in-prod",
		});
	}
	return instance;
}
