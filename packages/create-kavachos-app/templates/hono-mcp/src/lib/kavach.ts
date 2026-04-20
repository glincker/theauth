import { createKavach } from "kavachos";

// Lazy singleton so imports do not open a DB connection before config is
// loaded. createKavach auto-creates the auth tables on first boot, no
// migration step required for development.
let instance: Awaited<ReturnType<typeof createKavach>> | null = null;

export async function getKavach() {
	if (!instance) {
		const provider = process.env["DB_PROVIDER"] === "postgres" ? "postgres" : "sqlite";
		instance = await createKavach({
			database: {
				provider,
				url: process.env["DATABASE_URL"] ?? "file:./kavach.db",
			},
			secret: process.env["KAVACHOS_SECRET"] ?? "dev-secret-change-me-in-prod",
			agents: {
				enabled: true,
				maxPerUser: 50,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		});
	}
	return instance;
}
