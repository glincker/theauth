import { createTheAuth } from "@glinr/theauth";

// Lazy singleton so imports do not open a DB connection before config is
// loaded. createTheAuth auto-creates the auth tables on first boot, no
// migration step required for development.
let instance: Awaited<ReturnType<typeof createTheAuth>> | null = null;

export async function getTheAuth() {
	if (!instance) {
		const provider = process.env["DB_PROVIDER"] === "postgres" ? "postgres" : "sqlite";
		instance = await createTheAuth({
			database: {
				provider,
				url: process.env["DATABASE_URL"] ?? "file:./theauth.db",
			},
			secret: process.env["THEAUTH_SECRET"] ?? "dev-secret-change-me-in-prod",
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
