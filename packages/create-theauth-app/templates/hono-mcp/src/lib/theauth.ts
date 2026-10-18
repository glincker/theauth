import { createTheAuth } from "@glinr/theauth";

const DRIVER = "__DB_DRIVER__" as string;
// SQLite uses a file on disk (better-sqlite3), so data survives restarts.
const PROVIDER = DRIVER === "pg" ? "postgres" : DRIVER === "sql.js" ? "sqlite" : "sqlite-native";

function requireEnv(name: string): string {
	const value = process.env[name];
	if (!value) {
		throw new Error(`${name} is not set. Copy .env.example to .env and fill it in.`);
	}
	return value;
}

// Lazy singleton so imports do not open a database connection early.
// createTheAuth creates the auth tables on first boot. Check them any time with
// `npx @glinr/theauth-cli db status`.
let instance: ReturnType<typeof createTheAuth> | null = null;

export function getTheAuth() {
	instance ??= createTheAuth({
		database: {
			provider: PROVIDER,
			url: process.env["DATABASE_URL"] ?? "./theauth.db",
		},
		secret: requireEnv("THEAUTH_SECRET"),
		agents: {
			enabled: true,
			maxPerUser: 50,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	return instance;
}
