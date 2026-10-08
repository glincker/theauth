import { findPlugin } from "./plugin-catalog.js";

export interface SchemaRequest {
	plugins: string[];
	agents: boolean;
	mcp: boolean;
}

export type SchemaResult = { ok: true; text: string } | { ok: false; message: string };

interface SqliteRow {
	name: string;
	sql: string;
}

interface DbHandle {
	client?: { prepare(sql: string): { all(): unknown[] }; close?(): void };
}

const STUB_CONFIGS: Record<string, Record<string, unknown>> = {
	magicLink: { appUrl: "http://localhost", sendMagicLink: async () => undefined },
	emailOtp: { sendOtp: async () => undefined },
	passkey: { rpName: "app", rpId: "localhost", origin: "http://localhost" },
};

/**
 * Create an in-memory SQLite instance with the requested features and read the
 * DDL back. Postgres and MySQL get the same tables with dialect-adapted types
 * when the app starts, so this is a reference for the table set, not a migration.
 */
export async function generateSchema(req: SchemaRequest): Promise<SchemaResult> {
	let core: Record<string, unknown>;
	try {
		core = (await import("@glinr/theauth")) as Record<string, unknown>;
	} catch (err) {
		return { ok: false, message: `Could not load @glinr/theauth: ${errMessage(err)}` };
	}
	const createTheAuth = core.createTheAuth as
		| ((config: Record<string, unknown>) => Promise<unknown>)
		| undefined;
	if (!createTheAuth) return { ok: false, message: "@glinr/theauth has no createTheAuth export." };

	const plugins: unknown[] = [];
	for (const id of req.plugins) {
		const entry = findPlugin(id);
		if (!entry) return { ok: false, message: `Unknown plugin "${id}".` };
		if (entry.importFrom !== "@glinr/theauth") continue;
		const factory = core[entry.factory] as ((c?: unknown) => unknown) | undefined;
		if (!factory) return { ok: false, message: `@glinr/theauth does not export ${entry.factory}.` };
		plugins.push(factory(STUB_CONFIGS[entry.factory]));
	}
	const config: Record<string, unknown> = {
		database: { provider: "sqlite-native", url: ":memory:" },
		plugins,
	};
	if (req.agents) config.agents = { enabled: true };
	if (req.mcp) config.mcp = { enabled: true };
	config.auth = { session: { secret: "x".repeat(32) } };

	try {
		const instance = (await createTheAuth(config)) as { db?: DbHandle & Record<string, unknown> };
		const handle = instance.db as unknown as { $client?: DbHandle["client"] } | undefined;
		const client = handle?.$client;
		if (!client) return { ok: false, message: "Could not read the generated schema from SQLite." };
		const rows = client
			.prepare(
				"SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name LIKE 'theauth_%' ORDER BY name",
			)
			.all() as SqliteRow[];
		client.close?.();
		const text = [
			`-- ${rows.length} tables (SQLite dialect, needs better-sqlite3). TheAuth creates these on startup; Postgres and MySQL use adapted types.`,
			...rows.map((r) => `${r.sql};`),
		].join("\n\n");
		return { ok: true, text };
	} catch (err) {
		return {
			ok: false,
			message: `Schema generation needs better-sqlite3 installed: ${errMessage(err)}`,
		};
	}
}

function errMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
