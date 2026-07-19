import type { Database, DatabaseConfig } from "../db/database.js";
import type { SessionManager } from "../session/session.js";
import type { AuthConfig } from "../types.js";
import type { TheAuthPlugin, PluginContext, PluginEndpoint } from "./types.js";

export interface PluginRegistry {
	endpoints: PluginEndpoint[];
	migrations: string[];
	hooks: {
		onRequest: Array<NonNullable<TheAuthPlugin["hooks"]>["onRequest"]>;
		onAuthenticate: Array<NonNullable<TheAuthPlugin["hooks"]>["onAuthenticate"]>;
		onSessionCreate: Array<NonNullable<TheAuthPlugin["hooks"]>["onSessionCreate"]>;
		onSessionRevoke: Array<NonNullable<TheAuthPlugin["hooks"]>["onSessionRevoke"]>;
	};
	pluginContext: Record<string, unknown>;
}

/**
 * Run plugin migrations against the database.
 *
 * Follows the same pattern as createTables() — raw DDL executed against the
 * underlying driver.  Only CREATE TABLE IF NOT EXISTS statements should be
 * passed here; plugins are responsible for making their DDL idempotent.
 */
async function runMigrations(
	db: Database,
	provider: DatabaseConfig["provider"],
	statements: string[],
): Promise<void> {
	if (statements.length === 0) return;

	if (provider === "sqlite") {
		// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
		const session = (db as any).session;
		if (session?.client?.exec) {
			session.client.exec(`${statements.join(";\n")};`);
			return;
		}
		// biome-ignore lint/suspicious/noExplicitAny: raw SQL fallback for DDL execution
		const anyDb = db as any;
		for (const sql of statements) {
			await anyDb.run(sql);
		}
		return;
	}

	// biome-ignore lint/suspicious/noExplicitAny: raw DDL on pg/mysql adapter boundary
	const anyDb = db as any;

	if (provider === "postgres") {
		const client: { query: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"TheAuth plugin migrations: cannot access underlying pg client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.query(sql);
		}
		return;
	}

	if (provider === "mysql") {
		const client: { execute: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"TheAuth plugin migrations: cannot access underlying mysql2 client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.execute(sql);
		}
		return;
	}

	throw new Error(`runMigrations: unsupported provider "${provider}"`);
}

/**
 * Initialize all plugins and collect their endpoints, migrations, and hooks
 * into a single registry.
 *
 * Calls each plugin's `init()` in registration order.  Migrations collected
 * during init are executed before the registry is returned so that any
 * subsequent requests can immediately use plugin tables.
 */
export async function initializePlugins(
	plugins: TheAuthPlugin[],
	db: Database,
	config: AuthConfig,
	sessionManager: SessionManager | null,
): Promise<PluginRegistry> {
	const registry: PluginRegistry = {
		endpoints: [],
		migrations: [],
		hooks: {
			onRequest: [],
			onAuthenticate: [],
			onSessionCreate: [],
			onSessionRevoke: [],
		},
		pluginContext: {},
	};

	for (const plugin of plugins) {
		const pluginMigrations: string[] = [];

		const ctx: PluginContext = {
			db,
			config,
			sessionManager,
			addEndpoint(endpoint: PluginEndpoint): void {
				registry.endpoints.push(endpoint);
			},
			addMigration(sql: string): void {
				pluginMigrations.push(sql);
				registry.migrations.push(sql);
			},
		};

		if (plugin.init) {
			const result = await plugin.init(ctx);
			if (result?.context) {
				Object.assign(registry.pluginContext, result.context);
			}
		}

		// Collect lifecycle hooks
		if (plugin.hooks) {
			if (plugin.hooks.onRequest) {
				registry.hooks.onRequest.push(plugin.hooks.onRequest);
			}
			if (plugin.hooks.onAuthenticate) {
				registry.hooks.onAuthenticate.push(plugin.hooks.onAuthenticate);
			}
			if (plugin.hooks.onSessionCreate) {
				registry.hooks.onSessionCreate.push(plugin.hooks.onSessionCreate);
			}
			if (plugin.hooks.onSessionRevoke) {
				registry.hooks.onSessionRevoke.push(plugin.hooks.onSessionRevoke);
			}
		}

		// Run this plugin's migrations before moving to the next plugin so
		// later plugins can rely on tables created by earlier ones.
		if (pluginMigrations.length > 0) {
			await runMigrations(db, config.database.provider, pluginMigrations);
		}
	}

	return registry;
}
