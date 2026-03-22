import type { Database, DatabaseConfig } from "./database.js";

// ──────────────────────────────────────────────────────────────────────────────
// Per-provider DDL helpers
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns CREATE TABLE statements for all 10 KavachOS tables, adapted to the
 * target SQL dialect.
 *
 * Dialect differences handled here:
 * - **Timestamps** – SQLite stores as INTEGER (Unix ms); Postgres uses
 *   TIMESTAMPTZ; MySQL uses DATETIME(3).
 * - **JSON columns** – SQLite stores as TEXT; Postgres uses JSONB;
 *   MySQL uses JSON.
 * - **Booleans** – SQLite stores as INTEGER (0/1); Postgres uses BOOLEAN;
 *   MySQL uses TINYINT(1).
 * - **Auto-increment** – Not used here (IDs are application-generated UUIDs /
 *   nanoids), so no SERIAL vs AUTO_INCREMENT difference applies.
 */
function buildStatements(provider: DatabaseConfig["provider"]): string[] {
	const isPostgres = provider === "postgres";
	const isMysql = provider === "mysql";

	// Timestamp column type
	const ts = isPostgres ? "TIMESTAMPTZ" : isMysql ? "DATETIME(3)" : "INTEGER";
	// Nullable timestamp (same type, just no NOT NULL)
	const tsNull = ts;
	// JSON column type
	const json = isPostgres ? "JSONB" : isMysql ? "JSON" : "TEXT";
	// Boolean column type
	const bool = isPostgres ? "BOOLEAN" : isMysql ? "TINYINT(1)" : "INTEGER";
	// IF NOT EXISTS is universally supported
	const ifne = "IF NOT EXISTS";

	return [
		// ------------------------------------------------------------------
		// kavach_users
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_users (
  id          TEXT        NOT NULL PRIMARY KEY,
  email       TEXT        NOT NULL UNIQUE,
  name        TEXT,
  external_id TEXT,
  external_provider TEXT,
  metadata    ${json},
  created_at  ${ts}       NOT NULL,
  updated_at  ${ts}       NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_tenants  (must come before kavach_agents – agents FK to tenants)
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_tenants (
  id         TEXT NOT NULL PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL UNIQUE,
  settings   ${json},
  status     TEXT NOT NULL DEFAULT 'active',
  created_at ${ts} NOT NULL,
  updated_at ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_agents
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_agents (
  id              TEXT  NOT NULL PRIMARY KEY,
  owner_id        TEXT  NOT NULL REFERENCES kavach_users(id),
  tenant_id       TEXT  REFERENCES kavach_tenants(id),
  name            TEXT  NOT NULL,
  type            TEXT  NOT NULL,
  status          TEXT  NOT NULL DEFAULT 'active',
  token_hash      TEXT  NOT NULL,
  token_prefix    TEXT  NOT NULL,
  expires_at      ${tsNull},
  last_active_at  ${tsNull},
  metadata        ${json},
  created_at      ${ts} NOT NULL,
  updated_at      ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_permissions
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_permissions (
  id          TEXT  NOT NULL PRIMARY KEY,
  agent_id    TEXT  NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  resource    TEXT  NOT NULL,
  actions     ${json} NOT NULL,
  constraints ${json},
  created_at  ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_delegation_chains
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_delegation_chains (
  id            TEXT    NOT NULL PRIMARY KEY,
  from_agent_id TEXT    NOT NULL REFERENCES kavach_agents(id),
  to_agent_id   TEXT    NOT NULL REFERENCES kavach_agents(id),
  permissions   ${json} NOT NULL,
  depth         INTEGER NOT NULL DEFAULT 1,
  max_depth     INTEGER NOT NULL DEFAULT 3,
  status        TEXT    NOT NULL DEFAULT 'active',
  expires_at    ${ts}   NOT NULL,
  created_at    ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_audit_logs
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_audit_logs (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES kavach_agents(id),
  user_id      TEXT    NOT NULL REFERENCES kavach_users(id),
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   ${json},
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  timestamp    ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_rate_limits
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_rate_limits (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  resource     TEXT    NOT NULL,
  window_start ${ts}   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0
)`,

		// ------------------------------------------------------------------
		// kavach_mcp_servers
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_mcp_servers (
  id               TEXT    NOT NULL PRIMARY KEY,
  name             TEXT    NOT NULL,
  endpoint         TEXT    NOT NULL UNIQUE,
  tools            ${json} NOT NULL,
  auth_required    ${bool} NOT NULL DEFAULT ${isPostgres ? "TRUE" : "1"},
  rate_limit_rpm   INTEGER,
  status           TEXT    NOT NULL DEFAULT 'active',
  created_at       ${ts}   NOT NULL,
  updated_at       ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_sessions
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_sessions (
  id         TEXT    NOT NULL PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES kavach_users(id),
  expires_at ${ts}   NOT NULL,
  metadata   ${json},
  created_at ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_oauth_clients
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_oauth_clients (
  id                          TEXT    NOT NULL PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret               TEXT,
  client_name                 TEXT,
  client_uri                  TEXT,
  redirect_uris               ${json} NOT NULL,
  grant_types                 ${json} NOT NULL,
  response_types              ${json} NOT NULL,
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_basic',
  type                        TEXT    NOT NULL DEFAULT 'confidential',
  disabled                    ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  metadata                    ${json},
  created_at                  ${ts}   NOT NULL,
  updated_at                  ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_oauth_access_tokens
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_oauth_access_tokens (
  id                        TEXT NOT NULL PRIMARY KEY,
  access_token              TEXT NOT NULL UNIQUE,
  refresh_token             TEXT UNIQUE,
  client_id                 TEXT NOT NULL REFERENCES kavach_oauth_clients(client_id),
  user_id                   TEXT NOT NULL REFERENCES kavach_users(id),
  scopes                    TEXT NOT NULL,
  resource                  TEXT,
  access_token_expires_at   ${ts} NOT NULL,
  refresh_token_expires_at  ${tsNull},
  created_at                ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_agent_cards
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_agent_cards (
  id               TEXT    NOT NULL PRIMARY KEY,
  agent_id         TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  name             TEXT    NOT NULL,
  description      TEXT,
  version          TEXT    NOT NULL,
  protocols        ${json} NOT NULL,
  capabilities     ${json} NOT NULL,
  auth_requirements ${json} NOT NULL,
  endpoint         TEXT,
  metadata         ${json},
  created_at       ${ts}   NOT NULL,
  updated_at       ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_approval_requests
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_approval_requests (
  id            TEXT NOT NULL PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES kavach_users(id),
  action        TEXT NOT NULL,
  resource      TEXT NOT NULL,
  arguments     ${json},
  status        TEXT NOT NULL DEFAULT 'pending',
  expires_at    ${ts} NOT NULL,
  responded_at  ${tsNull},
  responded_by  TEXT,
  created_at    ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_trust_scores
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_trust_scores (
  agent_id     TEXT    NOT NULL PRIMARY KEY REFERENCES kavach_agents(id) ON DELETE CASCADE,
  score        INTEGER NOT NULL,
  level        TEXT    NOT NULL,
  factors      ${json} NOT NULL,
  computed_at  ${ts}   NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_oauth_authorization_codes
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_oauth_authorization_codes (
  id                     TEXT NOT NULL PRIMARY KEY,
  code                   TEXT NOT NULL UNIQUE,
  client_id              TEXT NOT NULL REFERENCES kavach_oauth_clients(client_id),
  user_id                TEXT NOT NULL REFERENCES kavach_users(id),
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  resource               TEXT,
  expires_at             ${ts} NOT NULL,
  created_at             ${ts} NOT NULL
)`,

		// ------------------------------------------------------------------
		// kavach_budget_policies
		// ------------------------------------------------------------------
		`CREATE TABLE ${ifne} kavach_budget_policies (
  id            TEXT    NOT NULL PRIMARY KEY,
  agent_id      TEXT    REFERENCES kavach_agents(id) ON DELETE CASCADE,
  user_id       TEXT    REFERENCES kavach_users(id),
  tenant_id     TEXT    REFERENCES kavach_tenants(id),
  limits        ${json} NOT NULL,
  current_usage ${json} NOT NULL,
  action        TEXT    NOT NULL DEFAULT 'warn',
  status        TEXT    NOT NULL DEFAULT 'active',
  created_at    ${ts}   NOT NULL
)`,
	];
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Create all KavachOS tables if they do not already exist.
 *
 * Uses `CREATE TABLE IF NOT EXISTS` so it is safe to call on every startup.
 * Tables are created in dependency order (no forward-reference FK issues).
 *
 * @param db       Drizzle database instance returned by `createDatabase()`.
 * @param provider The database provider used to build the correct DDL syntax.
 *
 * @example
 * ```typescript
 * const db = await createDatabase({ provider: 'postgres', url: process.env.DATABASE_URL });
 * await createTables(db, 'postgres');
 * ```
 */
export async function createTables(
	db: Database,
	provider: DatabaseConfig["provider"],
): Promise<void> {
	const statements = buildStatements(provider);

	if (provider === "sqlite") {
		// SQLite Drizzle exposes the underlying better-sqlite3 instance via
		// the `session` property. We use it for synchronous multi-statement
		// execution which is the most reliable path for DDL on SQLite.
		// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
		const session = (db as any).session;
		if (session?.client?.exec) {
			// better-sqlite3 Database.exec() runs multiple statements separated
			// by semicolons in a single call.
			session.client.exec(`${statements.join(";\n")};`);
			return;
		}
		// Fallback: run each statement individually via drizzle `run`.
		// biome-ignore lint/suspicious/noExplicitAny: raw SQL fallback for DDL execution
		const anyDb = db as any;
		for (const sql of statements) {
			await anyDb.run(sql);
		}
		return;
	}

	// Postgres and MySQL: execute each statement via the underlying pool/client.
	// We access the internal session to issue raw DDL since drizzle-orm/node-postgres
	// and drizzle-orm/mysql2 both expose `.session.client` (or `.client`).
	// biome-ignore lint/suspicious/noExplicitAny: raw DDL on pg/mysql adapter boundary
	const anyDb = db as any;

	if (provider === "postgres") {
		// drizzle-orm/node-postgres wraps a `pg` Pool; the pool is at db.session.client
		// or accessible via db.$client depending on drizzle version.
		const client: { query: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"KavachOS createTables: cannot access underlying pg client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.query(sql);
		}
		return;
	}

	if (provider === "mysql") {
		// drizzle-orm/mysql2 wraps a mysql2 Pool; exposed at db.$client.
		const client: { execute: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"KavachOS createTables: cannot access underlying mysql2 client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.execute(sql);
		}
		return;
	}

	throw new Error(`createTables: unsupported provider "${provider}"`);
}
