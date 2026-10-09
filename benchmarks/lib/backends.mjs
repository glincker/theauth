import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CORE_ENTRY =
	process.env.BENCH_CORE_ENTRY ??
	new URL("../../packages/core/dist/index.js", import.meta.url).href;

let corePromise;
/** Load the built SDK once. Run `pnpm --filter @glinr/theauth build` first. */
export function loadCore() {
	corePromise ??= import(CORE_ENTRY).catch((err) => {
		throw new Error(
			`Could not load the SDK from ${CORE_ENTRY}. Build it first: pnpm --filter @glinr/theauth build. (${err.message})`,
		);
	});
	return corePromise;
}

const tmpDirs = [];
function fileUrl(label) {
	const dir = mkdtempSync(join(tmpdir(), `theauth-bench-${label}-`));
	tmpDirs.push(dir);
	return join(dir, "bench.db");
}

function pickUrl(kind) {
	const explicit = kind === "postgres" ? process.env.POSTGRES_URL : process.env.MYSQL_URL;
	if (explicit) return explicit;
	const generic = process.env.DATABASE_URL;
	if (!generic) return null;
	const isPg = /^postgres(ql)?:/.test(generic);
	const isMy = /^mysql:/.test(generic);
	if (kind === "postgres" && isPg) return generic;
	if (kind === "mysql" && isMy) return generic;
	return null;
}

/**
 * Every backend the harness knows about. `config()` returns the database config
 * for createTheAuth, or null when the backend is not available in this run.
 * Postgres and MySQL are skipped unless a URL is provided, never failed.
 */
export const BACKENDS = {
	"sqlite-memory": {
		label: "SQLite (sql.js, in memory)",
		smoke: true,
		multiInstance: false,
		config: () => ({ provider: "sqlite", url: ":memory:" }),
	},
	"sqlite-file": {
		label: "SQLite (sql.js, file)",
		smoke: false,
		multiInstance: false,
		config: () => ({ provider: "sqlite", url: fileUrl("sqljs") }),
	},
	"sqlite-native-memory": {
		label: "SQLite (better-sqlite3, in memory)",
		smoke: true,
		multiInstance: false,
		config: () => ({ provider: "sqlite-native", url: ":memory:" }),
	},
	"sqlite-native-file": {
		label: "SQLite (better-sqlite3, file)",
		smoke: false,
		multiInstance: false,
		config: () => ({ provider: "sqlite-native", url: fileUrl("native") }),
	},
	postgres: {
		label: "Postgres (pg)",
		smoke: false,
		multiInstance: true,
		config: () => {
			const url = pickUrl("postgres");
			return url ? { provider: "postgres", url } : null;
		},
	},
	mysql: {
		label: "MySQL (mysql2)",
		smoke: false,
		multiInstance: true,
		config: () => {
			const url = pickUrl("mysql");
			return url ? { provider: "mysql", url } : null;
		},
	},
};

export function cleanupTempFiles() {
	for (const dir of tmpDirs) rmSync(dir, { recursive: true, force: true });
}

/**
 * Build a fixture bound to one backend. `open()` creates a TheAuth instance,
 * `seedUser()` adds a user owned by the fixture, and `ids` hands out unique
 * names so repeated runs against a shared Postgres or MySQL database do not collide.
 */
export async function createFixture(backendName) {
	const backend = BACKENDS[backendName];
	const dbConfig = backend.config();
	if (!dbConfig) return null;
	const core = await loadCore();
	const runId = Math.random().toString(36).slice(2, 10);
	let counter = 0;
	const uid = (prefix) => `${prefix}-${runId}-${counter++}`;

	async function open(extra = {}) {
		return core.createTheAuth({
			database: dbConfig,
			agents: {
				enabled: true,
				maxPerUser: 1_000_000_000,
				defaultPermissions: [],
				auditAll: extra.auditAll ?? true,
				tokenExpiry: "24h",
			},
			audit: extra.tamperEvident ? { tamperEvident: true, hmacKey: "bench-hmac-key" } : undefined,
			auth: extra.session
				? { session: { secret: "bench-session-secret-0123456789abcdef" } }
				: undefined,
		});
	}

	async function seedUser(theauth) {
		const id = uid("user");
		const now = new Date();
		await theauth.db.insert(core.users).values({
			id,
			email: `${id}@bench.invalid`,
			name: id,
			createdAt: now,
			updatedAt: now,
		});
		return id;
	}

	return { backendName, backend, core, open, seedUser, uid };
}
