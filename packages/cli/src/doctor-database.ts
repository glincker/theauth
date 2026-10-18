import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { TheAuthConfig } from "@glinr/theauth";
import type { DoctorRule } from "./doctor-rules.js";

export type DoctorProvider = "postgres" | "mysql" | "sqlite-native";

export interface DoctorDatabase {
	provider: DoctorProvider;
	/** As configured: a connection string, or a SQLite path relative to the project. */
	url: string;
}

/** The database the doctor inspects: `DATABASE_URL`, else the url in the config. Null when neither names one. */
export function resolveDoctorDatabase(
	env: Record<string, string | undefined>,
	config: TheAuthConfig | null,
): DoctorDatabase | null {
	const db = config?.database;
	const fromConfig = db && "url" in db ? db : null;
	const url = env["DATABASE_URL"] ?? fromConfig?.url;
	if (!url) return null;
	const provider: DoctorProvider = /^postgres(ql)?:\/\//.test(url)
		? "postgres"
		: /^mysql:\/\//.test(url)
			? "mysql"
			: "sqlite-native";
	return { provider, url };
}

/** True when a SQLite file path is not on disk yet (nothing to inspect). */
export function sqliteFileMissing(cwd: string, target: DoctorDatabase): boolean {
	return (
		target.provider === "sqlite-native" &&
		target.url !== ":memory:" &&
		!existsSync(resolve(cwd, target.url))
	);
}

/**
 * `audit.secrets_table_collision` (warn): `theauth_audit_secrets` exists with the layout theauth-go creates (integer id, binary secret), so both libraries share this database and TheAuth refuses to migrate it. Read only: it runs a dry run of the migrator, which checks the table layout before it plans anything and writes nothing. Returns null when there is no database to inspect, the layout is ours or absent, or the inspection itself fails (the `schema` check reports that).
 */
export async function auditSecretsCollisionRule(
	cwd: string,
	env: Record<string, string | undefined>,
	config: TheAuthConfig | null,
): Promise<DoctorRule | null> {
	const target = resolveDoctorDatabase(env, config);
	if (!target || sqliteFileMissing(cwd, target)) return null;
	try {
		const core = await import("@glinr/theauth");
		const database = await core.createDatabase({
			provider: target.provider,
			url: target.provider === "sqlite-native" ? resolve(cwd, target.url) : target.url,
		});
		try {
			await core.runSchemaMigrations(database, target.provider, {
				dryRun: true,
				...(config ? { config } : {}),
			});
			return null;
		} finally {
			// biome-ignore lint/suspicious/noExplicitAny: reaching the driver pool so the process can exit
			const client = (database as any).$client as { end?: () => unknown } | undefined;
			try {
				await client?.end?.();
			} catch {
				// Already closed.
			}
		}
	} catch (error) {
		const e = error as { code?: unknown; found?: unknown };
		if (e.code !== "AUDIT_SECRETS_LAYOUT_MISMATCH") return null;
		return {
			id: "audit.secrets_table_collision",
			status: "warn",
			severity: "warn",
			message: `theauth_audit_secrets has another library's layout (${typeof e.found === "string" ? e.found : "unknown columns"}), so TheAuth will not migrate this database`,
			fix: "Give TheAuth and theauth-go each their own database or schema. Nothing was changed.",
		};
	}
}
