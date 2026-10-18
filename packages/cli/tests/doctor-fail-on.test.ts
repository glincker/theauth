import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runProjectDoctorChecks } from "../src/doctor-live.js";
import type { DoctorCheck } from "../src/tools-commands.js";
import {
	DOCTOR_HELP,
	formatDoctor,
	parseDoctorArgs,
	reachesThreshold,
} from "../src/tools-commands.js";

const pass: DoctorCheck = { id: "p", status: "pass", message: "fine" };
const warn: DoctorCheck = { id: "w", status: "warn", message: "careful", fix: "do x" };
const info: DoctorCheck = { id: "i", status: "warn", severity: "info", message: "fyi" };
const fail: DoctorCheck = { id: "f", status: "fail", severity: "fail", message: "broken" };

describe("parseDoctorArgs --fail-on", () => {
	it("defaults to fail", () => {
		expect(parseDoctorArgs([], "/c").failOn).toBe("fail");
	});

	it("accepts info, warn and fail, as two words or with =", () => {
		expect(parseDoctorArgs(["--fail-on", "warn"], "/c")).toMatchObject({
			failOn: "warn",
			error: null,
		});
		expect(parseDoctorArgs(["--fail-on=info"], "/c")).toMatchObject({
			failOn: "info",
			error: null,
		});
		expect(parseDoctorArgs(["--fail-on", "fail", "--json"], "/c")).toMatchObject({
			failOn: "fail",
			json: true,
		});
	});

	it("rejects other values and a missing value", () => {
		expect(parseDoctorArgs(["--fail-on", "critical"], "/c").error).toMatch(
			/--fail-on must be one of/,
		);
		expect(parseDoctorArgs(["--fail-on"], "/c").error).toMatch(/--fail-on must be one of/);
	});

	it("is documented in the help text", () => {
		expect(DOCTOR_HELP).toContain("--fail-on <severity>");
		expect(DOCTOR_HELP).toContain("info < warn < fail");
	});
});

describe("exit code convention (formatDoctor ok)", () => {
	const all = [pass, warn, info, fail];
	it("fail (default) trips only on a failed check", () => {
		expect(formatDoctor([pass, warn, info], false).ok).toBe(true);
		expect(formatDoctor([pass, warn, info, fail], false).ok).toBe(false);
		expect(formatDoctor([warn], false, "fail").ok).toBe(true);
	});

	it("warn trips on warn and fail but not info", () => {
		expect(formatDoctor([pass, info], false, "warn").ok).toBe(true);
		expect(formatDoctor([pass, warn], false, "warn").ok).toBe(false);
		expect(formatDoctor([fail], false, "warn").ok).toBe(false);
	});

	it("info trips on every finding that is not a pass", () => {
		expect(formatDoctor([pass], false, "info").ok).toBe(true);
		expect(formatDoctor([pass, info], false, "info").ok).toBe(false);
		for (const c of all.slice(1)) expect(reachesThreshold(c, "info")).toBe(true);
		expect(reachesThreshold(pass, "info")).toBe(false);
	});

	it("a rule's severity wins over its status", () => {
		expect(reachesThreshold(info, "warn")).toBe(false);
		expect(reachesThreshold({ ...info, severity: "warn" }, "warn")).toBe(true);
	});

	it("json ok matches the threshold and the text names it", () => {
		const json = JSON.parse(formatDoctor([warn], true, "warn").text) as { ok: boolean };
		expect(json.ok).toBe(false);
		expect(formatDoctor([warn], false, "warn").text).toContain("--fail-on warn");
		expect(formatDoctor([info], false).text).toContain("info  fyi");
	});
});

describe("audit.secrets_table_collision", () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "theauth-doctor-audit-"));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	async function sqliteWith(secretsDdl: string | null): Promise<string> {
		const core = await import("@glinr/theauth");
		const file = join(dir, "app.db");
		const db = await core.createDatabase({ provider: "sqlite-native", url: file });
		await core.runSchemaMigrations(db, "sqlite-native", { to: "0001" });
		const client = (
			db as unknown as { $client: { exec: (sql: string) => void; close: () => void } }
		).$client;
		client.exec("DROP TABLE IF EXISTS theauth_audit_secrets");
		if (secretsDdl) client.exec(secretsDdl);
		client.close();
		return file;
	}

	const run = (file: string) =>
		runProjectDoctorChecks({ cwd: dir, env: { DATABASE_URL: file }, loadConfig: async () => null });

	it("warns when the table has the theauth-go layout, and changes nothing", async () => {
		const file = await sqliteWith(
			"CREATE TABLE theauth_audit_secrets (id INTEGER PRIMARY KEY, secret BLOB NOT NULL, created_at INTEGER NOT NULL)",
		);
		const checks = await run(file);
		const hit = checks.find((c) => c.id === "audit.secrets_table_collision");
		expect(hit).toMatchObject({ status: "warn", severity: "warn" });
		expect(hit?.message).toContain("theauth_audit_secrets");
		expect(formatDoctor(checks, false, "warn").ok).toBe(false);
		expect(
			formatDoctor(
				checks.filter((c) => c.status !== "fail"),
				false,
			).ok,
		).toBe(true);
		// A second run sees the same table: the dry run altered nothing.
		expect((await run(file)).some((c) => c.id === "audit.secrets_table_collision")).toBe(true);
	});

	it("stays quiet for this library's layout and for no table", async () => {
		const ours = await sqliteWith(
			"CREATE TABLE theauth_audit_secrets (id TEXT PRIMARY KEY, secret TEXT NOT NULL, created_at INTEGER NOT NULL)",
		);
		expect((await run(ours)).some((c) => c.id === "audit.secrets_table_collision")).toBe(false);
		const none = await sqliteWith(null);
		expect((await run(none)).some((c) => c.id === "audit.secrets_table_collision")).toBe(false);
	});

	it("is skipped without a database", async () => {
		const checks = await runProjectDoctorChecks({
			cwd: dir,
			env: {},
			loadConfig: async () => null,
		});
		expect(checks.some((c) => c.id === "audit.secrets_table_collision")).toBe(false);
	});
});
