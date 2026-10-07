import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { transformSource } from "../src/codemod.js";
import { formatSummary, parseCodemodArgs, runRenameCodemod } from "../src/codemod-run.js";

describe("transformSource: identifiers", () => {
	it("renames import specifiers, usages and type references", () => {
		const input = [
			'import { createKavach, type KavachConfig } from "@glinr/theauth";',
			"const config: KavachConfig = { database: db };",
			"const auth = await createKavach(config);",
			"export type Instance = KavachInstance;",
			"",
		].join("\n");
		const expected = [
			'import { createTheAuth, type TheAuthConfig } from "@glinr/theauth";',
			"const config: TheAuthConfig = { database: db };",
			"const auth = await createTheAuth(config);",
			"export type Instance = TheAuthInstance;",
			"",
		].join("\n");
		const result = transformSource(input, "script");
		expect(result.output).toBe(expected);
		expect(result.counts.get("createKavach")).toBe(2);
		expect(result.counts.get("KavachConfig")).toBe(2);
	});

	it("renames JSX component names including closing tags", () => {
		const input = `<KavachProvider client={client}>\n  <App />\n</KavachProvider>;\n`;
		const result = transformSource(input, "script");
		expect(result.output).toBe(
			`<TheAuthProvider client={client}>\n  <App />\n</TheAuthProvider>;\n`,
		);
		expect(result.counts.get("KavachProvider")).toBe(2);
	});

	it("prefers the longest name and respects word boundaries", () => {
		const input = "KavachProviderProps KavachProvider MyKavachProvider KavachProviders $KavachUser";
		const result = transformSource(input, "script");
		expect(result.output).toBe(
			"TheAuthProviderProps TheAuthProvider MyKavachProvider KavachProviders $KavachUser",
		);
	});

	it("does not change string literals that are not import paths or env names", () => {
		const input = [
			'const a = "KavachProvider is required";',
			"const b = 'createKavach';",
			"const c = `call createKavach ${createKavach} now`;",
			"",
		].join("\n");
		const result = transformSource(input, "script");
		expect(result.output).toBe(
			[
				'const a = "KavachProvider is required";',
				"const b = 'createKavach';",
				"const c = `call createKavach ${createTheAuth} now`;",
				"",
			].join("\n"),
		);
	});

	it("renames identifiers in comments", () => {
		const result = transformSource("// see KavachConfig\n/** @link KavachUser */\n", "script");
		expect(result.output).toBe("// see TheAuthConfig\n/** @link TheAuthUser */\n");
	});

	it("treats an apostrophe in JSX text as prose, not a string", () => {
		const input = `const x = <p>Don't forget <KavachUser /></p>;\n`;
		expect(transformSource(input, "script").output).toBe(
			`const x = <p>Don't forget <TheAuthUser /></p>;\n`,
		);
	});
});

describe("transformSource: import paths and env", () => {
	it("rewrites old package names in import paths only", () => {
		const input = [
			'import { x } from "@kavachos/react";',
			'import "kavachos";',
			'const m = await import("@kavachos/core");',
			'const r = require("kavachos/server");',
			'const label = "@kavachos/react";',
			"",
		].join("\n");
		const result = transformSource(input, "script");
		expect(result.output).toBe(
			[
				'import { x } from "@glinr/theauth-react";',
				'import "@glinr/theauth";',
				'const m = await import("@glinr/theauth");',
				'const r = require("@glinr/theauth/server");',
				'const label = "@kavachos/react";',
				"",
			].join("\n"),
		);
	});

	it("rewrites KAVACH_ env names in process.env and import.meta.env", () => {
		const input = [
			"const a = process.env.KAVACH_SECRET;",
			'const b = process.env["KAVACH_URL"];',
			"const c = import.meta.env.KAVACH_MODE;",
			'const d = "KAVACH_SECRET";',
			"",
		].join("\n");
		const result = transformSource(input, "script");
		expect(result.output).toBe(
			[
				"const a = process.env.THEAUTH_SECRET;",
				'const b = process.env["THEAUTH_URL"];',
				"const c = import.meta.env.THEAUTH_MODE;",
				'const d = "KAVACH_SECRET";',
				"",
			].join("\n"),
		);
		expect(result.counts.get("env:KAVACH_SECRET")).toBe(1);
		const left = result.findings.map((f) => f.text);
		expect(left).toEqual(["KAVACH_SECRET"]);
	});

	it("rewrites bare KAVACH_ names in dotenv and markup kinds", () => {
		const env = transformSource("KAVACH_SECRET=abc\nexport KAVACH_URL=x\n", "dotenv");
		expect(env.output).toBe("THEAUTH_SECRET=abc\nexport THEAUTH_URL=x\n");
		const doc = transformSource("Set `KAVACH_SECRET` and call `createKavach()`.\n", "markup");
		expect(doc.output).toBe("Set `THEAUTH_SECRET` and call `createTheAuth()`.\n");
	});
});

describe("transformSource: Vue and Svelte", () => {
	it("handles script blocks with string protection and template markup", () => {
		const input = [
			'<script setup lang="ts">',
			'import { createKavachPlugin, type KavachUser } from "@kavachos/vue";',
			'const msg = "KavachUser";',
			"</script>",
			"<template>",
			'  <KavachDashboard :user="user" />',
			"</template>",
			"",
		].join("\n");
		const result = transformSource(input, "sfc");
		expect(result.output).toBe(
			[
				'<script setup lang="ts">',
				'import { createTheAuthPlugin, type TheAuthUser } from "@glinr/theauth-vue";',
				'const msg = "KavachUser";',
				"</script>",
				"<template>",
				'  <TheAuthDashboard :user="user" />',
				"</template>",
				"",
			].join("\n"),
		);
	});
});

describe("transformSource: reports", () => {
	it("reports a kavachos_notes variable in a comment instead of changing it", () => {
		const input = "// TODO: tidy kavachos_notes before release\nconst kavachos_notes = 1;\n";
		const result = transformSource(input, "script");
		expect(result.output).toBe(input);
		expect(result.findings).toEqual([
			{ line: 1, category: "unmapped", text: "kavachos_notes" },
			{ line: 2, category: "unmapped", text: "kavachos_notes" },
		]);
	});

	it("reports header and table names without editing them", () => {
		const input = 'const h = "X-Kavach-Signature";\nconst t = "kavach_users";\n';
		const result = transformSource(input, "script");
		expect(result.output).toBe(input);
		expect(result.findings).toEqual([
			{ line: 1, category: "header", text: "X-Kavach-Signature" },
			{ line: 2, category: "table", text: "kavach_users" },
		]);
	});

	it("reports unknown Kavach identifiers", () => {
		const result = transformSource("const x = KavachMystery();\n", "script");
		expect(result.findings).toEqual([{ line: 1, category: "unmapped", text: "KavachMystery" }]);
	});
});

describe("transformSource: idempotency", () => {
	it("produces no further changes on a second pass", () => {
		const input = [
			'import { createKavach } from "kavachos";',
			"const k = createKavach({ secret: process.env.KAVACH_SECRET });",
			"const c = `x ${KavachUser}`;",
			"",
		].join("\n");
		const first = transformSource(input, "script");
		const second = transformSource(first.output, "script");
		expect(second.output).toBe(first.output);
		expect(second.counts.size).toBe(0);
	});
});

describe("parseCodemodArgs", () => {
	it("parses flags and paths", () => {
		const parsed = parseCodemodArgs(["src", "--write", "--include-env", "app"]);
		expect(parsed).toEqual({
			paths: ["src", "app"],
			write: true,
			includeEnv: true,
			help: false,
			unknownFlag: null,
		});
		expect(parseCodemodArgs(["--bogus"]).unknownFlag).toBe("--bogus");
	});
});

describe("runRenameCodemod", () => {
	let dir = "";
	const sourcePath = () => join(dir, "src/app.ts");
	const original = 'import { createKavach } from "kavachos";\nexport const k = createKavach({});\n';

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "theauth-codemod-"));
		mkdirSync(join(dir, "src"));
		mkdirSync(join(dir, "node_modules/dep"), { recursive: true });
		writeFileSync(sourcePath(), original);
		writeFileSync(join(dir, "node_modules/dep/index.ts"), "export const KavachConfig = 1;\n");
		writeFileSync(join(dir, ".env"), "KAVACH_SECRET=abc\n");
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("writes nothing in dry-run mode", async () => {
		const result = await runRenameCodemod({ paths: [], write: false, includeEnv: true, cwd: dir });
		expect(readFileSync(sourcePath(), "utf8")).toBe(original);
		expect(readFileSync(join(dir, ".env"), "utf8")).toBe("KAVACH_SECRET=abc\n");
		expect(result.changed.sort()).toEqual([".env", "src/app.ts"]);
		expect(result.written).toBe(false);
		expect(formatSummary(result)).toContain("dry run, nothing written");
		expect(formatSummary(result)).toContain("Re-run with --write");
	});

	it("applies changes with write, skips node_modules, and is idempotent", async () => {
		const first = await runRenameCodemod({ paths: [], write: true, includeEnv: false, cwd: dir });
		expect(first.scanned).toBe(1);
		expect(first.changed).toEqual(["src/app.ts"]);
		expect(readFileSync(sourcePath(), "utf8")).toBe(
			'import { createTheAuth } from "@glinr/theauth";\nexport const k = createTheAuth({});\n',
		);
		expect(readFileSync(join(dir, ".env"), "utf8")).toBe("KAVACH_SECRET=abc\n");
		expect(readFileSync(join(dir, "node_modules/dep/index.ts"), "utf8")).toContain("KavachConfig");

		const second = await runRenameCodemod({ paths: [], write: true, includeEnv: false, cwd: dir });
		expect(second.changed).toEqual([]);
		expect(second.counts.size).toBe(0);
	});

	it("rewrites env files only with include-env and summarizes findings", async () => {
		writeFileSync(join(dir, "src/extra.ts"), 'const t = "kavach_agents"; // kavachos_notes\n');
		const result = await runRenameCodemod({
			paths: ["."],
			write: true,
			includeEnv: true,
			cwd: dir,
		});
		expect(readFileSync(join(dir, ".env"), "utf8")).toBe("THEAUTH_SECRET=abc\n");
		const summary = formatSummary(result);
		expect(summary).toContain("Files scanned: 3");
		expect(summary).toContain("createKavach: 2");
		expect(summary).toContain("src/extra.ts:1  kavach_agents");
		expect(summary).toContain("src/extra.ts:1  kavachos_notes");
	});
});
