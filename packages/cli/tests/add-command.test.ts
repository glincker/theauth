import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	createLoader,
	formatAdd,
	installCommand,
	listItems,
	parseAddArgs,
	runAdd,
} from "../src/add-command.js";

const REGISTRY = join(__dirname, "../../../registry");

function project(files: Record<string, string> = {}): string {
	const dir = mkdtempSync(join(tmpdir(), "theauth-add-"));
	for (const [name, content] of Object.entries(files)) {
		mkdirSync(join(dir, name, ".."), { recursive: true });
		writeFileSync(join(dir, name), content);
	}
	return dir;
}

describe("parseAddArgs", () => {
	it("collects names and flags", () => {
		expect(parseAddArgs(["sign-in", "--dir", "app/ui", "--overwrite", "--dry-run"])).toMatchObject({
			names: ["sign-in"],
			dir: "app/ui",
			overwrite: true,
			dryRun: true,
			error: null,
		});
		expect(parseAddArgs(["--list"]).list).toBe(true);
	});

	it("rejects an empty call and unknown flags", () => {
		expect(parseAddArgs([]).error).toMatch(/at least one component/i);
		expect(parseAddArgs(["--nope"]).error).toMatch(/Unknown option/);
	});
});

describe("theauth add", () => {
	it("lists the committed registry", () => {
		expect(listItems(REGISTRY)).toEqual([
			"forgot-password",
			"oauth-buttons",
			"sign-in",
			"sign-up",
			"theauth-base",
			"two-factor-verify",
			"user-button",
		]);
	});

	it("writes a component and its dependencies into src/components/theauth", async () => {
		const cwd = project({ "src/index.ts": "" });
		const result = await runAdd(parseAddArgs(["sign-in", "--registry", REGISTRY]), cwd);

		expect(result.targetDir).toBe("src/components/theauth");
		expect(result.written.sort()).toEqual(
			[
				"auth-card.tsx",
				"defaults.tsx",
				"oauth-buttons.tsx",
				"sign-in.tsx",
				"types.ts",
				"utils.ts",
			].map((f) => join("src/components/theauth", f)),
		);
		expect(result.dependencies).toEqual(["@glinr/theauth-react"]);
		const signIn = readFileSync(join(cwd, "src/components/theauth/sign-in.tsx"), "utf8");
		expect(signIn).toContain('from "./auth-card"');
		expect(signIn).not.toContain('.js"');
	});

	it("falls back to components/theauth and keeps existing files unless told to overwrite", async () => {
		const cwd = project({ "components/theauth/sign-in.tsx": "// mine" });
		const first = await runAdd(parseAddArgs(["sign-in", "--registry", REGISTRY]), cwd);
		expect(first.skipped).toEqual([join("components/theauth", "sign-in.tsx")]);
		expect(readFileSync(join(cwd, "components/theauth/sign-in.tsx"), "utf8")).toBe("// mine");

		const second = await runAdd(
			parseAddArgs(["sign-in", "--overwrite", "--registry", REGISTRY]),
			cwd,
		);
		expect(second.skipped).toEqual([]);
		expect(readFileSync(join(cwd, "components/theauth/sign-in.tsx"), "utf8")).not.toBe("// mine");
	});

	it("writes nothing on a dry run and refuses a target outside the project", async () => {
		const cwd = project();
		const dry = await runAdd(parseAddArgs(["sign-up", "--dry-run", "--registry", REGISTRY]), cwd);
		expect(dry.written.length).toBeGreaterThan(0);
		expect(existsSync(join(cwd, "components"))).toBe(false);

		await expect(
			runAdd(parseAddArgs(["sign-up", "--dir", "../elsewhere", "--registry", REGISTRY]), cwd),
		).rejects.toThrow(/inside the current project/);
	});

	it("reports an unknown component", async () => {
		await expect(
			runAdd(parseAddArgs(["nope", "--registry", REGISTRY]), project(), createLoader(REGISTRY)),
		).rejects.toThrow(/Unknown component "nope"/);
	});

	it("ignores directories smuggled into registry file paths", async () => {
		const cwd = project();
		const load = async () => ({
			name: "evil",
			files: [{ path: "../../../etc/passwd", type: "registry:lib", content: "x" }],
		});
		const out = await runAdd(parseAddArgs(["evil"]), cwd, load);
		expect(out.written).toEqual([join("components/theauth", "passwd")]);
	});

	it("picks the install command from the lockfile and prints a usable summary", async () => {
		expect(installCommand(project({ "pnpm-lock.yaml": "" }), ["a", "b"])).toBe("pnpm add a b");
		expect(installCommand(project(), ["a"])).toBe("npm install a");
		expect(installCommand(project(), [])).toBeNull();
		const cwd = project();
		const result = await runAdd(parseAddArgs(["user-button", "--registry", REGISTRY]), cwd);
		expect(formatAdd(result, cwd, false)).toContain("npm install @glinr/theauth-react");
	});
});

describe("registry drift", () => {
	it("matches what the UI source generates", async () => {
		// Committed registry/ must be rebuilt with `node scripts/build-registry.mjs` after UI changes.
		const { buildRegistry } = await import("../../../scripts/registry.mjs");
		const items = buildRegistry(join(__dirname, "../../ui/src")) as Array<{ name: string }>;
		for (const item of items) {
			const committed = JSON.parse(readFileSync(join(REGISTRY, `${item.name}.json`), "utf8"));
			expect(committed).toEqual(item);
		}
	});
});
