import { basename, resolve } from "node:path";
import { exit } from "node:process";
import * as p from "@clack/prompts";
import { bold, green, yellow } from "kolorist";
import { scaffold } from "./scaffold.js";

type PackageManager = "pnpm" | "npm" | "yarn" | "bun";
type DbDriver = "better-sqlite3" | "pg";
type Template = "next-saas" | "hono-mcp" | "expo-mobile";

function detectPackageManager(): PackageManager {
	const ua = process.env.npm_config_user_agent ?? "";
	if (ua.startsWith("pnpm")) return "pnpm";
	if (ua.startsWith("yarn")) return "yarn";
	if (ua.startsWith("bun")) return "bun";
	return "npm";
}

function defaultDbUrl(driver: DbDriver): string {
	if (driver === "better-sqlite3") return "file:./kavach.db";
	return "";
}

function printBanner(): void {
	p.intro(`${bold(green("KavachOS"))} ${green("·")} Auth OS for AI agents`);
}

function printNextSteps(targetDir: string, pm: PackageManager, template: Template): void {
	const rel = targetDir.startsWith(process.cwd())
		? targetDir.slice(process.cwd().length + 1)
		: targetDir;
	const runCmd = pm === "npm" ? "npm run" : pm;
	const steps = [
		`cd ${rel}`,
		`${pm} install`,
		`cp .env.example .env   # then fill in KAVACHOS_SECRET`,
	];
	if (template === "next-saas") {
		steps.push(`${runCmd} db:push`);
	}
	steps.push(`${runCmd} dev`);
	p.note(steps.join("\n"), "Next steps");
	p.outro(`${bold(green("Done."))} Happy building.`);
}

export async function main(): Promise<void> {
	printBanner();

	const answers = await p.group(
		{
			targetDir: () =>
				p.text({
					message: "Project directory",
					placeholder: "./my-kavachos-app",
					defaultValue: "./my-kavachos-app",
					validate(value) {
						if (!value || value.trim() === "") return "Directory is required";
						return undefined;
					},
				}),

			template: () =>
				p.select<Template>({
					message: "Template",
					options: [
						{
							value: "next-saas",
							label: "Next.js SaaS",
							hint: "App Router · Drizzle · KavachOS auth",
						},
						{
							value: "hono-mcp",
							label: "Hono MCP",
							hint: "Hono server · MCP OAuth 2.1",
						},
						{
							value: "expo-mobile",
							label: `Expo mobile  ${yellow("(coming soon)")}`,
							hint: "React Native · Expo Router",
						},
					],
				}),

			packageManager: () =>
				p.select<PackageManager>({
					message: "Package manager",
					initialValue: detectPackageManager(),
					options: [
						{ value: "pnpm", label: "pnpm" },
						{ value: "npm", label: "npm" },
						{ value: "yarn", label: "yarn" },
						{ value: "bun", label: "bun" },
					],
				}),

			dbDriver: () =>
				p.select<DbDriver>({
					message: "Database",
					options: [
						{ value: "better-sqlite3", label: "SQLite", hint: "local · zero config" },
						{ value: "pg", label: "Postgres", hint: "pg driver · set DATABASE_URL" },
					],
				}),
		},
		{
			onCancel() {
				p.cancel("Cancelled.");
				exit(0);
			},
		},
	);

	const template = answers.template as Template;

	if (template === "expo-mobile") {
		p.note(
			`The ${bold(template)} template is not ready yet.\nPick ${bold("next-saas")} or ${bold("hono-mcp")} for now and stay tuned.`,
			yellow("Coming soon"),
		);
		exit(0);
	}

	const targetDir = resolve(answers.targetDir as string);
	const appName = basename(targetDir);
	const dbDriver = answers.dbDriver as DbDriver;
	const dbUrl = defaultDbUrl(dbDriver);
	const pm = answers.packageManager as PackageManager;

	const spinner = p.spinner();
	spinner.start("Scaffolding project");

	try {
		await scaffold({ targetDir, template, appName, dbDriver, dbUrl });
		spinner.stop("Project created");
	} catch (err) {
		spinner.stop("Scaffold failed");
		p.log.error(err instanceof Error ? err.message : String(err));
		exit(1);
	}

	printNextSteps(targetDir, pm, template);
}
