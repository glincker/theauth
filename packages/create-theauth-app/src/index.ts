import { spawnSync } from "node:child_process";
import { basename, resolve } from "node:path";
import { argv, exit } from "node:process";
import * as p from "@clack/prompts";
import { bold, green, yellow } from "kolorist";
import { HELP, parseArgs } from "./args.js";
import { scaffold } from "./scaffold.js";

type PackageManager = "pnpm" | "npm" | "yarn" | "bun";
type DbDriver = "sql.js" | "pg";
type Template = "first-run" | "next-saas" | "hono-mcp" | "expo-mobile";

function detectPackageManager(): PackageManager {
	const ua = process.env.npm_config_user_agent ?? "";
	if (ua.startsWith("pnpm")) return "pnpm";
	if (ua.startsWith("yarn")) return "yarn";
	if (ua.startsWith("bun")) return "bun";
	return "npm";
}

function defaultDbUrl(driver: DbDriver): string {
	if (driver === "sql.js") return "./theauth.db";
	return "";
}

function printBanner(): void {
	p.intro(`${bold(green("TheAuth"))} ${green("·")} Auth OS for AI agents`);
}

function installDependencies(targetDir: string, pm: PackageManager): boolean {
	const result = spawnSync(pm, ["install"], { cwd: targetDir, stdio: "inherit" });
	return result.status === 0;
}

function printNextSteps(
	targetDir: string,
	pm: PackageManager,
	template: Template,
	installed: boolean,
): void {
	const rel = targetDir.startsWith(process.cwd())
		? targetDir.slice(process.cwd().length + 1)
		: targetDir;
	const runCmd = pm === "npm" ? "npm run" : pm;
	if (template === "first-run") {
		const steps = [`cd ${rel}`];
		if (!installed) steps.push(`${pm} install`);
		steps.push(`${pm} start   # prints the agent token and the curl commands to try`);
		p.note(steps.join("\n"), "Next steps");
		p.outro(`${bold(green("Done."))} The server runs in memory, nothing to configure.`);
		return;
	}
	const steps = [`cd ${rel}`];
	if (!installed) steps.push(`${pm} install`);
	steps.push(`cp .env.example .env   # then fill in THEAUTH_SECRET`);
	if (template === "next-saas") {
		steps.push(`${runCmd} db:push`);
	}
	steps.push(`${runCmd} dev`);
	p.note(steps.join("\n"), "Next steps");
	p.outro(`${bold(green("Done."))} Happy building.`);
}

interface Answers {
	targetDir: string;
	template: Template;
	packageManager: PackageManager;
	dbDriver: DbDriver;
}

async function promptAnswers(args: ReturnType<typeof parseArgs>): Promise<Answers> {
	const onCancel = () => {
		p.cancel("Cancelled.");
		exit(0);
	};
	const template = args.template ?? "first-run";

	if (args.yes) {
		return {
			targetDir: args.dir ?? "./my-theauth-app",
			template,
			packageManager: detectPackageManager(),
			dbDriver: "sql.js",
		};
	}

	const answers = await p.group(
		{
			targetDir: () =>
				args.dir !== null
					? Promise.resolve(args.dir)
					: p.text({
							message: "Project directory",
							placeholder: "./my-theauth-app",
							defaultValue: "./my-theauth-app",
							validate(value) {
								if (!value || value.trim() === "") return "Directory is required";
								return undefined;
							},
						}),

			template: () =>
				args.template !== null
					? Promise.resolve<Template>(args.template)
					: p.select<Template>({
							message: "Template",
							initialValue: "first-run",
							options: [
								{
									value: "first-run",
									label: "First run",
									hint: "one agent, one allowed call, one denied call, audit log",
								},
								{
									value: "next-saas",
									label: "Next.js SaaS",
									hint: "App Router · Drizzle · TheAuth auth",
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

			// The first-run template keeps everything in memory and has no driver.
			dbDriver: ({ results }) =>
				results.template === "first-run"
					? Promise.resolve<DbDriver>("sql.js")
					: p.select<DbDriver>({
							message: "Database",
							options: [
								{ value: "sql.js", label: "SQLite", hint: "local · zero config" },
								{ value: "pg", label: "Postgres", hint: "pg driver · set DATABASE_URL" },
							],
						}),
		},
		{ onCancel },
	);

	return {
		targetDir: answers.targetDir as string,
		template: answers.template as Template,
		packageManager: answers.packageManager as PackageManager,
		dbDriver: answers.dbDriver as DbDriver,
	};
}

export async function main(): Promise<void> {
	const args = parseArgs(argv.slice(2));
	if (args.help) {
		process.stdout.write(HELP);
		return;
	}
	if (args.error !== null) {
		process.stderr.write(`${args.error}\n\n${HELP}`);
		exit(1);
	}

	printBanner();
	const answers = await promptAnswers(args);
	const { template } = answers;

	if (template === "expo-mobile") {
		p.note(
			`The ${bold(template)} template is not ready yet.\nPick ${bold("first-run")}, ${bold("next-saas")} or ${bold("hono-mcp")} for now and stay tuned.`,
			yellow("Coming soon"),
		);
		exit(0);
	}

	const targetDir = resolve(answers.targetDir);
	const appName = basename(targetDir);
	const { dbDriver, packageManager: pm } = answers;
	const dbUrl = defaultDbUrl(dbDriver);

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

	let installed = false;
	if (args.install) {
		p.log.step(`Running ${pm} install`);
		installed = installDependencies(targetDir, pm);
		if (!installed) p.log.warn(`${pm} install failed. Run it yourself in the project directory.`);
	}

	printNextSteps(targetDir, pm, template, installed);
}
