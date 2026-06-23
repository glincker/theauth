import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";

// ── Types ────────────────────────────────────────────────────────────────────

type Framework = "hono" | "express" | "nextjs" | "fastify";
type Database = "sqlite" | "postgres";

interface InitAnswers {
	framework: Framework;
	database: Database;
	dbUrl: string;
}

interface InitResult {
	success: true;
	configPath: string;
	examplePath: string;
}

interface InitError {
	success: false;
	error: { code: string; message: string };
}

// ── Prompt helpers ────────────────────────────────────────────────────────────

function printMenu(title: string, options: string[]): void {
	stdout.write(`\n${title}\n`);
	options.forEach((opt, i) => {
		stdout.write(`  ${i + 1}. ${opt}\n`);
	});
}

async function pickOne(
	rl: Awaited<ReturnType<typeof createInterface>>,
	prompt: string,
	options: string[],
): Promise<number> {
	while (true) {
		const raw = await rl.question(`${prompt} [1-${options.length}]: `);
		const n = Number(raw.trim());
		if (Number.isInteger(n) && n >= 1 && n <= options.length) {
			return n - 1;
		}
		stdout.write(`  Please enter a number between 1 and ${options.length}.\n`);
	}
}

async function fileExists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}

// ── Template generators ───────────────────────────────────────────────────────

function configTemplate(answers: InitAnswers): string {
	const dbConfig =
		answers.database === "sqlite"
			? `  provider: "sqlite",\n  url: "${answers.dbUrl}",`
			: `  provider: "postgres",\n  url: process.env.DATABASE_URL ?? "${answers.dbUrl}",`;

	return `import { type KavachConfig } from "@glinr/theauth";

const config: KavachConfig = {
  database: {
${dbConfig}
  },
  agents: {
    maxPerUser: 10,
    tokenExpiry: "24h",
    auditAll: true,
  },
};

export default config;
`;
}

function exampleTemplate(answers: InitAnswers): string {
	const adapterPkg: Record<Framework, string> = {
		hono: "@glinr/theauth-hono",
		express: "@glinr/theauth-express",
		nextjs: "@glinr/theauth-nextjs",
		fastify: "@glinr/theauth-fastify",
	};

	const frameworkComment: Record<Framework, string> = {
		hono: "// Hono example — mount kavach middleware on your app",
		express: "// Express example — mount kavach middleware on your app",
		nextjs: "// Next.js example — use in API routes or middleware",
		fastify: "// Fastify example — register kavach as a plugin",
	};

	const dbSetup =
		answers.database === "sqlite"
			? `  database: { provider: "sqlite", url: "kavach.db" },`
			: `  database: { provider: "postgres", url: process.env.DATABASE_URL! },`;

	return `import { createKavach } from "@glinr/theauth";
${frameworkComment[answers.framework]}
// Adapter: npm install ${adapterPkg[answers.framework]}

// 1. Create the kavach instance (do this once at startup)
const kavach = await createKavach({
${dbSetup}
  agents: {
    maxPerUser: 10,
    tokenExpiry: "24h",
    auditAll: true,
  },
});

// 2. Create an agent for a user
const agent = await kavach.agent.create({
  ownerId: "user_123",
  name: "my-first-agent",
  type: "autonomous",
  permissions: [
    {
      resource: "documents",
      actions: ["read", "write"],
    },
  ],
});

console.log("Agent created:", agent.id);
console.log("Agent token:", agent.token); // store this securely

// 3. Authorize a request
const result = await kavach.authorize(agent.id, {
  action: "read",
  resource: "documents",
});

if (result.allowed) {
  console.log("Authorized — audit ID:", result.auditId);
} else {
  console.log("Denied:", result.reason);
}

// 4. Rotate a token when needed
const rotated = await kavach.agent.rotate(agent.id);
console.log("New token:", rotated.token);
`;
}

// ── Main init flow ────────────────────────────────────────────────────────────

export async function runInit(): Promise<InitResult | InitError> {
	stdout.write("\nTheAuth — project setup\n");
	stdout.write("─────────────────────────────────────\n");

	const rl = createInterface({ input: stdin, output: stdout });

	try {
		// Framework
		const frameworks: Framework[] = ["hono", "express", "nextjs", "fastify"];
		const frameworkLabels = ["Hono", "Express", "Next.js", "Fastify"];
		printMenu("Which framework are you using?", frameworkLabels);
		const fwIdx = await pickOne(rl, "Framework", frameworkLabels);
		const framework = frameworks[fwIdx] as Framework;

		// Database
		const databases: Database[] = ["sqlite", "postgres"];
		const dbLabels = ["SQLite (local file, no setup needed)", "PostgreSQL"];
		printMenu("Which database?", dbLabels);
		const dbIdx = await pickOne(rl, "Database", dbLabels);
		const database = databases[dbIdx] as Database;

		// Database URL
		let dbUrlDefault: string;
		let dbUrlPrompt: string;
		if (database === "sqlite") {
			dbUrlDefault = "kavach.db";
			dbUrlPrompt = `SQLite file path [${dbUrlDefault}]: `;
		} else {
			dbUrlDefault = "postgresql://localhost:5432/kavach";
			dbUrlPrompt = `PostgreSQL connection URL [${dbUrlDefault}]: `;
		}

		stdout.write("\n");
		const rawDbUrl = await rl.question(dbUrlPrompt);
		const dbUrl = rawDbUrl.trim() !== "" ? rawDbUrl.trim() : dbUrlDefault;

		const answers: InitAnswers = { framework, database, dbUrl };

		// Write files
		const cwd = process.cwd();
		const configPath = join(cwd, "kavach.config.ts");
		const examplePath = join(cwd, "kavach.example.ts");

		// Warn if files already exist
		const [configExists, exampleExists] = await Promise.all([
			fileExists(configPath),
			fileExists(examplePath),
		]);

		if (configExists || exampleExists) {
			stdout.write("\nThe following files already exist:\n");
			if (configExists) stdout.write(`  kavach.config.ts\n`);
			if (exampleExists) stdout.write(`  kavach.example.ts\n`);
			const overwrite = await rl.question("Overwrite? [y/N]: ");
			if (overwrite.trim().toLowerCase() !== "y") {
				rl.close();
				return {
					success: false,
					error: { code: "ABORTED", message: "Setup cancelled by user." },
				};
			}
		}

		await Promise.all([
			writeFile(configPath, configTemplate(answers), "utf8"),
			writeFile(examplePath, exampleTemplate(answers), "utf8"),
		]);

		rl.close();

		// Print next steps
		stdout.write("\n  Files written\n");
		stdout.write(`  kavach.config.ts   — your TheAuth configuration\n`);
		stdout.write(`  kavach.example.ts  — minimal agent + authorization example\n`);

		stdout.write("\nNext steps\n");
		stdout.write("──────────\n");
		stdout.write("  1. Install the core package:\n");
		stdout.write("       npm install @glinr/theauth\n");
		if (framework !== "hono") {
			const adapterPkg: Record<Exclude<Framework, "hono">, string> = {
				express: "@glinr/theauth-express",
				nextjs: "@glinr/theauth-nextjs",
				fastify: "@glinr/theauth-fastify",
			};
			stdout.write(`       npm install ${adapterPkg[framework]}\n`);
		} else {
			stdout.write("       npm install @glinr/@glinr/theauth-hono\n");
		}
		if (database === "postgres") {
			stdout.write("       npm install pg\n");
		}
		stdout.write("  2. Set DATABASE_URL in your environment (if using Postgres).\n");
		stdout.write("  3. Run your app — TheAuth creates tables automatically on first start.\n");
		stdout.write(
			"  4. Open kavach.example.ts to see how to create agents and authorize requests.\n",
		);
		stdout.write("\n  Docs: https://theauth.dev/docs\n\n");

		return { success: true, configPath, examplePath };
	} catch (err: unknown) {
		rl.close();
		return {
			success: false,
			error: {
				code: "INIT_FAILED",
				message: err instanceof Error ? err.message : String(err),
			},
		};
	}
}
