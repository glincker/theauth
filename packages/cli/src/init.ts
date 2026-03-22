import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { stdout } from "node:process";

// ── Types ────────────────────────────────────────────────────────────────────

type Framework = "hono" | "express" | "nextjs" | "fastify";
type DbChoice = "sqlite" | "postgres" | "mysql";

interface InitAnswers {
	framework: Framework;
	database: DbChoice;
}

interface InitResult {
	success: true;
	files: string[];
}

interface InitError {
	success: false;
	error: { code: string; message: string };
}

// ── Simple stdin readline ─────────────────────────────────────────────────────

function ask(question: string): Promise<string> {
	process.stdout.write(question);
	return new Promise((resolve) => {
		let data = "";
		process.stdin.setEncoding("utf-8");
		const onData = (chunk: string) => {
			data += chunk;
			if (data.includes("\n")) {
				process.stdin.removeListener("data", onData);
				resolve(data.trim());
			}
		};
		process.stdin.on("data", onData);
		process.stdin.resume();
	});
}

function printMenu(title: string, options: string[]): void {
	stdout.write(`\n${title}\n`);
	for (let i = 0; i < options.length; i++) {
		stdout.write(`  ${i + 1}. ${options[i]}\n`);
	}
}

async function pickOne(prompt: string, count: number): Promise<number> {
	while (true) {
		const raw = await ask(`${prompt} [1-${count}]: `);
		const n = Number(raw.trim());
		if (Number.isInteger(n) && n >= 1 && n <= count) {
			return n - 1;
		}
		stdout.write(`  Please enter a number between 1 and ${count}.\n`);
	}
}

// ── Template generators ───────────────────────────────────────────────────────

function dbUrlPlaceholder(db: DbChoice): string {
	if (db === "sqlite") return "file:./kavach.db";
	if (db === "postgres") return "postgresql://localhost:5432/kavach";
	return "mysql://root:password@localhost:3306/kavach";
}

function envExampleTemplate(db: DbChoice): string {
	const dbUrl = dbUrlPlaceholder(db);
	return `# KavachOS environment variables
DATABASE_URL="${dbUrl}"
KAVACH_SECRET="change-me-use-a-long-random-string"
`;
}

function dbConfigSnippet(db: DbChoice): string {
	if (db === "sqlite") {
		return `    database: {
    provider: "sqlite",
    url: process.env.DATABASE_URL ?? "file:./kavach.db",
  },`;
	}
	if (db === "postgres") {
		return `    database: {
    provider: "postgres",
    url: process.env.DATABASE_URL!,
  },`;
	}
	return `    database: {
    provider: "mysql",
    url: process.env.DATABASE_URL!,
  },`;
}

function honoKavachTs(db: DbChoice): string {
	return `import { createKavach } from "kavachos";
import { kavachHono } from "@kavachos/hono";
import { Hono } from "hono";

export const kavach = await createKavach({
${dbConfigSnippet(db)}
  secret: process.env.KAVACH_SECRET,
  agents: {
    maxPerUser: 10,
    tokenExpiry: "24h",
    auditAll: true,
  },
});

export const app = new Hono();

// Mount KavachOS auth routes at /auth
app.route("/auth", kavachHono(kavach));

// Protect a route
app.get("/api/protected", async (c) => {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return c.json({ error: "Unauthorized" }, 401);

  const result = await kavach.authorizeByToken(token, {
    action: "read",
    resource: "api",
  });

  if (!result.allowed) return c.json({ error: result.reason }, 403);
  return c.json({ message: "OK", auditId: result.auditId });
});
`;
}

function expressKavachTs(db: DbChoice): string {
	return `import express from "express";
import { createKavach } from "kavachos";
import { kavachExpress } from "@kavachos/express";

export const kavach = await createKavach({
${dbConfigSnippet(db)}
  secret: process.env.KAVACH_SECRET,
  agents: {
    maxPerUser: 10,
    tokenExpiry: "24h",
    auditAll: true,
  },
});

export const app = express();

app.use(express.json());

// Mount KavachOS auth routes at /auth
app.use("/auth", kavachExpress(kavach));

// Protect a route
app.get("/api/protected", async (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const result = await kavach.authorizeByToken(token, {
    action: "read",
    resource: "api",
  });

  if (!result.allowed) return res.status(403).json({ error: result.reason });
  return res.json({ message: "OK", auditId: result.auditId });
});
`;
}

function nextjsRouteTs(_db: DbChoice): string {
	return `import { kavach } from "@/lib/kavach";
import { NextRequest, NextResponse } from "next/server";

// Catch-all handler for KavachOS auth routes
// Handles: /api/kavach/authorize, /api/kavach/agents, etc.
export async function GET(req: NextRequest) {
  return handleKavach(req);
}

export async function POST(req: NextRequest) {
  return handleKavach(req);
}

export async function DELETE(req: NextRequest) {
  return handleKavach(req);
}

async function handleKavach(req: NextRequest): Promise<NextResponse> {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const result = await kavach.authorizeByToken(token, {
    action: "read",
    resource: "api",
  });

  if (!result.allowed) {
    return NextResponse.json({ error: result.reason }, { status: 403 });
  }

  return NextResponse.json({ message: "OK", auditId: result.auditId });
}
`;
}

function nextjsLibKavachTs(db: DbChoice): string {
	return `import { createKavach } from "kavachos";

// Singleton — Next.js can hot-reload modules; globalThis prevents re-init
const globalKavach = globalThis as typeof globalThis & {
  _kavach?: Awaited<ReturnType<typeof createKavach>>;
};

if (!globalKavach._kavach) {
  globalKavach._kavach = await createKavach({
${dbConfigSnippet(db)}
    secret: process.env.KAVACH_SECRET,
    agents: {
      maxPerUser: 10,
      tokenExpiry: "24h",
      auditAll: true,
    },
  });
}

export const kavach = globalKavach._kavach;
`;
}

function fastifyKavachTs(db: DbChoice): string {
	return `import Fastify from "fastify";
import { createKavach } from "kavachos";
import { kavachFastify } from "@kavachos/fastify";

export const kavach = await createKavach({
${dbConfigSnippet(db)}
  secret: process.env.KAVACH_SECRET,
  agents: {
    maxPerUser: 10,
    tokenExpiry: "24h",
    auditAll: true,
  },
});

export const app = Fastify({ logger: true });

// Register KavachOS as a Fastify plugin
await app.register(kavachFastify, { kavach, prefix: "/auth" });

// Protect a route
app.get("/api/protected", async (request, reply) => {
  const token = request.headers.authorization?.replace("Bearer ", "");
  if (!token) return reply.status(401).send({ error: "Unauthorized" });

  const result = await kavach.authorizeByToken(token, {
    action: "read",
    resource: "api",
  });

  if (!result.allowed) return reply.status(403).send({ error: result.reason });
  return { message: "OK", auditId: result.auditId };
});
`;
}

function installCommand(framework: Framework, db: DbChoice): string {
	const dbPkg = db === "sqlite" ? "better-sqlite3" : db === "postgres" ? "pg" : "mysql2";

	const frameworkPkgs: Record<Framework, string> = {
		hono: "hono @hono/node-server @kavachos/hono",
		express: "express @kavachos/express",
		nextjs: "@kavachos/nextjs",
		fastify: "fastify @kavachos/fastify",
	};

	return `pnpm add kavachos ${frameworkPkgs[framework]} ${dbPkg}`;
}

// ── File sets per framework ───────────────────────────────────────────────────

interface ScaffoldFile {
	path: string;
	content: string;
}

function buildFiles(answers: InitAnswers): ScaffoldFile[] {
	const { framework, database } = answers;
	const envFile: ScaffoldFile = {
		path: ".env.example",
		content: envExampleTemplate(database),
	};

	switch (framework) {
		case "hono":
			return [{ path: "kavach.ts", content: honoKavachTs(database) }, envFile];
		case "express":
			return [{ path: "kavach.ts", content: expressKavachTs(database) }, envFile];
		case "nextjs":
			return [
				{
					path: join("app", "api", "kavach", "[...path]", "route.ts"),
					content: nextjsRouteTs(database),
				},
				{ path: join("lib", "kavach.ts"), content: nextjsLibKavachTs(database) },
				envFile,
			];
		case "fastify":
			return [{ path: "kavach.ts", content: fastifyKavachTs(database) }, envFile];
	}
}

// ── Main init flow ────────────────────────────────────────────────────────────

export async function runInit(): Promise<InitResult | InitError> {
	stdout.write("\nKavachOS — project setup\n");
	stdout.write("─────────────────────────────────────\n");

	try {
		// Framework
		const frameworkKeys: Framework[] = ["hono", "express", "nextjs", "fastify"];
		const frameworkLabels = ["Hono", "Express", "Next.js", "Fastify"];
		printMenu("Which framework are you using?", frameworkLabels);
		const fwIdx = await pickOne("Framework", frameworkLabels.length);
		const framework = frameworkKeys[fwIdx] as Framework;

		// Database
		const dbKeys: DbChoice[] = ["sqlite", "postgres", "mysql"];
		const dbLabels = ["SQLite (local file, no setup needed)", "PostgreSQL", "MySQL"];
		printMenu("Which database?", dbLabels);
		const dbIdx = await pickOne("Database", dbLabels.length);
		const database = dbKeys[dbIdx] as DbChoice;

		const answers: InitAnswers = { framework, database };
		const files = buildFiles(answers);
		const cwd = process.cwd();

		// Write all files
		const written: string[] = [];
		for (const file of files) {
			const fullPath = join(cwd, file.path);
			const dir = dirname(fullPath);
			await mkdir(dir, { recursive: true });
			await writeFile(fullPath, file.content, "utf8");
			written.push(file.path);
		}

		// Summary
		stdout.write("\n  Files created\n");
		for (const f of written) {
			stdout.write(`  ${f}\n`);
		}

		stdout.write("\nNext steps\n");
		stdout.write("──────────\n");
		stdout.write(`  1. Install packages:\n`);
		stdout.write(`       ${installCommand(framework, database)}\n`);
		if (database !== "sqlite") {
			stdout.write(`  2. Set DATABASE_URL in .env (see .env.example).\n`);
			stdout.write(`  3. Run your app — KavachOS creates tables automatically on first start.\n`);
		} else {
			stdout.write(`  2. Run your app — KavachOS creates the SQLite file automatically.\n`);
		}
		stdout.write("\n  Docs: https://kavachos.com/docs\n\n");

		// Pause stdin so the process can exit cleanly
		process.stdin.pause();

		return { success: true, files: written };
	} catch (err: unknown) {
		process.stdin.pause();
		return {
			success: false,
			error: {
				code: "INIT_FAILED",
				message: err instanceof Error ? err.message : String(err),
			},
		};
	}
}
