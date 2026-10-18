/** Pure generators for the files `theauth init` writes. No dashes in any generated text. */

export type Framework = "hono" | "express" | "nextjs" | "fastify" | "sveltekit" | "nuxt";
export type Database = "sqlite" | "postgres" | "mysql";
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export const FRAMEWORKS: readonly Framework[] = [
	"hono",
	"express",
	"nextjs",
	"fastify",
	"sveltekit",
	"nuxt",
];
export const DATABASES: readonly Database[] = ["sqlite", "postgres", "mysql"];

export const MOUNT_PATH = "/api/theauth";

export const ADAPTER_PACKAGE: Record<Framework, string> = {
	hono: "@glinr/theauth-hono",
	express: "@glinr/theauth-express",
	nextjs: "@glinr/theauth-nextjs",
	fastify: "@glinr/theauth-fastify",
	sveltekit: "@glinr/theauth-sveltekit",
	nuxt: "@glinr/theauth-nuxt",
};

export const DB_DRIVER: Record<Database, string> = {
	sqlite: "better-sqlite3",
	postgres: "pg",
	mysql: "mysql2",
};

export const DB_URL_DEFAULT: Record<Database, string> = {
	sqlite: "./theauth.db",
	postgres: "postgres://localhost:5432/theauth",
	mysql: "mysql://root@localhost:3306/theauth",
};

/** Frameworks where init writes a standalone server file that listens on a port. */
export const SERVER_FRAMEWORKS: readonly Framework[] = ["hono", "express", "fastify"];

export function defaultPort(framework: Framework): number {
	return framework === "sveltekit" ? 5173 : 3000;
}

function envRead(framework: Framework, name: string): string {
	return framework === "sveltekit" ? `env["${name}"]` : `process.env["${name}"]`;
}

/** `src/theauth.ts`: the one TheAuth instance, created lazily, plus the admin key resolver. */
export function instanceFile(framework: Framework, database: Database): string {
	const sveltekit = framework === "sveltekit";
	const provider = database === "sqlite" ? "sqlite-native" : database;
	return `${sveltekit ? 'import { env } from "$env/dynamic/private";\n' : ""}import { createHash, timingSafeEqual } from "node:crypto";
import type { TheAuth } from "@glinr/theauth";
import { createTheAuth } from "@glinr/theauth";

let instance: Promise<TheAuth> | null = null;

/** The TheAuth instance. Created on first use so importing this file opens no connection. */
export function getTheAuth(): Promise<TheAuth> {
	instance ??= createTheAuth({
		// SQLite is a file on disk, so data survives restarts. Change DATABASE_URL to move.
		database: {
			provider: "${provider}",
			url: ${envRead(framework, "DATABASE_URL")} ?? "${DB_URL_DEFAULT[database]}",
		},
		secret: ${envRead(framework, "THEAUTH_SECRET")},
		agents: { maxPerUser: 10, tokenExpiry: "24h", auditAll: true },
	});
	return instance;
}

function digest(value: string): Uint8Array {
	return createHash("sha256").update(value).digest();
}

/**
 * Who may call the management routes (agents, delegations, audit).
 * Callers send "Authorization: Bearer <ADMIN_API_KEY>". Without the key every call gets a 401.
 * Replace this with your own session or SSO check before you expose the server.
 */
export async function authenticateAdmin(request: Request): Promise<{ id: string } | null> {
	const key = ${envRead(framework, "ADMIN_API_KEY")};
	if (!key) return null;
	const header = request.headers.get("authorization");
	if (!header?.startsWith("Bearer ")) return null;
	return timingSafeEqual(digest(header.slice("Bearer ".length)), digest(key))
		? { id: "owner" }
		: null;
}
`;
}

/** `src/seed.ts`: creates the owner user, then a demo agent for that owner. Safe to run twice. */
export function seedFile(framework: Framework): string {
	const ext =
		framework === "nextjs" || framework === "nuxt" || framework === "sveltekit" ? "" : ".js";
	return `import type { TheAuth } from "@glinr/theauth";
import { getTheAuth } from "./theauth${ext}";

const OWNER_EMAIL = process.env["OWNER_EMAIL"] ?? "owner@example.com";
const DEMO_AGENT = "demo-agent";

/** Create the owner user first (agents reference it by foreign key), then one demo agent. */
export async function seedDemo(auth: TheAuth): Promise<void> {
	const owner = await auth.user.create({ email: OWNER_EMAIL, name: "Owner" });
	console.log(\`Owner user: \${owner.email} (\${owner.id})\`);

	const existing = await auth.agent.list({ userId: owner.id });
	if (existing.some((agent) => agent.name === DEMO_AGENT)) {
		console.log(\`Demo agent "\${DEMO_AGENT}" already exists, nothing to do.\`);
		return;
	}

	const agent = await auth.agent.create({
		ownerId: owner.id,
		name: DEMO_AGENT,
		type: "autonomous",
		permissions: [{ resource: "documents", actions: ["read", "write"] }],
	});
	console.log(\`Demo agent created: \${agent.id}\`);
	console.log(\`Agent token (shown once, store it safely): \${agent.token}\`);
}

// Run directly: npx tsx --env-file=.env src/seed.ts
if (/seed.[cm]?[jt]s$/.test(process.argv[1] ?? "")) {
	getTheAuth()
		.then(seedDemo)
		.catch((error: unknown) => {
			console.error("Seeding failed:", error);
			process.exit(1);
		});
}
`;
}

function serverHono(): string {
	return `import { serve } from "@hono/node-server";
import { theAuthHono } from "@glinr/theauth-hono";
import { Hono } from "hono";
import { seedDemo } from "./seed.js";
import { authenticateAdmin, getTheAuth } from "./theauth.js";

const port = Number(process.env["PORT"] ?? 3000);

async function main(): Promise<void> {
	const auth = await getTheAuth();
	await seedDemo(auth);

	const app = new Hono();
	app.get("/health", (c) => c.json({ status: "ok" }));
	// Every TheAuth route lives under ${MOUNT_PATH}.
	app.route("${MOUNT_PATH}", theAuthHono(auth, { authenticate: authenticateAdmin }));

	serve({ fetch: app.fetch, port }, (info) => {
		console.log(\`Listening on http://localhost:\${info.port}\`);
	});
}

main().catch((error: unknown) => {
	console.error("Startup failed:", error);
	process.exit(1);
});
`;
}

function serverExpress(): string {
	return `import { theAuthExpress } from "@glinr/theauth-express";
import express from "express";
import { seedDemo } from "./seed.js";
import { authenticateAdmin, getTheAuth } from "./theauth.js";

const port = Number(process.env["PORT"] ?? 3000);

async function main(): Promise<void> {
	const auth = await getTheAuth();
	await seedDemo(auth);

	const app = express();
	app.get("/health", (_req, res) => {
		res.json({ status: "ok" });
	});
	// Every TheAuth route lives under ${MOUNT_PATH}.
	app.use("${MOUNT_PATH}", theAuthExpress(auth, { authenticate: authenticateAdmin }));

	app.listen(port, () => {
		console.log(\`Listening on http://localhost:\${port}\`);
	});
}

main().catch((error: unknown) => {
	console.error("Startup failed:", error);
	process.exit(1);
});
`;
}

function serverFastify(): string {
	return `import { theAuthFastify } from "@glinr/theauth-fastify";
import Fastify from "fastify";
import { seedDemo } from "./seed.js";
import { authenticateAdmin, getTheAuth } from "./theauth.js";

const port = Number(process.env["PORT"] ?? 3000);

async function main(): Promise<void> {
	const auth = await getTheAuth();
	await seedDemo(auth);

	const app = Fastify();
	app.get("/health", async () => ({ status: "ok" }));
	// Every TheAuth route lives under ${MOUNT_PATH}.
	await app.register(theAuthFastify(auth, { authenticate: authenticateAdmin }), {
		prefix: "${MOUNT_PATH}",
	});

	await app.listen({ port });
	console.log(\`Listening on http://localhost:\${port}\`);
}

main().catch((error: unknown) => {
	console.error("Startup failed:", error);
	process.exit(1);
});
`;
}

/** Relative import specifier from a mount file to `src/theauth` (no extension, bundlers resolve it). */
function nextjsRoute(importPath: string): string {
	return `import { theAuthNextjs } from "@glinr/theauth-nextjs";
import { authenticateAdmin, getTheAuth } from "${importPath}";

export const runtime = "nodejs";

type Handlers = ReturnType<typeof theAuthNextjs>;
let handlers: Promise<Handlers> | null = null;

// Built on the first request so \`next build\` never opens the database.
function load(): Promise<Handlers> {
	handlers ??= getTheAuth().then((auth) => theAuthNextjs(auth, { authenticate: authenticateAdmin }));
	return handlers;
}

export const GET = async (request: Request) => (await load()).GET(request);
export const POST = async (request: Request) => (await load()).POST(request);
export const PATCH = async (request: Request) => (await load()).PATCH(request);
export const DELETE = async (request: Request) => (await load()).DELETE(request);
export const OPTIONS = async (request: Request) => (await load()).OPTIONS(request);
`;
}

function sveltekitRoute(importPath: string): string {
	return `import { theAuthSvelteKit } from "@glinr/theauth-sveltekit";
import type { RequestHandler } from "@sveltejs/kit";
import { authenticateAdmin, getTheAuth } from "${importPath}";

type Handlers = ReturnType<typeof theAuthSvelteKit>;
let handlers: Promise<Handlers> | null = null;

function load(): Promise<Handlers> {
	handlers ??= getTheAuth().then((auth) => theAuthSvelteKit(auth, { authenticate: authenticateAdmin }));
	return handlers;
}

// One handler serves every method: the TheAuth router picks the route from the request.
const handle: RequestHandler = async (event) => (await load()).GET(event);

export const GET = handle;
export const POST = handle;
export const PATCH = handle;
export const DELETE = handle;
export const OPTIONS = handle;
`;
}

function nuxtRoute(importPath: string): string {
	return `import { theAuthNuxt } from "@glinr/theauth-nuxt";
import { defineEventHandler } from "h3";
import { authenticateAdmin, getTheAuth } from "${importPath}";

type Handler = ReturnType<typeof theAuthNuxt>;
let handler: Promise<Handler> | null = null;

export default defineEventHandler(async (event) => {
	handler ??= getTheAuth().then((auth) => theAuthNuxt(auth, { authenticate: authenticateAdmin }));
	return (await handler)(event);
});
`;
}

export interface MountFile {
	/** Path relative to the project directory. */
	path: string;
	content: string;
}

/** The framework mount file. `importPath` is how it reaches `src/theauth`. */
export function mountFile(
	framework: Framework,
	opts: { srcDir: boolean; importPath: string },
): MountFile {
	switch (framework) {
		case "hono":
			return { path: "src/server.ts", content: serverHono() };
		case "express":
			return { path: "src/server.ts", content: serverExpress() };
		case "fastify":
			return { path: "src/server.ts", content: serverFastify() };
		case "nextjs":
			return {
				path: `${opts.srcDir ? "src/" : ""}app/api/theauth/[...theauth]/route.ts`,
				content: nextjsRoute(opts.importPath),
			};
		case "sveltekit":
			return {
				path: "src/routes/api/theauth/[...path]/+server.ts",
				content: sveltekitRoute(opts.importPath),
			};
		case "nuxt":
			return { path: "server/api/theauth/[...path].ts", content: nuxtRoute(opts.importPath) };
	}
}

export function envExample(database: Database, port: number): string {
	return `# Long random string that signs tokens. Generate: theauth secret --env THEAUTH_SECRET
THEAUTH_SECRET=

# Bearer key for the management routes. Generate: theauth secret --env ADMIN_API_KEY
ADMIN_API_KEY=

# SQLite is a file on disk. For Postgres or MySQL use a connection URL.
DATABASE_URL=${DB_URL_DEFAULT[database]}

# Email of the user who owns the demo agent (src/seed.ts).
OWNER_EMAIL=owner@example.com

PORT=${port}
`;
}

export function envFile(
	database: Database,
	port: number,
	secret: string,
	adminKey: string,
): string {
	return envExample(database, port)
		.replace("THEAUTH_SECRET=\n", `THEAUTH_SECRET=${secret}\n`)
		.replace("ADMIN_API_KEY=\n", `ADMIN_API_KEY=${adminKey}\n`);
}

/** Lines init appends to .gitignore when they are missing. */
export const GITIGNORE_LINES = [".env", ".env.local", "*.db"];

export function packageManagerCommands(pm: PackageManager): {
	add: string;
	addDev: string;
	exec: string;
} {
	switch (pm) {
		case "pnpm":
			return { add: "pnpm add", addDev: "pnpm add -D", exec: "pnpm exec" };
		case "yarn":
			return { add: "yarn add", addDev: "yarn add -D", exec: "yarn" };
		case "bun":
			return { add: "bun add", addDev: "bun add -d", exec: "bunx" };
		default:
			return { add: "npm install", addDev: "npm install -D", exec: "npx" };
	}
}

/** Extra runtime packages the mount file needs besides core and the adapter. */
export function extraPackages(framework: Framework): string[] {
	if (framework === "hono") return ["hono", "@hono/node-server", "zod"];
	if (framework === "express") return ["express", "zod"];
	if (framework === "fastify") return ["fastify", "zod"];
	return ["zod"];
}
