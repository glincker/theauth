import { spawnSync } from "node:child_process";

const checks = [
	{
		name: "core artifact smoke",
		command: [
			"pnpm",
			"--filter",
			"theauth",
			"exec",
			"vitest",
			"run",
			"tests/build-artifacts.test.ts",
		],
	},
	{
		name: "cli smoke",
		command: ["pnpm", "--filter", "@glinr/theauth-cli", "test"],
	},
	{
		name: "basic agent example smoke",
		command: ["pnpm", "--filter", "@glinr/theauth-example-basic-agent", "test"],
	},
	{
		name: "hono example smoke",
		command: ["pnpm", "--filter", "@glinr/theauth-example-hono-server", "test"],
	},
	{
		name: "mcp example smoke",
		command: ["pnpm", "--filter", "@glinr/theauth-example-mcp-server", "test"],
	},
	{
		name: "migrate-from-auth0 example smoke",
		command: ["pnpm", "--filter", "@glinr/theauth-example-migrate-from-auth0", "test"],
	},
	{
		name: "migrate-from-better-auth-agent-plugin example smoke",
		command: [
			"pnpm",
			"--filter",
			"@glinr/theauth-example-migrate-from-better-auth-agent-plugin",
			"test",
		],
	},
	{
		name: "dashboard e2e",
		command: ["pnpm", "--filter", "@glinr/theauth-dashboard", "test:e2e"],
	},
];

for (const check of checks) {
	process.stdout.write(`\n==> ${check.name}\n`);
	const result = spawnSync(check.command[0], check.command.slice(1), {
		stdio: "inherit",
		env: process.env,
	});

	if (result.status !== 0) {
		process.stderr.write(`\nOSS smoke failed during: ${check.name}\n`);
		process.exit(result.status ?? 1);
	}
}

process.stdout.write("\nOSS smoke passed.\n");
