/** Fixtures for tests that run the MCP authorization server on the TheAuth database stores. */

import { createMcpModule } from "../src/mcp/server.js";
import type { McpAuthModule, McpConfig } from "../src/mcp/types.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import type { Harness } from "./mcp-test-harness.js";
import { BASE_URL, ISSUER, RESOURCE, SECRET } from "./mcp-test-harness.js";

export interface DbHarness {
	auth: TheAuth;
	userId: string;
	mcp: McpAuthModule;
	/** The same module shaped like the in-memory harness, so shared helpers such as `codeFlow` work. */
	h: Harness;
	/** A second module on the same database, like another instance. */
	another: () => McpAuthModule;
}

export function mcpConfig(extra: Partial<McpConfig> = {}): McpConfig {
	return {
		enabled: true,
		issuer: ISSUER,
		baseUrl: BASE_URL,
		signingSecret: SECRET,
		resource: RESOURCE,
		scopes: ["mcp:read", "mcp:write", "offline_access"],
		...extra,
	};
}

export async function bootDb(
	options: { url?: string; config?: Partial<McpConfig> } = {},
): Promise<DbHarness> {
	const auth = await createTheAuth({
		database: options.url
			? { provider: "sqlite-native", url: options.url }
			: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 20, auditAll: true, tokenExpiry: "24h" },
		mcp: mcpConfig(),
	});
	const user = await auth.user.create({ email: "owner@example.com" });
	return finishBoot(auth, user.id, options.config);
}

export function finishBoot(auth: TheAuth, userId: string, extra?: Partial<McpConfig>): DbHarness {
	const build = (): McpAuthModule =>
		createMcpModule({ auth, config: mcpConfig(extra), resolveUserId: async () => userId });
	const mcp = build();
	return {
		auth,
		userId,
		mcp,
		h: { mcp, clients: new Map(), codes: new Map(), tokens: new Map() },
		another: build,
	};
}
