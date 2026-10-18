import { describe, expectTypeOf, it } from "vitest";
import type {
	McpBindingStore,
	McpBindingVerdict,
	McpDelegationBinding,
	McpFreshnessMode,
	McpInactiveReason,
	McpIntrospectionConfig,
	McpIntrospectionResponse,
	McpRevocationBus,
	McpRevocationConfig,
	McpRevocationEvent,
	McpRevocationHit,
	McpRevocationKind,
	McpRevocationStore,
	McpValidateOptions,
} from "../src/mcp/index.js";
import type {
	McpAuthModule,
	McpConfig,
	McpJtiDenylist,
	McpSession,
	McpTokenPayload,
	Result,
} from "../src/mcp/types.js";

describe("MCP revocation types", () => {
	it("keeps configs without the new fields valid", () => {
		const minimal: McpConfig = { enabled: true, signingSecret: "x".repeat(32) };
		expectTypeOf(minimal).toMatchTypeOf<McpConfig>();
		expectTypeOf<McpConfig["revocation"]>().toEqualTypeOf<McpRevocationConfig | undefined>();
		expectTypeOf<McpConfig["introspection"]>().toEqualTypeOf<McpIntrospectionConfig | undefined>();
		const session: McpSession = {
			userId: "u",
			clientId: "c",
			scopes: [],
			resource: null,
			expiresAt: new Date(),
			tokenId: "j",
		};
		expectTypeOf(session).toMatchTypeOf<McpSession>();
	});

	it("accepts a full config", () => {
		const full: McpConfig = {
			enabled: true,
			signingSecret: "x".repeat(32),
			revocation: {
				mode: "cached",
				maxStalenessMs: 5000,
				pollIntervalMs: 1000,
				cacheMax: 10000,
				requireBoundChain: true,
				revokeOnSignOutEverywhere: false,
				onRevoked: async (event) => {
					expectTypeOf(event).toEqualTypeOf<McpRevocationEvent>();
				},
			},
			introspection: {
				enabled: true,
				resourceServers: [{ clientId: "rs", audiences: ["https://mcp.example"] }],
				maxRequestsPerMinute: 600,
			},
		};
		expectTypeOf(full).toMatchTypeOf<McpConfig>();
		expectTypeOf<McpFreshnessMode>().toEqualTypeOf<"live" | "cached" | "offline">();
	});

	it("shapes the binding claim and session fields", () => {
		const binding: McpDelegationBinding = { v: 1, agt: ["a", "b"], lnk: ["l1"] };
		expectTypeOf(binding).toMatchTypeOf<McpTokenPayload["theauth_dlg"]>();
		expectTypeOf<McpDelegationBinding["v"]>().toEqualTypeOf<1>();
		expectTypeOf<NonNullable<McpSession["revalidate"]>>().returns.toEqualTypeOf<
			Promise<Result<void>>
		>();
		expectTypeOf<McpSession["binding"]>().toEqualTypeOf<McpDelegationBinding | undefined>();
		expectTypeOf<McpValidateOptions["freshness"]>().toEqualTypeOf<McpFreshnessMode | undefined>();
		expectTypeOf<NonNullable<McpAuthModule["introspect"]>>().returns.toEqualTypeOf<
			Promise<Result<McpIntrospectionResponse>>
		>();
	});

	it("defines the stores, verdicts and bus", () => {
		expectTypeOf<McpRevocationStore>().toMatchTypeOf<McpJtiDenylist>();
		expectTypeOf<McpRevocationStore["check"]>().returns.toEqualTypeOf<
			Promise<McpRevocationHit | null>
		>();
		expectTypeOf<McpRevocationKind>().toEqualTypeOf<"jti" | "dlg" | "agent" | "sub" | "client">();
		expectTypeOf<McpBindingStore["check"]>().returns.toEqualTypeOf<Promise<McpBindingVerdict>>();
		expectTypeOf<McpRevocationBus["subscribe"]>().returns.toEqualTypeOf<() => void>();
		expectTypeOf<McpIntrospectionResponse["theauth_inactive_reason"]>().toEqualTypeOf<
			McpInactiveReason | undefined
		>();
	});
});
