import { describe, expectTypeOf, it } from "vitest";
import type { McpClient, McpConfig, McpServerMetadata } from "../src/mcp/types.js";
import type { McpRegistrationConfig } from "../src/mcp/types-auth.js";
import type { ClientDescription, McpCimdConfig, McpCimdEvent } from "../src/mcp/types-cimd.js";

describe("CIMD types", () => {
	it("accepts the legacy config shape", () => {
		const legacy: NonNullable<McpConfig["clientIdMetadataDocuments"]> = {
			enabled: true,
			resolver: async () => ["93.184.216.34"],
			allowedHosts: ["app.example"],
			negativeCacheSeconds: 30,
		};
		expectTypeOf(legacy).toMatchTypeOf<McpCimdConfig>();
		expectTypeOf<{ enabled: false }>().toMatchTypeOf<McpCimdConfig>();
	});

	it("has the new fields", () => {
		expectTypeOf<McpCimdConfig["resolver"]>().toExtend<
			"auto" | "none" | ((host: string) => Promise<string[]>) | undefined
		>();
		expectTypeOf<McpCimdConfig["onBoundClientChange"]>().toEqualTypeOf<
			"disable" | "allow" | undefined
		>();
		expectTypeOf<McpCimdConfig["onEvent"]>().parameter(0).toEqualTypeOf<McpCimdEvent>();
		expectTypeOf<McpConfig["clientIdMetadataDocuments"]>().toEqualTypeOf<
			McpCimdConfig | undefined
		>();
		expectTypeOf<McpClient["disabledReason"]>().toEqualTypeOf<string | null | undefined>();
		expectTypeOf<McpServerMetadata["registration_endpoint"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<McpRegistrationConfig["enabled"]>().toEqualTypeOf<boolean | undefined>();
		expectTypeOf<ClientDescription["warnings"][number]>().toExtend<string>();
	});
});
