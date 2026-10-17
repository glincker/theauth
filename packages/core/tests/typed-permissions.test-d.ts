import { describe, expectTypeOf, it } from "vitest";
import type { TypedTheAuth } from "../src/permission/index.js";
import { definePermissions } from "../src/permission/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const catalog = definePermissions({
	"mcp:github:*": ["read", "write"],
	"tool:file_read": ["execute"],
});

type Typed = TypedTheAuth<typeof catalog>;

declare const typed: Typed;
declare const untyped: TheAuth;

describe("typed permissions", () => {
	it("exact pattern accepts only its literal resource", () => {
		typed.authorize("a", { resource: "tool:file_read", action: "execute" });
		// @ts-expect-error resource is not declared
		typed.authorize("a", { resource: "tool:file_write", action: "execute" });
	});

	it("wildcard pattern accepts any suffix and rejects other prefixes", () => {
		typed.authorize("a", { resource: "mcp:github:issues", action: "read" });
		// @ts-expect-error other prefix
		typed.authorize("a", { resource: "mcp:gitlab:issues", action: "read" });
	});

	it("actions are correlated with the matching pattern", () => {
		// @ts-expect-error "execute" is not listed for mcp:github:*
		typed.authorize("a", { resource: "mcp:github:issues", action: "execute" });
		// @ts-expect-error "read" belongs to another pattern
		typed.authorize("a", { resource: "tool:file_read", action: "read" });
		// @ts-expect-error same for tokens
		typed.authorizeByToken("t", { resource: "mcp:github:x", action: "execute" });
	});

	it("untyped createTheAuth keeps accepting arbitrary strings", () => {
		expectTypeOf(createTheAuth).returns.resolves.toMatchTypeOf<TheAuth | Typed>();
		untyped.authorize("a", { resource: "anything:goes", action: "whatever" });
	});

	it("agent.create and delegate reject undeclared resources and allow wildcard actions", () => {
		typed.agent.create({
			ownerId: "u",
			name: "n",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:github:*", actions: ["*"] },
				{ resource: "tool:file_read", actions: ["execute"] },
			],
		});
		typed.agent.create({
			ownerId: "u",
			name: "n",
			type: "autonomous",
			// @ts-expect-error undeclared resource
			permissions: [{ resource: "db:users", actions: ["read"] }],
		});
		typed.agent.update("a", {
			// @ts-expect-error undeclared action
			permissions: [{ resource: "mcp:github:*", actions: ["delete"] }],
		});
		typed.delegate({
			fromAgent: "a",
			toAgent: "b",
			expiresAt: new Date(),
			// @ts-expect-error undeclared resource
			permissions: [{ resource: "db:users", actions: ["read"] }],
		});
	});

	it("TypedTheAuth can be cast to TheAuth for adapters", () => {
		const adapterFactory = (_auth: TheAuth): void => undefined;
		adapterFactory(typed as unknown as TheAuth);
		expectTypeOf(typed.authorize).parameter(1).not.toBeString();
	});
});
