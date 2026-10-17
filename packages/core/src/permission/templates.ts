import type { Permission } from "../types.js";

/** Pre-built permission templates for common access patterns. Use these as starting points when creating agents. */
export const permissionTemplates = {
	/** Read-only access to all resources */
	readonly: [{ resource: "*", actions: ["read"] }] satisfies Permission[],

	/** Read and write access to all resources */
	readwrite: [{ resource: "*", actions: ["read", "write"] }] satisfies Permission[],

	/** Full access to all resources and actions */
	admin: [{ resource: "*", actions: ["*"] }] satisfies Permission[],

	/** Standard MCP tool access - read + execute */
	mcpBasic: [{ resource: "mcp:*", actions: ["read", "execute"] }] satisfies Permission[],

	/** MCP tool access with write - read + write + execute */
	mcpFull: [{ resource: "mcp:*", actions: ["read", "write", "execute"] }] satisfies Permission[],

	/** Rate-limited read access (100 calls/hour) */
	rateLimitedRead: [
		{
			resource: "*",
			actions: ["read"],
			constraints: { maxCallsPerHour: 100 },
		},
	] satisfies Permission[],

	/** Approval-required access (human-in-the-loop for everything) */
	approvalRequired: [
		{
			resource: "*",
			actions: ["*"],
			constraints: { requireApproval: true },
		},
	] satisfies Permission[],

	/** Business hours only access (9am-5pm) */
	businessHours: [
		{
			resource: "*",
			actions: ["read", "write", "execute"],
			constraints: { timeWindow: { start: "09:00", end: "17:00" } },
		},
	] satisfies Permission[],
} as const;

export type PermissionTemplateName = keyof typeof permissionTemplates;

/** Get a permission template by name. Returns a fresh copy of the permissions array. */
export function getPermissionTemplate(name: PermissionTemplateName): Permission[] {
	return JSON.parse(JSON.stringify(permissionTemplates[name])) as Permission[];
}
