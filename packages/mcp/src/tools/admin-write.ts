import type { McpServer, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { InputSource } from "../provenance.js";
import { readInputsMeta } from "../provenance.js";
import type { RegisteredTool, ToolContext } from "./define.js";

/**
 * Write tools never act on first contact. The first call opens an approval
 * request through the deployment's approval (CIBA) routes and returns
 * `pending`. A human approves out of band. Calling the same tool again with
 * the `approvalId` executes the change only if the approval is approved,
 * unexpired and unused; the server spends it atomically, so one approval
 * authorizes one execution of exactly this action and resource.
 */

interface WriteSpec {
	name: string;
	title: string;
	description: string;
	/** Approval action string, for example admin:revoke_agent. */
	action: string;
	resourcePrefix: "agent" | "delegation" | "user";
	idLabel: string;
	execute(id: string, ctx: ToolContext): ReturnType<ToolContext["client"]["request"]>;
}

interface ApprovalRecord {
	id?: unknown;
	status?: unknown;
}

const WRITE_SHAPE = {
	id: z.string().min(1).max(200),
	reason: z
		.string()
		.max(500)
		.optional()
		.describe("Why this change is needed, shown to the approver"),
	approvalId: z
		.string()
		.min(1)
		.max(200)
		.optional()
		.describe("Id returned by an earlier pending call; pass it to execute once approved"),
};

type WriteArgs = z.objectOutputType<typeof WRITE_SHAPE, z.ZodTypeAny>;

function text(value: unknown, isError = false) {
	return {
		...(isError ? { isError: true } : {}),
		content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
	};
}

function defineWriteTool(spec: WriteSpec, actor: string): RegisteredTool {
	return {
		name: spec.name,
		register(server: McpServer, ctx: ToolContext) {
			const resourceOf = (id: string) => `${spec.resourcePrefix}:${id}`;
			const audit = (
				result: Parameters<NonNullable<ToolContext["audit"]>["record"]>[0]["result"],
				args: WriteArgs,
				approvalId?: string,
				inputs?: InputSource[],
			) =>
				ctx.audit?.record({
					tool: spec.name,
					mode: "write",
					result,
					approvalId,
					inputs,
					params: { id: args.id, reason: args.reason },
				}) ?? Promise.resolve(true);

			const callback = (async (args: WriteArgs, extra?: unknown) => {
				const inputs = readInputsMeta(extra);
				try {
					const resource = resourceOf(args.id);
					if (!args.approvalId) {
						// Fail closed: no audited intent, no approval request.
						if (!(await audit("requested", args, undefined, inputs))) {
							return text(
								{
									success: false,
									error: {
										code: "AUDIT_UNAVAILABLE",
										message: "Could not record the request in the audit log, nothing was done",
									},
								},
								true,
							);
						}
						const created = await ctx.client.request<ApprovalRecord>("POST", "/approvals", {
							body: {
								agentId: actor,
								userId: actor,
								action: spec.action,
								resource,
								arguments: { reason: args.reason },
							},
						});
						if (!created.ok) {
							return text(
								{
									success: false,
									error: { code: created.error.code, message: created.error.message },
								},
								true,
							);
						}
						const approvalId = typeof created.data.id === "string" ? created.data.id : undefined;
						if (!approvalId) {
							return text(
								{
									success: false,
									error: { code: "BAD_RESPONSE", message: "Approval response had no id" },
								},
								true,
							);
						}
						await audit("pending", args, approvalId, inputs);
						return text({
							status: "pending",
							approvalId,
							message: `Approval needed before ${spec.idLabel} ${args.id} changes. Ask an approver, then poll get_approval_status or call ${spec.name} again with this approvalId.`,
						});
					}

					const found = await ctx.client.request<ApprovalRecord>(
						"GET",
						`/approvals/${encodeURIComponent(args.approvalId)}`,
					);
					if (!found.ok) {
						return text(
							{ success: false, error: { code: found.error.code, message: found.error.message } },
							true,
						);
					}
					if (found.data.status === "pending") {
						return text({ status: "pending", approvalId: args.approvalId });
					}
					if (found.data.status !== "approved") {
						await audit("denied", args, args.approvalId, inputs);
						return text(
							{
								success: false,
								status: found.data.status,
								error: {
									code: "APPROVAL_NOT_APPROVED",
									message: `Approval is ${String(found.data.status)}, nothing was done`,
								},
							},
							true,
						);
					}
					// Spend the approval first, bound to this action, resource and the reason the approver saw.
					const spent = await ctx.client.request(
						"POST",
						`/approvals/${encodeURIComponent(args.approvalId)}/consume`,
						{
							body: {
								agentId: actor,
								action: spec.action,
								resource,
								arguments: { reason: args.reason },
							},
						},
					);
					if (!spent.ok) {
						await audit("denied", args, args.approvalId, inputs);
						return text(
							{ success: false, error: { code: spent.error.code, message: spent.error.message } },
							true,
						);
					}
					const done = await spec.execute(args.id, ctx);
					if (!done.ok) {
						await audit("failed", args, args.approvalId, inputs);
						return text(
							{ success: false, error: { code: done.error.code, message: done.error.message } },
							true,
						);
					}
					await audit("executed", args, args.approvalId, inputs);
					return text({ status: "executed", approvalId: args.approvalId, target: resource });
				} catch (error) {
					ctx.logger.error(`tool ${spec.name} failed`, error);
					return text(
						{
							success: false,
							error: {
								code: "INTERNAL_ERROR",
								message: error instanceof Error ? error.message : "Unknown error",
							},
						},
						true,
					);
				}
			}) as unknown as ToolCallback<typeof WRITE_SHAPE>;

			server.registerTool(
				spec.name,
				{
					title: spec.title,
					description: spec.description,
					inputSchema: WRITE_SHAPE,
					annotations: {
						readOnlyHint: false,
						destructiveHint: true,
						idempotentHint: false,
						openWorldHint: false,
					},
				},
				callback,
			);
		},
	};
}

const enc = encodeURIComponent;

export function createWriteTools(actor: string): RegisteredTool[] {
	return [
		defineWriteTool(
			{
				name: "revoke_agent",
				title: "Revoke agent",
				description:
					"Revoke an agent identity. Requires human approval: the first call returns a pending approvalId, call again with it after approval.",
				action: "admin:revoke_agent",
				resourcePrefix: "agent",
				idLabel: "agent",
				execute: (id, { client }) => client.request("DELETE", `/agents/${enc(id)}`),
			},
			actor,
		),
		defineWriteTool(
			{
				name: "revoke_delegation",
				title: "Revoke delegation",
				description:
					"Revoke a delegation chain. Requires human approval: the first call returns a pending approvalId, call again with it after approval.",
				action: "admin:revoke_delegation",
				resourcePrefix: "delegation",
				idLabel: "delegation",
				execute: (id, { client }) => client.request("DELETE", `/delegations/${enc(id)}`),
			},
			actor,
		),
		defineWriteTool(
			{
				name: "rotate_key",
				title: "Rotate agent key",
				description:
					"Rotate an agent's credential. The new token is deliberately not returned to the MCP client. Requires human approval.",
				action: "admin:rotate_key",
				resourcePrefix: "agent",
				idLabel: "agent",
				execute: (id, { client }) => client.request("POST", `/agents/${enc(id)}/rotate`),
			},
			actor,
		),
		defineWriteTool(
			{
				name: "disable_user",
				title: "Disable user",
				description:
					"Disable a user account and end its sessions. Requires human approval: the first call returns a pending approvalId, call again with it after approval.",
				action: "admin:disable_user",
				resourcePrefix: "user",
				idLabel: "user",
				execute: (id, { client }) => client.request("POST", `/users/${enc(id)}/disable`),
			},
			actor,
		),
	];
}
