import type { McpServer, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import type { ApiClient } from "../client.js";
import type { Logger } from "../logger.js";

export interface ToolContext {
	client: ApiClient;
	logger: Logger;
}

export type Outcome = { ok: true; value: unknown } | { ok: false; code: string; message: string };

export const success = (value: unknown): Outcome => ({ ok: true, value });
export const failure = (code: string, message: string): Outcome => ({ ok: false, code, message });

export interface ToolSpec<Shape extends z.ZodRawShape> {
	name: string;
	title: string;
	description: string;
	inputSchema: Shape;
	run(args: z.objectOutputType<Shape, z.ZodTypeAny>, ctx: ToolContext): Promise<Outcome>;
}

export interface RegisteredTool {
	name: string;
	register(server: McpServer, ctx: ToolContext): void;
}

/**
 * Every tool is read-only. Failures become `isError` results with a code and
 * message so the model can react; nothing is thrown across the protocol.
 */
export function defineTool<Shape extends z.ZodRawShape>(spec: ToolSpec<Shape>): RegisteredTool {
	return {
		name: spec.name,
		register(server, ctx) {
			// The SDK callback type is conditional on the shape; the runtime contract is
			// (parsedArgs) => CallToolResult, which this satisfies.
			const callback = (async (args: z.objectOutputType<Shape, z.ZodTypeAny>) => {
				try {
					const outcome = await spec.run(args, ctx);
					if (outcome.ok) {
						return {
							content: [{ type: "text" as const, text: JSON.stringify(outcome.value, null, 2) }],
						};
					}
					return errorResult(outcome.code, outcome.message);
				} catch (error) {
					ctx.logger.error(`tool ${spec.name} failed`, error);
					return errorResult(
						"INTERNAL_ERROR",
						error instanceof Error ? error.message : "Unknown error",
					);
				}
			}) as unknown as ToolCallback<Shape>;
			server.registerTool(
				spec.name,
				{
					title: spec.title,
					description: spec.description,
					inputSchema: spec.inputSchema,
					annotations: {
						readOnlyHint: true,
						destructiveHint: false,
						idempotentHint: true,
						openWorldHint: false,
					},
				},
				callback,
			);
		},
	};
}

function errorResult(code: string, message: string) {
	return {
		isError: true,
		content: [
			{ type: "text" as const, text: JSON.stringify({ success: false, error: { code, message } }) },
		],
	};
}
