import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { ToolContext } from "./tools.js";
import { callTool, TOOLS } from "./tools.js";

const SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;

interface JsonRpcRequest {
	jsonrpc: "2.0";
	id?: string | number | null;
	method: string;
	params?: Record<string, unknown>;
}

type JsonRpcResponse =
	| { jsonrpc: "2.0"; id: string | number | null; result: unknown }
	| { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string } };

const rpcError = (id: JsonRpcRequest["id"], code: number, message: string): JsonRpcResponse => ({
	jsonrpc: "2.0",
	id: id ?? null,
	error: { code, message },
});

/** Handle one JSON-RPC message. Returns null for notifications. */
export async function handleMessage(
	raw: unknown,
	ctx: ToolContext,
	version: string,
): Promise<JsonRpcResponse | null> {
	if (
		typeof raw !== "object" ||
		raw === null ||
		typeof (raw as JsonRpcRequest).method !== "string"
	) {
		return rpcError(null, -32600, "Invalid request");
	}
	const msg = raw as JsonRpcRequest;
	const isNotification = msg.id === undefined;
	const respond = (result: unknown): JsonRpcResponse | null =>
		isNotification ? null : { jsonrpc: "2.0", id: msg.id ?? null, result };

	switch (msg.method) {
		case "initialize": {
			const asked = msg.params?.protocolVersion;
			const protocolVersion =
				typeof asked === "string" && (SUPPORTED_PROTOCOLS as readonly string[]).includes(asked)
					? asked
					: SUPPORTED_PROTOCOLS[0];
			return respond({
				protocolVersion,
				capabilities: { tools: {} },
				serverInfo: { name: "theauth", version },
				instructions:
					"Tools for adding theAuth to a project: search_docs, get_doc, add_plugin, generate_schema, inspect. All are read-only.",
			});
		}
		case "ping":
			return respond({});
		case "tools/list":
			return respond({ tools: TOOLS });
		case "tools/call": {
			const name = msg.params?.name;
			if (typeof name !== "string") return rpcError(msg.id, -32602, "Missing tool name");
			const args =
				typeof msg.params?.arguments === "object" && msg.params.arguments !== null
					? (msg.params.arguments as Record<string, unknown>)
					: {};
			const result = await callTool(name, args, ctx);
			return respond({ content: [{ type: "text", text: result.text }], isError: result.isError });
		}
		default:
			if (isNotification) return null;
			return rpcError(msg.id, -32601, `Method not found: ${msg.method}`);
	}
}

/** Newline-delimited JSON-RPC over streams. Only protocol messages go to `output`. */
export async function serveStdio(
	input: Readable,
	output: Writable,
	ctx: ToolContext,
	version: string,
): Promise<void> {
	const rl = createInterface({ input });
	const pending = new Set<Promise<void>>();
	const send = (message: JsonRpcResponse): void => {
		output.write(`${JSON.stringify(message)}\n`);
	};
	rl.on("line", (line) => {
		if (line.trim() === "") return;
		const task = (async () => {
			let parsed: unknown;
			try {
				parsed = JSON.parse(line);
			} catch {
				send(rpcError(null, -32700, "Parse error"));
				return;
			}
			const response = await handleMessage(parsed, ctx, version);
			if (response) send(response);
		})().finally(() => pending.delete(task));
		pending.add(task);
	});
	await new Promise<void>((resolve) => rl.once("close", resolve));
	await Promise.all(pending);
}
