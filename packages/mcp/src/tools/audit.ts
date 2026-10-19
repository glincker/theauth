import type { ApiClient } from "../client.js";
import type { Logger } from "../logger.js";
import type { InputSource } from "../provenance.js";
import { redact } from "../redact.js";

export interface AuditEntry {
	tool: string;
	mode: "read" | "write";
	/** ok and error describe the call; requested, approved, denied record the write lifecycle. */
	result: "ok" | "error" | "requested" | "pending" | "denied" | "executed" | "failed";
	params?: unknown;
	approvalId?: string;
	/** Caller claimed inputs of this call, from the request `_meta`. */
	inputs?: InputSource[];
}

export interface AuditRecorder {
	/** Resolves true when the entry was stored. Never throws. */
	record(entry: AuditEntry): Promise<boolean>;
}

/**
 * Records every admin MCP call in the deployment's audit log with the actor
 * attached. Secret-looking params are redacted before they leave the process.
 */
export function createAuditRecorder(
	client: ApiClient,
	actor: string,
	logger: Logger,
): AuditRecorder {
	return {
		async record(entry) {
			const r = await client.request("POST", "/audit/events", {
				body: {
					actor,
					source: "theauth-mcp",
					action: `admin_mcp.${entry.tool}`,
					mode: entry.mode,
					result: entry.result,
					approvalId: entry.approvalId,
					params: redact(entry.params ?? {}),
					...(entry.inputs ? { inputs: entry.inputs } : {}),
				},
			});
			if (!r.ok) logger.error(`audit write failed for ${entry.tool}: ${r.error.code}`);
			return r.ok;
		},
	};
}
