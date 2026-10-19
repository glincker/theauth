// HTTP guard for Node orchestrators (LangGraph.js, CrewAI sidecars, any HTTP caller). It calls
// POST <baseUrl>/authorize/token with the agent bearer token. Uses the global `fetch`.

import type { ToolDenial } from "./gate.js";

export interface HttpGuardOptions {
	/** Where the theAuth handler is mounted, for example `https://auth.example.com/api/auth`. */
	baseUrl: string;
	/** Agent bearer token. A function is called per request so a rotated token is picked up. */
	token: string | (() => string | Promise<string>);
	/** Action checked. Default `execute`. */
	action?: string;
	/** Resource checked. Default `tool:<name>`. */
	resource?: (toolName: string, args: Record<string, unknown> | undefined) => string;
	/** Override for tests or custom transports. Default: global `fetch`. */
	fetch?: typeof fetch;
	/** Abort the check after this many milliseconds. Default 5000. */
	timeoutMs?: number;
}

export interface HttpGuard {
	/** Returns null when allowed, or the denial. Never throws: network and server errors deny (fail closed). */
	check(toolName: string, args?: unknown): Promise<ToolDenial | null>;
	/** Wrap an async function. A refusal is returned as the `ToolDenial`, the function does not run. */
	guard<A, R>(
		toolName: string,
		fn: (args: A) => Promise<R> | R,
	): (args: A) => Promise<R | ToolDenial>;
}

interface WireResult {
	allowed?: boolean;
	reason?: string;
	code?: string;
	auditId?: string;
}

function deny(toolName: string, code: string, reason: string, auditId?: string): ToolDenial {
	return {
		ok: false,
		denied: true,
		toolName,
		code,
		reason,
		approvalRequired: code === "approval_required",
		...(auditId ? { auditId } : {}),
	};
}

export function createHttpGuard(options: HttpGuardOptions): HttpGuard {
	const doFetch = options.fetch ?? fetch;
	const action = options.action ?? "execute";
	const url = `${options.baseUrl.replace(/\/+$/, "")}/authorize/token`;

	async function check(toolName: string, args?: unknown): Promise<ToolDenial | null> {
		const record =
			args !== null && typeof args === "object" && !Array.isArray(args)
				? (args as Record<string, unknown>)
				: undefined;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
		try {
			const token = typeof options.token === "function" ? await options.token() : options.token;
			const response = await doFetch(url, {
				method: "POST",
				headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
				body: JSON.stringify({
					action,
					resource: options.resource ? options.resource(toolName, record) : `tool:${toolName}`,
					...(record ? { arguments: record } : {}),
				}),
				signal: controller.signal,
			});
			const body = (await response.json().catch(() => null)) as {
				data?: WireResult;
				error?: { code?: string; message?: string };
			} | null;
			const data = body?.data;
			if (response.ok && data?.allowed === true) return null;
			if (data) {
				return deny(
					toolName,
					data.code ?? "no_permission",
					data.reason ?? "Denied by policy",
					data.auditId,
				);
			}
			return deny(
				toolName,
				body?.error?.code?.toLowerCase() ?? "guard_error",
				body?.error?.message ?? `Authorization check failed (HTTP ${response.status})`,
			);
		} catch (error) {
			return deny(
				toolName,
				"guard_error",
				error instanceof Error ? error.message : "Authorization check failed",
			);
		} finally {
			clearTimeout(timer);
		}
	}

	return {
		check,
		guard(toolName, fn) {
			return async (args) => {
				const refused = await check(toolName, args);
				if (refused) return refused;
				return fn(args);
			};
		},
	};
}
