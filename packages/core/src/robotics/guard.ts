// Runtime gate for hazardous robot commands. It calls POST <baseUrl>/authorize/token with the robot's
// agent bearer token and runs the command only on an explicit `allowed: true`.
//
// Two rules shape it:
//  1. Fail closed. A timeout, a network error, a non JSON answer, a 5xx or anything other than
//     `allowed: true` refuses the command.
//  2. Safety stops never wait for the network. A resource listed in `safetyStops` runs at once,
//     with no request and no refusal path. This is a convenience for software stop commands only.
//     It is not a safety function: an emergency stop must be wired in hardware or in a certified
//     safety controller, independent of this process, the network and theAuth (see ISO 13850 and the
//     safety standards for your machine).

export interface RobotCommand {
	/** theAuth action, for example `publish`, `call` or `execute`. */
	action: string;
	/** theAuth resource, for example `ros2:/cmd_vel`. */
	resource: string;
	/** Command arguments, checked against `allowedArgPatterns` constraints on the server. */
	arguments?: Record<string, unknown>;
	/** Id of a granted approval (`requireApproval`). */
	approvalId?: string;
}

export interface RobotGuardOptions {
	/** Where the theAuth handler is mounted, for example `https://auth.example.com/api/auth`. */
	baseUrl: string;
	/** Robot agent bearer token. A function is called per request so a rotated token is picked up. */
	token: string | (() => string | Promise<string>);
	/**
	 * Exact resources that bypass the check, for example `["ros2:/e_stop", "ros2:/safety/stop"]`.
	 * Matched literally, no wildcards, and empty by default. Keep it short and only list commands
	 * that stop motion.
	 */
	safetyStops?: readonly string[];
	/** Called after a safety stop ran. Errors and rejections are swallowed, it is never awaited. */
	onSafetyStop?: (command: RobotCommand) => void | Promise<void>;
	/** Override for tests or custom transports. Default: global `fetch`. */
	fetch?: typeof fetch;
	/** Abort the check after this many milliseconds. Default 2000. */
	timeoutMs?: number;
}

export type RobotGuardResult<T> =
	| { ok: true; value: T; bypassed: boolean; auditId?: string }
	| {
			ok: false;
			code: string;
			reason: string;
			/** True when a human approval or a step up would let the command through. */
			approvalRequired: boolean;
			auditId?: string;
	  };

interface WireResult {
	allowed?: boolean;
	reason?: string;
	code?: string;
	auditId?: string;
}

const HELD_CODES = new Set(["approval_required", "step_up_required"]);

function refuse(code: string, reason: string, auditId?: string): RobotGuardResult<never> {
	return {
		ok: false,
		code,
		reason,
		approvalRequired: HELD_CODES.has(code),
		...(auditId ? { auditId } : {}),
	};
}

async function askServer(
	options: RobotGuardOptions,
	command: RobotCommand,
): Promise<{ allowed: true; auditId?: string } | RobotGuardResult<never>> {
	const doFetch = options.fetch ?? fetch;
	const url = `${options.baseUrl.replace(/\/+$/, "")}/authorize/token`;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 2000);
	try {
		const token = typeof options.token === "function" ? await options.token() : options.token;
		const response = await doFetch(url, {
			method: "POST",
			headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
			body: JSON.stringify({
				action: command.action,
				resource: command.resource,
				...(command.arguments ? { arguments: command.arguments } : {}),
				...(command.approvalId ? { approvalId: command.approvalId } : {}),
			}),
			signal: controller.signal,
		});
		const body = (await response.json().catch(() => null)) as {
			data?: WireResult;
			error?: { code?: string; message?: string };
		} | null;
		const data = body?.data;
		if (response.ok && data?.allowed === true) {
			return { allowed: true, ...(data.auditId ? { auditId: data.auditId } : {}) };
		}
		if (data) {
			return refuse(data.code ?? "no_permission", data.reason ?? "Denied by policy", data.auditId);
		}
		return refuse(
			body?.error?.code?.toLowerCase() ?? "guard_error",
			body?.error?.message ?? `Authorization check failed (HTTP ${response.status})`,
		);
	} catch (error) {
		return refuse(
			"guard_error",
			error instanceof Error ? error.message : "Authorization check failed",
		);
	} finally {
		clearTimeout(timer);
	}
}

function notifySafetyStop(options: RobotGuardOptions, command: RobotCommand): void {
	if (!options.onSafetyStop) return;
	try {
		void Promise.resolve(options.onSafetyStop(command)).catch(() => undefined);
	} catch {
		// A failing notifier must never affect a stop.
	}
}

/**
 * Run `run` only if theAuth allows `command`. Never throws for a policy or network problem, it
 * returns `{ ok: false }` instead. Errors thrown by `run` itself propagate to the caller.
 */
export async function guardRobotCommand<T>(
	options: RobotGuardOptions,
	command: RobotCommand,
	run: () => Promise<T> | T,
): Promise<RobotGuardResult<T>> {
	if (options.safetyStops?.includes(command.resource)) {
		const value = await run();
		notifySafetyStop(options, command);
		return { ok: true, value, bypassed: true };
	}
	const verdict = await askServer(options, command);
	if ("ok" in verdict) return verdict;
	const value = await run();
	return {
		ok: true,
		value,
		bypassed: false,
		...(verdict.auditId ? { auditId: verdict.auditId } : {}),
	};
}
