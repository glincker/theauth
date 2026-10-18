/**
 * Remote guard protocol. `httpGuard` turns an HTTPS endpoint run by a guard
 * vendor into a `beforeAuthorize` hook. Timeout, fail-closed handling and the
 * audit fields come from the hook runner, see `hookSafety`.
 *
 * Wire format (protocol 2026-10):
 *   POST <url>, content-type application/json, body = GuardWireRequest
 *   x-theauth-timestamp: unix seconds
 *   x-theauth-signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>">
 *   x-theauth-guard-version: 2026-10
 * Response: 2xx JSON, one of the GuardWireVerdict shapes. Anything else denies.
 */
import { z } from "zod";
import type { ExternalGuard, GuardCheckInput } from "./guard.js";
import { guardHook } from "./guard.js";
import type { HookVerdict } from "./lifecycle.js";
import { defaultEnvReader } from "./safety.js";

export const GUARD_PROTOCOL_VERSION = "2026-10";
export const GUARD_TIMESTAMP_HEADER = "x-theauth-timestamp";
export const GUARD_SIGNATURE_HEADER = "x-theauth-signature";
export const GUARD_VERSION_HEADER = "x-theauth-guard-version";
export const GUARD_KEY_ID_HEADER = "x-theauth-key-id";
/** Default replay window for `verifyGuardRequest`, in seconds. */
export const GUARD_DEFAULT_TOLERANCE_SEC = 300;
/** Responses larger than this are refused. */
export const GUARD_MAX_RESPONSE_BYTES = 65536;

export interface GuardWireRequest {
	version: string;
	requestId: string;
	issuedAt: string;
	input: GuardCheckInput;
}

const metadataSchema = z
	.record(z.union([z.string(), z.number(), z.boolean()]))
	.refine((m) => Object.keys(m).length <= 16, "metadata allows at most 16 keys");

const common = {
	guard: z.string().max(128).optional(),
	ruleId: z.string().max(128).optional(),
	metadata: metadataSchema.optional(),
};

/** Strict response schema. Unknown fields are rejected. */
export const guardVerdictSchema = z.discriminatedUnion("decision", [
	z
		.object({ decision: z.literal("allow"), reason: z.string().max(1024).optional(), ...common })
		.strict(),
	z
		.object({
			decision: z.literal("deny"),
			reason: z.string().min(1).max(1024),
			code: z.string().max(128).optional(),
			...common,
		})
		.strict(),
	z
		.object({ decision: z.literal("escalate"), reason: z.string().max(1024).optional(), ...common })
		.strict(),
]);

export type GuardWireVerdict = z.infer<typeof guardVerdictSchema>;

export interface HttpGuardOptions {
	name: string;
	version?: string;
	/** Vendor endpoint. https only, except localhost outside production. */
	url: string;
	/** HMAC secret shared with the guard. Never logged, never sent. */
	secret: string;
	keyId?: string;
	/** Extra request headers, for example a vendor API key. Never echoed in errors. */
	headers?: Record<string, string>;
	/** Drop or mask fields before they leave the process. Default sends the full input. */
	redact?: (input: GuardCheckInput) => GuardCheckInput;
	/** Test seam. Defaults to the global fetch. */
	fetch?: typeof fetch;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function assertSafeUrl(raw: string, name: string): URL {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new Error(`httpGuard "${name}": url is not valid`);
	}
	if (url.username || url.password) {
		throw new Error(`httpGuard "${name}": url must not contain credentials`);
	}
	if (url.protocol === "https:") return url;
	const dev = defaultEnvReader("NODE_ENV") !== "production";
	if (url.protocol === "http:" && dev && LOOPBACK.has(url.hostname)) return url;
	throw new Error(
		`httpGuard "${name}": url must use https (http is allowed only for localhost outside production)`,
	);
}

const encoder = new TextEncoder();

async function hmacHex(secret: string, message: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
	return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a: string, b: string): boolean {
	const x = encoder.encode(a);
	const y = encoder.encode(b);
	let diff = x.length ^ y.length;
	for (let i = 0; i < Math.max(x.length, y.length); i += 1) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
	return diff === 0;
}

/** Sign a body the way the protocol requires. Exported for vendors and tests. */
export async function signGuardBody(
	secret: string,
	timestamp: number,
	body: string,
): Promise<string> {
	return `v1=${await hmacHex(secret, `${timestamp}.${body}`)}`;
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function readHeader(headers: HeaderSource, name: string): string | undefined {
	if (typeof (headers as Headers).get === "function") {
		return (headers as Headers).get(name) ?? undefined;
	}
	for (const [key, value] of Object.entries(
		headers as Record<string, string | string[] | undefined>,
	)) {
		if (key.toLowerCase() === name) return Array.isArray(value) ? value[0] : value;
	}
	return undefined;
}

export type VerifyGuardResult =
	| { ok: true; requestId: string; input: GuardCheckInput }
	| { ok: false; reason: string };

export interface VerifyGuardOptions {
	/** Max age or clock skew in seconds. Default 300. */
	toleranceSec?: number;
	/** Return true if this requestId was already accepted. Lets a vendor reject exact replays. */
	seen?: (requestId: string) => boolean | Promise<boolean>;
	/** Clock seam for tests, unix seconds. */
	now?: () => number;
}

/**
 * Vendor side check. Verifies signature and freshness over the raw body, then
 * parses the envelope.
 *
 *   const r = await verifyGuardRequest(secret, req.headers, rawBody);
 *   if (!r.ok) return respond(401);
 *   return respond(200, decide(r.input));
 */
export async function verifyGuardRequest(
	secret: string,
	headers: HeaderSource,
	body: string,
	options: VerifyGuardOptions = {},
): Promise<VerifyGuardResult> {
	const timestamp = readHeader(headers, GUARD_TIMESTAMP_HEADER);
	const signature = readHeader(headers, GUARD_SIGNATURE_HEADER);
	if (!timestamp || !signature) return { ok: false, reason: "missing signature headers" };
	if (!/^\d{1,12}$/.test(timestamp)) return { ok: false, reason: "bad timestamp" };
	const ts = Number(timestamp);
	const now = (options.now ?? (() => Math.floor(Date.now() / 1000)))();
	const tolerance = options.toleranceSec ?? GUARD_DEFAULT_TOLERANCE_SEC;
	if (Math.abs(now - ts) > tolerance) return { ok: false, reason: "stale timestamp" };
	if (!safeEqual(await signGuardBody(secret, ts, body), signature)) {
		return { ok: false, reason: "bad signature" };
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch {
		return { ok: false, reason: "body is not JSON" };
	}
	const envelope = z
		.object({
			version: z.string(),
			requestId: z.string().min(1).max(128),
			issuedAt: z.string(),
			input: z.object({ action: z.string(), resource: z.string() }).passthrough(),
		})
		.passthrough()
		.safeParse(parsed);
	if (!envelope.success) return { ok: false, reason: "malformed envelope" };
	if (options.seen && (await options.seen(envelope.data.requestId))) {
		return { ok: false, reason: "replayed request" };
	}
	return {
		ok: true,
		requestId: envelope.data.requestId,
		input: envelope.data.input as unknown as GuardCheckInput,
	};
}

async function readCapped(response: Response): Promise<string> {
	const declared = Number(response.headers.get("content-length") ?? "0");
	if (declared > GUARD_MAX_RESPONSE_BYTES) throw new Error("guard response too large");
	const text = await response.text();
	if (encoder.encode(text).length > GUARD_MAX_RESPONSE_BYTES) {
		throw new Error("guard response too large");
	}
	return text;
}

/** Build an ExternalGuard that calls a vendor endpoint. Throws on a bad url or empty secret. */
export function httpGuard(options: HttpGuardOptions): ExternalGuard {
	const url = assertSafeUrl(options.url, options.name);
	if (!options.secret) throw new Error(`httpGuard "${options.name}": secret is required`);
	const { secret, redact, keyId } = options;
	const doFetch = options.fetch ?? fetch;
	const where = url.origin;
	const guard: ExternalGuard = {
		name: options.name,
		async check(rawInput, signal): Promise<HookVerdict> {
			const input = redact ? redact(rawInput) : rawInput;
			const envelope: GuardWireRequest = {
				version: GUARD_PROTOCOL_VERSION,
				requestId: crypto.randomUUID(),
				issuedAt: new Date().toISOString(),
				input,
			};
			const body = JSON.stringify(envelope);
			const timestamp = Math.floor(Date.now() / 1000);
			const headers: Record<string, string> = {
				...options.headers,
				"content-type": "application/json",
				accept: "application/json",
				[GUARD_TIMESTAMP_HEADER]: String(timestamp),
				[GUARD_SIGNATURE_HEADER]: await signGuardBody(secret, timestamp, body),
				[GUARD_VERSION_HEADER]: GUARD_PROTOCOL_VERSION,
			};
			if (keyId) headers[GUARD_KEY_ID_HEADER] = keyId;
			const response = await doFetch(url.toString(), {
				method: "POST",
				headers,
				body,
				redirect: "manual",
				signal,
			});
			if (response.status >= 300 && response.status < 400) {
				throw new Error(`guard at ${where} answered with a redirect, refused`);
			}
			if (response.type === "opaqueredirect") {
				throw new Error(`guard at ${where} answered with a redirect, refused`);
			}
			if (response.status < 200 || response.status >= 300) {
				throw new Error(`guard at ${where} answered HTTP ${response.status}`);
			}
			let json: unknown;
			try {
				json = JSON.parse(await readCapped(response));
			} catch (error) {
				if (error instanceof Error && error.message === "guard response too large") throw error;
				throw new Error(`guard at ${where} returned a body that is not JSON`);
			}
			const parsed = guardVerdictSchema.safeParse(json);
			if (!parsed.success) throw new Error(`guard at ${where} returned a malformed verdict`);
			const { decision, reason, guard: vendorGuard, ruleId, metadata } = parsed.data;
			const code = parsed.data.decision === "deny" ? parsed.data.code : undefined;
			const verdict: HookVerdict = { decision };
			if (reason !== undefined) verdict.reason = reason;
			if (vendorGuard) verdict.guard = vendorGuard;
			if (ruleId ?? code) verdict.ruleId = ruleId ?? code;
			if (metadata) verdict.metadata = metadata;
			return verdict;
		},
	};
	if (options.version) guard.version = options.version;
	return guard;
}

/** Shorthand: `beforeAuthorize: httpGuardHook({ ... })`. */
export function httpGuardHook(options: HttpGuardOptions): ReturnType<typeof guardHook> {
	return guardHook(httpGuard(options));
}
