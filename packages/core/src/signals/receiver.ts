/**
 * Shared Signals receiver: verifies incoming SETs, rejects replays, and
 * dispatches events to handlers. Push endpoint per RFC 8935.
 */

import type { JWK, JWTVerifyGetKey } from "jose";
import { createLocalJWKSet } from "jose";
import { constantTimeEqual } from "../crypto/web-crypto.js";
import type { SafeFetchOptions } from "../mcp/safe-fetch.js";
import { safeFetchJson } from "../mcp/safe-fetch.js";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { VerifyKey } from "./set.js";
import { verifySet } from "./set.js";
import { parseSubject } from "./subjects.js";
import type { SecurityEventToken, SubjectIdentifier } from "./types.js";
import { SET_MEDIA_TYPE } from "./types.js";

export interface ReceivedEvent {
	/** Event type URI. */
	type: string;
	payload: Record<string, unknown>;
	/** Subject from the event payload, else from `sub_id`. */
	subject: SubjectIdentifier | null;
	/** Seconds since epoch, when the event carried one. */
	eventTimestamp: number | null;
	token: SecurityEventToken;
}

export type EventHandler = (event: ReceivedEvent) => Promise<void> | void;

export interface ReceiverConfig {
	/** Issuer you accept SETs from. */
	issuer: string;
	/** Your audience value; SETs must name it. */
	audience: string;
	/**
	 * Key source, first match wins: `verificationKey`, static `jwks`, or
	 * discovery. Discovery fetches `${issuer}/.well-known/ssf-configuration`
	 * (or `configurationUrl`) and then its `jwks_uri`, through the SSRF-safe
	 * fetcher.
	 */
	verificationKey?: VerifyKey;
	jwks?: { keys: JWK[] };
	configurationUrl?: string;
	/** Options for the discovery fetches (resolver, fetchImpl, timeout). */
	fetchOptions?: SafeFetchOptions;
	algorithms?: string[];
	/** Shared secret the transmitter sends in `Authorization`. Optional hardening. */
	authorizationHeader?: string;
	/** Replay cache. Defaults to per-process memory; use a shared store for several instances. */
	replayStorage?: SecondaryStorage;
	/** How long a jti is remembered, seconds. Default 86400. */
	replayTtlSeconds?: number;
	/** Reject SETs whose `iat` is older than this. Default 3600 seconds. */
	maxAgeSeconds?: number;
	/** Per event type handlers. */
	handlers?: Record<string, EventHandler>;
	/** Called for event types with no handler. */
	onUnhandled?: EventHandler;
	/** Receives verification event states (stream verification). */
	onVerification?: (state: string | undefined) => Promise<void> | void;
}

export interface ReceiveOutcome {
	jti: string;
	events: string[];
}

export type ReceiveResult =
	| { ok: true; value: ReceiveOutcome }
	| { ok: false; err: string; description: string };

export interface Receiver {
	/** Verify and process one SET. */
	receive(token: string): Promise<ReceiveResult>;
	/** Push endpoint handler: POST application/secevent+jwt. */
	handleRequest(request: Request): Promise<Response>;
	/** Process the `sets` object of a poll response; returns jtis to ack. */
	receivePolled(sets: Record<string, string>): Promise<{
		ack: string[];
		setErrs: Record<string, { err: string; description: string }>;
	}>;
	on(type: string, handler: EventHandler): void;
}

const VERIFICATION_EVENT = "https://schemas.openid.net/secevent/ssf/event-type/verification";
const DISCOVERY_TTL_MS = 5 * 60 * 1000;
const MIN_REFETCH_MS = 30 * 1000;

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
	});
}

export function createReceiver(config: ReceiverConfig): Receiver {
	const handlers = new Map<string, EventHandler>(Object.entries(config.handlers ?? {}));
	const replay = config.replayStorage ?? memoryStorage();
	const replayTtl = config.replayTtlSeconds ?? 86_400;
	const maxAge = config.maxAgeSeconds ?? 3600;
	const encoder = new TextEncoder();

	let cachedJwks: { keys: JWK[]; at: number } | null = null;

	async function discoverJwks(force: boolean): Promise<JWK[] | null> {
		const now = Date.now();
		if (
			cachedJwks &&
			now - cachedJwks.at < DISCOVERY_TTL_MS &&
			!(force && now - cachedJwks.at >= MIN_REFETCH_MS)
		) {
			return cachedJwks.keys;
		}
		const configUrl =
			config.configurationUrl ??
			`${config.issuer.replace(/\/+$/, "")}/.well-known/ssf-configuration`;
		const meta = await safeFetchJson(configUrl, { maxBytes: 64 * 1024, ...config.fetchOptions });
		if (!meta.ok || typeof meta.json !== "object" || meta.json === null)
			return cachedJwks?.keys ?? null;
		const record = meta.json as { issuer?: unknown; jwks_uri?: unknown };
		// The metadata must describe the issuer we were configured for.
		if (record.issuer !== config.issuer || typeof record.jwks_uri !== "string") {
			return cachedJwks?.keys ?? null;
		}
		const doc = await safeFetchJson(record.jwks_uri, {
			maxBytes: 64 * 1024,
			...config.fetchOptions,
		});
		if (!doc.ok || typeof doc.json !== "object" || doc.json === null)
			return cachedJwks?.keys ?? null;
		const keys = (doc.json as { keys?: unknown }).keys;
		if (!Array.isArray(keys) || keys.length === 0) return cachedJwks?.keys ?? null;
		cachedJwks = { keys: keys as JWK[], at: now };
		return cachedJwks.keys;
	}

	const getKey: JWTVerifyGetKey = async (header, token) => {
		if (config.verificationKey) {
			const key = config.verificationKey;
			if (typeof key === "function") return key(header, token);
			return key;
		}
		if (config.jwks) return createLocalJWKSet(config.jwks)(header, token);
		let keys = await discoverJwks(false);
		if (!keys) throw new Error("signing keys could not be discovered");
		const kid = header.kid;
		if (kid && !keys.some((k) => k.kid === kid)) {
			// Unknown kid: the transmitter may have rotated. Refetch, rate limited.
			keys = (await discoverJwks(true)) ?? keys;
		}
		return createLocalJWKSet({ keys })(header, token);
	};

	async function dispatch(token: SecurityEventToken): Promise<string[]> {
		const seen: string[] = [];
		for (const [type, raw] of Object.entries(token.events)) {
			seen.push(type);
			if (type === VERIFICATION_EVENT) {
				const state = typeof raw.state === "string" ? raw.state : undefined;
				await config.onVerification?.(state);
				continue;
			}
			const subject = parseSubject(raw.subject) ?? token.sub_id ?? null;
			const ts = typeof raw.event_timestamp === "number" ? raw.event_timestamp : null;
			const event: ReceivedEvent = { type, payload: raw, subject, eventTimestamp: ts, token };
			const handler = handlers.get(type) ?? config.onUnhandled;
			if (handler) await handler(event);
		}
		return seen;
	}

	async function receive(jwt: string): Promise<ReceiveResult> {
		const verified = await verifySet(jwt, {
			issuer: config.issuer,
			audience: config.audience,
			key: getKey,
			algorithms: config.algorithms,
			maxAgeSeconds: maxAge,
		});
		if (!verified.ok) return { ok: false, err: verified.code, description: verified.message };
		const token = verified.value;
		// First sighting wins: the counter is 1 only for the first caller.
		const replayKey = `ssf:jti:${config.issuer}:${token.jti}`;
		const seen = await replay.incr(replayKey, replayTtl);
		if (seen.count > 1) {
			// A duplicate is acknowledged so the transmitter stops retrying.
			return { ok: true, value: { jti: token.jti, events: Object.keys(token.events) } };
		}
		try {
			const events = await dispatch(token);
			return { ok: true, value: { jti: token.jti, events } };
		} catch (err) {
			// Let the transmitter redeliver: forget the jti.
			await replay.delete(replayKey);
			throw err;
		}
	}

	async function handleRequest(request: Request): Promise<Response> {
		if (request.method !== "POST") {
			return new Response(null, { status: 405, headers: { Allow: "POST" } });
		}
		if (config.authorizationHeader) {
			const given = request.headers.get("authorization") ?? "";
			if (!constantTimeEqual(encoder.encode(given), encoder.encode(config.authorizationHeader))) {
				return jsonResponse(401, { err: "authentication_failed", description: "bad credentials" });
			}
		}
		const type = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
		if (type !== SET_MEDIA_TYPE) {
			return jsonResponse(400, {
				err: "invalid_request",
				description: `Content-Type must be ${SET_MEDIA_TYPE}`,
			});
		}
		const body = (await request.text()).trim();
		if (!body || body.length > 64 * 1024) {
			return jsonResponse(400, { err: "invalid_request", description: "missing or oversized SET" });
		}
		try {
			const result = await receive(body);
			if (!result.ok) {
				return jsonResponse(400, { err: result.err, description: result.description });
			}
			return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
		} catch {
			return jsonResponse(500, {
				err: "server_error",
				description: "event could not be processed",
			});
		}
	}

	async function receivePolled(sets: Record<string, string>) {
		const ack: string[] = [];
		const errs = new Map<string, { err: string; description: string }>();
		for (const [jti, jwt] of Object.entries(sets)) {
			try {
				const result = await receive(jwt);
				if (result.ok) ack.push(jti);
				else errs.set(jti, { err: result.err, description: result.description });
			} catch {
				errs.set(jti, { err: "server_error", description: "event could not be processed" });
			}
		}
		return { ack, setErrs: Object.fromEntries(errs) };
	}

	return {
		receive,
		handleRequest,
		receivePolled,
		on(type, handler) {
			handlers.set(type, handler);
		},
	};
}
