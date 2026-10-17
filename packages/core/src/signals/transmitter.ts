/** Shared Signals transmitter: stream management, SET creation, push delivery with retry, and the poll queue. HTTP wiring lives in `transmitter-endpoints.ts`. */

import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import type { DnsResolver } from "../mcp/safe-fetch.js";
import { backoffMs, pushSet, validateDeliveryUrl } from "./delivery.js";
import type { SigningKey } from "./set.js";
import { signSet } from "./set.js";
import type { SignalsStore } from "./store.js";
import { createSignalsStore } from "./store.js";
import { candidateKeys } from "./subjects.js";
import type {
	DeliveryMethod,
	EventPayload,
	OutboxRow,
	Result,
	StoredStream,
	StreamConfiguration,
	StreamStatus,
	SubjectIdentifier,
} from "./types.js";
import {
	DELIVERY_POLL,
	DELIVERY_PUSH,
	SSF_VERIFICATION_EVENT,
	SUPPORTED_EVENT_TYPES,
} from "./types.js";

export interface TransmitterDeliveryConfig {
	/** Attempts before a push SET is marked failed. Default 5. */
	maxAttempts?: number;
	/** First retry delay. Default 1000 ms, doubling up to `maxBackoffMs`. */
	baseBackoffMs?: number;
	/** Default 300000 ms. */
	maxBackoffMs?: number;
	/** Per request timeout. Default 5000 ms. */
	timeoutMs?: number;
	/**
	 * `background` (default) returns from `emit` once SETs are stored and runs delivery in the background. `inline` awaits delivery and retries. Serverless runtimes that freeze after the response should use `inline` or call `processDue()` from a scheduled job.
	 */
	mode?: "background" | "inline";
	fetchImpl?: typeof fetch;
	resolver?: DnsResolver;
	/** Development only: allow http and private hosts for push endpoints. */
	allowInsecure?: boolean;
	/** Override the wait between retries (tests). */
	sleep?: (ms: number) => Promise<void>;
}

export interface TransmitterConfig {
	db: Database;
	/** SET and metadata issuer. */
	issuer: string;
	/** Absolute base URL the endpoints are mounted at. Default `${issuer}/ssf`. */
	endpointBaseUrl?: string;
	signingKey: SigningKey;
	/** JWS algorithm of the signing key. Default `RS256`. */
	signingAlgorithm?: string;
	/** `kid` placed in SET headers. Default `theauth-ssf-1`. */
	keyId?: string;
	/** Where receivers fetch the public key. Default `${issuer}/.well-known/jwks.json`. */
	jwksUri?: string;
	/** Authenticate a management or poll request. Return a stable id for the receiver (used as stream owner and default audience) or null to refuse. */
	authenticate: (request: Request) => Promise<{ id: string } | null>;
	/** Event types this transmitter will deliver. Default: all CAEP and RISC types. */
	eventsSupported?: string[];
	/** Default subject mode for new streams. Default `ALL`. */
	defaultSubjects?: "ALL" | "NONE";
	/** Seconds between verification requests per stream. Default 0 (no limit). */
	minVerificationInterval?: number;
	/** Long poll wait for `returnImmediately: false`. Default 0 (answer at once). */
	longPollMs?: number;
	delivery?: TransmitterDeliveryConfig;
	store?: SignalsStore;
}

export interface EmitInput {
	/** Event type URI. */
	type: string;
	/** Event specific claims. */
	payload?: EventPayload;
	subject: SubjectIdentifier;
	/** Seconds since epoch. Default now. */
	eventTimestamp?: number;
	txn?: string;
}

export interface EmitResult {
	/** jti values stored, one per matching stream. */
	queued: string[];
}

export interface CreateStreamInput {
	owner: string;
	eventsRequested: string[];
	delivery: { method: DeliveryMethod; endpoint_url?: string; authorization_header?: string };
	aud?: string[];
	description?: string;
	minVerificationInterval?: number;
}

export interface Transmitter {
	readonly config: TransmitterConfig;
	readonly store: SignalsStore;
	readonly eventsSupported: string[];
	readonly endpointBaseUrl: string;
	metadata(): Record<string, unknown>;
	toConfiguration(stream: StoredStream): StreamConfiguration;
	createStream(input: CreateStreamInput): Promise<Result<StoredStream>>;
	updateStream(
		stream: StoredStream,
		patch: Partial<Omit<CreateStreamInput, "owner">>,
	): Promise<Result<StoredStream>>;
	setStatus(stream: StoredStream, status: StreamStatus, reason?: string): Promise<void>;
	/** Send a verification event (SSF 8.1.4.1). */
	verify(stream: StoredStream, state?: string): Promise<Result<{ jti: string }>>;
	emit(input: EmitInput): Promise<EmitResult>;
	/** Retry due push SETs once each. Safe to call from a scheduler. */
	processDue(limit?: number): Promise<{ attempted: number; delivered: number; failed: number }>;
	/** Take pending SETs of a poll stream. */
	poll(
		stream: StoredStream,
		opts: {
			maxEvents?: number;
			ack?: string[];
			setErrs?: Record<string, { err: string; description?: string }>;
			returnImmediately?: boolean;
		},
	): Promise<{ sets: Record<string, string>; moreAvailable: boolean }>;
}

const DEFAULT_ALG = "RS256";

export function createTransmitter(config: TransmitterConfig): Transmitter {
	const store = config.store ?? createSignalsStore(config.db);
	const alg = config.signingAlgorithm ?? DEFAULT_ALG;
	const kid = config.keyId ?? "theauth-ssf-1";
	const eventsSupported = config.eventsSupported ?? [...SUPPORTED_EVENT_TYPES];
	const endpointBaseUrl = (config.endpointBaseUrl ?? `${config.issuer}/ssf`).replace(/\/+$/, "");
	const d = config.delivery ?? {};
	const maxAttempts = d.maxAttempts ?? 5;
	const sleep = d.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const inFlight = new Set<string>();
	const guard = { resolver: d.resolver, allowInsecure: d.allowInsecure };

	function pollUrl(streamId: string): string {
		return `${endpointBaseUrl}/poll/${encodeURIComponent(streamId)}`;
	}

	function metadata(): Record<string, unknown> {
		return {
			spec_version: "1_0",
			issuer: config.issuer,
			jwks_uri: config.jwksUri ?? `${config.issuer}/.well-known/jwks.json`,
			delivery_methods_supported: [DELIVERY_PUSH, DELIVERY_POLL],
			configuration_endpoint: `${endpointBaseUrl}/stream`,
			status_endpoint: `${endpointBaseUrl}/status`,
			add_subject_endpoint: `${endpointBaseUrl}/subjects/add`,
			remove_subject_endpoint: `${endpointBaseUrl}/subjects/remove`,
			verification_endpoint: `${endpointBaseUrl}/verify`,
			critical_subject_members: [],
			default_subjects: config.defaultSubjects ?? "ALL",
		};
	}

	function toConfiguration(s: StoredStream): StreamConfiguration {
		return {
			stream_id: s.id,
			iss: config.issuer,
			aud: s.aud,
			events_supported: eventsSupported,
			events_requested: s.eventsRequested,
			events_delivered: s.eventsDelivered,
			delivery: {
				method: s.deliveryMethod,
				endpoint_url:
					s.deliveryMethod === DELIVERY_POLL ? pollUrl(s.id) : (s.endpointUrl ?? undefined),
			},
			...(s.minVerificationInterval !== null
				? { min_verification_interval: s.minVerificationInterval }
				: {}),
			...(s.description ? { description: s.description } : {}),
		};
	}

	async function checkDelivery(delivery: CreateStreamInput["delivery"]): Promise<string | null> {
		if (delivery.method !== DELIVERY_PUSH && delivery.method !== DELIVERY_POLL) {
			return "unsupported delivery method";
		}
		if (delivery.method === DELIVERY_PUSH) {
			if (!delivery.endpoint_url) return "push delivery needs endpoint_url";
			const checked = await validateDeliveryUrl(delivery.endpoint_url, guard);
			if (!checked.ok) return `endpoint_url rejected: ${checked.message}`;
		}
		return null;
	}

	function delivered(requested: string[]): string[] {
		return requested.filter((e) => eventsSupported.includes(e));
	}

	async function createStream(input: CreateStreamInput): Promise<Result<StoredStream>> {
		const problem = await checkDelivery(input.delivery);
		if (problem) return { ok: false, code: "invalid_request", message: problem };
		const stream = await store.createStream({
			id: generateId(),
			owner: input.owner,
			aud: input.aud && input.aud.length > 0 ? input.aud : [input.owner],
			eventsRequested: input.eventsRequested,
			eventsDelivered: delivered(input.eventsRequested),
			deliveryMethod: input.delivery.method,
			endpointUrl:
				input.delivery.method === DELIVERY_PUSH ? (input.delivery.endpoint_url ?? null) : null,
			authorizationHeader: input.delivery.authorization_header ?? null,
			status: "enabled",
			statusReason: null,
			subjectMode: (config.defaultSubjects ?? "ALL") === "ALL" ? "all" : "none",
			description: input.description ?? null,
			minVerificationInterval:
				input.minVerificationInterval ?? config.minVerificationInterval ?? null,
		});
		return { ok: true, value: stream };
	}

	async function updateStream(
		stream: StoredStream,
		patch: Partial<Omit<CreateStreamInput, "owner">>,
	): Promise<Result<StoredStream>> {
		const next: Partial<StoredStream> = {};
		if (patch.delivery) {
			const problem = await checkDelivery(patch.delivery);
			if (problem) return { ok: false, code: "invalid_request", message: problem };
			next.deliveryMethod = patch.delivery.method;
			next.endpointUrl =
				patch.delivery.method === DELIVERY_PUSH ? (patch.delivery.endpoint_url ?? null) : null;
			next.authorizationHeader = patch.delivery.authorization_header ?? null;
		}
		if (patch.eventsRequested) {
			next.eventsRequested = patch.eventsRequested;
			next.eventsDelivered = delivered(patch.eventsRequested);
		}
		if (patch.description !== undefined) next.description = patch.description;
		if (patch.minVerificationInterval !== undefined) {
			next.minVerificationInterval = patch.minVerificationInterval;
		}
		await store.updateStream(stream.id, next);
		const fresh = await store.getStream(stream.id);
		if (!fresh) return { ok: false, code: "not_found", message: "stream not found" };
		return { ok: true, value: fresh };
	}

	async function attempt(
		row: OutboxRow,
		stream: StoredStream,
	): Promise<{ result: "delivered" | "failed" | "retry"; waitMs: number }> {
		const outcome = await pushSet(stream.endpointUrl ?? "", row.jwt, {
			authorizationHeader: stream.authorizationHeader,
			fetchImpl: d.fetchImpl,
			timeoutMs: d.timeoutMs,
			...guard,
		});
		const attempts = row.attempts + 1;
		if (outcome.kind === "delivered") {
			await store.updateOutbox(row.jti, { status: "delivered", attempts, lastError: null });
			return { result: "delivered", waitMs: 0 };
		}
		if (outcome.kind === "permanent" || attempts >= maxAttempts) {
			await store.updateOutbox(row.jti, { status: "failed", attempts, lastError: outcome.message });
			return { result: "failed", waitMs: 0 };
		}
		const wait = backoffMs(attempts, { baseMs: d.baseBackoffMs, maxMs: d.maxBackoffMs });
		await store.updateOutbox(row.jti, {
			attempts,
			lastError: outcome.message,
			nextAttemptAt: new Date(Date.now() + wait),
		});
		return { result: "retry", waitMs: wait };
	}

	/** Deliver one SET, sleeping between retries. */
	async function deliverWithRetries(jti: string): Promise<void> {
		if (inFlight.has(jti)) return;
		inFlight.add(jti);
		try {
			for (;;) {
				const row = await store.getOutbox(jti);
				if (!row || row.status !== "pending") return;
				const stream = await store.getStream(row.streamId);
				if (!stream || stream.status !== "enabled" || stream.deliveryMethod !== DELIVERY_PUSH)
					return;
				const { result, waitMs } = await attempt(row, stream);
				if (result !== "retry") return;
				await sleep(waitMs);
			}
		} finally {
			inFlight.delete(jti);
		}
	}

	function schedule(jti: string): Promise<void> {
		const run = deliverWithRetries(jti).catch(() => undefined);
		return d.mode === "inline" ? run : Promise.resolve();
	}

	async function processDue(limit = 100) {
		const rows = await store.listDue(new Date(), limit);
		let attempted = 0;
		let deliveredCount = 0;
		let failed = 0;
		for (const row of rows) {
			if (inFlight.has(row.jti)) continue;
			const stream = await store.getStream(row.streamId);
			if (!stream || stream.status !== "enabled" || stream.deliveryMethod !== DELIVERY_PUSH)
				continue;
			inFlight.add(row.jti);
			try {
				attempted += 1;
				const { result } = await attempt(row, stream);
				if (result === "delivered") deliveredCount += 1;
				if (result === "failed") failed += 1;
			} finally {
				inFlight.delete(row.jti);
			}
		}
		return { attempted, delivered: deliveredCount, failed };
	}

	async function enqueueFor(
		stream: StoredStream,
		events: Record<string, EventPayload>,
		extra: { subId?: SubjectIdentifier; txn?: string },
	): Promise<string> {
		const jti = generateId();
		const jwt = await signSet({
			issuer: config.issuer,
			audience: stream.aud.length === 1 ? (stream.aud[0] as string) : stream.aud,
			events,
			signingKey: config.signingKey,
			alg,
			kid,
			jti,
			...(extra.subId ? { subId: extra.subId } : {}),
			...(extra.txn ? { txn: extra.txn } : {}),
		});
		await store.enqueue({ jti, streamId: stream.id, jwt, nextAttemptAt: new Date() });
		return jti;
	}

	async function streamWantsSubject(
		stream: StoredStream,
		subject: SubjectIdentifier,
	): Promise<boolean> {
		const listed = await store.hasAnySubject(stream.id, candidateKeys(subject));
		return stream.subjectMode === "all" ? !listed : listed;
	}

	async function emit(input: EmitInput): Promise<EmitResult> {
		const queued: string[] = [];
		const timestamp = input.eventTimestamp ?? Math.floor(Date.now() / 1000);
		const streams = await store.listActiveStreams();
		const pending: Promise<void>[] = [];
		for (const stream of streams) {
			if (!stream.eventsDelivered.includes(input.type)) continue;
			if (!(await streamWantsSubject(stream, input.subject))) continue;
			const jti = await enqueueFor(
				stream,
				{
					[input.type]: {
						...(input.payload ?? {}),
						subject: input.subject,
						event_timestamp: timestamp,
					},
				},
				{ txn: input.txn },
			);
			queued.push(jti);
			if (stream.status === "enabled" && stream.deliveryMethod === DELIVERY_PUSH) {
				pending.push(schedule(jti));
			}
		}
		await Promise.all(pending);
		return { queued };
	}

	async function verify(stream: StoredStream, state?: string): Promise<Result<{ jti: string }>> {
		if (stream.status === "disabled") {
			return { ok: false, code: "invalid_request", message: "stream is disabled" };
		}
		const interval = stream.minVerificationInterval ?? 0;
		if (interval > 0 && stream.lastVerifiedAt) {
			const elapsed = (Date.now() - stream.lastVerifiedAt.getTime()) / 1000;
			if (elapsed < interval) {
				return { ok: false, code: "too_many_requests", message: "verification requested too soon" };
			}
		}
		await store.updateStream(stream.id, { lastVerifiedAt: new Date() });
		const jti = await enqueueFor(
			stream,
			{ [SSF_VERIFICATION_EVENT]: state !== undefined ? { state } : {} },
			{},
		);
		if (stream.status === "enabled" && stream.deliveryMethod === DELIVERY_PUSH) await schedule(jti);
		return { ok: true, value: { jti } };
	}

	async function setStatus(stream: StoredStream, status: StreamStatus, reason?: string) {
		await store.updateStream(stream.id, { status, statusReason: reason ?? null });
		if (status === "enabled" && stream.deliveryMethod === DELIVERY_PUSH) {
			const pending = await store.listPending(stream.id, 1000);
			await Promise.all(pending.map((row) => schedule(row.jti)));
		}
		if (status === "disabled") {
			// A disabled stream drops what it has not delivered.
			const pending = await store.listPending(stream.id, 1000);
			for (const row of pending) {
				await store.updateOutbox(row.jti, { status: "failed", lastError: "stream disabled" });
			}
		}
	}

	async function poll(
		stream: StoredStream,
		opts: {
			maxEvents?: number;
			ack?: string[];
			setErrs?: Record<string, { err: string; description?: string }>;
			returnImmediately?: boolean;
		},
	) {
		if (opts.ack && opts.ack.length > 0) await store.ack(stream.id, opts.ack);
		if (opts.setErrs) {
			for (const [jti, err] of Object.entries(opts.setErrs)) {
				const row = await store.getOutbox(jti);
				if (row && row.streamId === stream.id) {
					await store.updateOutbox(jti, { status: "failed", lastError: `receiver: ${err.err}` });
				}
			}
		}
		const max = Math.min(Math.max(opts.maxEvents ?? 100, 0), 1000);
		const read = async () =>
			stream.status === "enabled" ? store.listPending(stream.id, max + 1) : [];
		let rows = await read();
		const wait = opts.returnImmediately === false ? (config.longPollMs ?? 0) : 0;
		const deadline = Date.now() + wait;
		while (rows.length === 0 && max > 0 && Date.now() < deadline) {
			await sleep(Math.min(250, Math.max(0, deadline - Date.now())));
			rows = await read();
		}
		const page = rows.slice(0, max);
		const sets = Object.fromEntries(page.map((row) => [row.jti, row.jwt]));
		return { sets, moreAvailable: rows.length > page.length };
	}

	return {
		config,
		store,
		eventsSupported,
		endpointBaseUrl,
		metadata,
		toConfiguration,
		createStream,
		updateStream,
		setStatus,
		verify,
		emit,
		processDue,
		poll,
	};
}
