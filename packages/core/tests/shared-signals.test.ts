import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	createDefaultHandlers,
	createEmissionBridge,
	createReceiver,
	events,
	parseSubject,
	sharedSignals,
	signSet,
	subjectKey,
	verifySet,
} from "../src/signals/index.js";
import {
	CAEP_SESSION_REVOKED,
	RISC_ACCOUNT_DISABLED,
	RISC_SESSIONS_REVOKED,
	SSF_VERIFICATION_EVENT,
} from "../src/signals/types.js";
import { createTheAuth } from "../src/theauth.js";

const ISS = "https://idp.example";
const PUBLIC_IP = async () => ["93.184.216.34"];

let keys: { privateKey: CryptoKey; publicKey: CryptoKey };

beforeAll(async () => {
	keys = (await generateKeyPair("ES256")) as typeof keys;
});

const subject = { format: "iss_sub", iss: ISS, sub: "user-1" } as const;

async function sign(overrides: Partial<Parameters<typeof signSet>[0]> = {}): Promise<string> {
	return signSet({
		issuer: ISS,
		audience: "https://rp.example",
		events: { [RISC_SESSIONS_REVOKED]: { subject, event_timestamp: 1 } },
		signingKey: keys.privateKey,
		alg: "ES256",
		kid: "k1",
		...overrides,
	});
}

describe("SET signing and verification", () => {
	const verifyOpts = () => ({
		issuer: ISS,
		audience: "https://rp.example",
		key: keys.publicKey,
		algorithms: ["ES256"],
	});

	it("round trips with typ secevent+jwt and no exp", async () => {
		const jwt = await sign({ jti: "j1" });
		const header = JSON.parse(Buffer.from(jwt.split(".")[0] as string, "base64url").toString());
		expect(header.typ).toBe("secevent+jwt");
		const claims = JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString());
		expect(claims.exp).toBeUndefined();
		const result = await verifySet(jwt, verifyOpts());
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.jti).toBe("j1");
			expect(Object.keys(result.value.events)).toEqual([RISC_SESSIONS_REVOKED]);
		}
	});

	it("rejects a tampered payload", async () => {
		const jwt = await sign();
		const [h, p, s] = jwt.split(".") as [string, string, string];
		const claims = JSON.parse(Buffer.from(p, "base64url").toString());
		claims.events[RISC_SESSIONS_REVOKED].subject.sub = "victim";
		const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
		const result = await verifySet(forged, verifyOpts());
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("invalid_key");
	});

	it("rejects wrong audience, wrong issuer and wrong typ", async () => {
		const aud = await verifySet(await sign({ audience: "https://other" }), verifyOpts());
		expect(!aud.ok && aud.code).toBe("invalid_audience");
		const iss = await verifySet(await sign({ issuer: "https://evil.example" }), verifyOpts());
		expect(!iss.ok && iss.code).toBe("invalid_issuer");
		const plain = await new SignJWT({ events: { [RISC_SESSIONS_REVOKED]: {} } })
			.setProtectedHeader({ alg: "ES256", typ: "JWT" })
			.setIssuer(ISS)
			.setAudience("https://rp.example")
			.setIssuedAt()
			.setJti("x")
			.sign(keys.privateKey);
		const typ = await verifySet(plain, verifyOpts());
		expect(!typ.ok && typ.code).toBe("invalid_request");
	});

	it("rejects a SET signed by another key", async () => {
		const other = await generateKeyPair("ES256");
		const jwt = await sign({ signingKey: other.privateKey });
		const result = await verifySet(jwt, verifyOpts());
		expect(result.ok).toBe(false);
	});
});

describe("subjects", () => {
	it("validates the four formats and rejects junk", () => {
		expect(parseSubject({ format: "iss_sub", iss: ISS, sub: "a" })).not.toBeNull();
		expect(parseSubject({ format: "email", email: "a@b.c" })).not.toBeNull();
		expect(parseSubject({ format: "opaque", id: "x" })).not.toBeNull();
		expect(
			parseSubject({
				format: "complex",
				user: { format: "opaque", id: "u" },
				session: { format: "opaque", id: "s" },
			}),
		).not.toBeNull();
		expect(parseSubject({ format: "email", email: "nope" })).toBeNull();
		expect(parseSubject({ format: "complex" })).toBeNull();
		expect(parseSubject({ format: "other" })).toBeNull();
		expect(parseSubject("x")).toBeNull();
	});

	it("compares email case-insensitively", () => {
		expect(subjectKey({ format: "email", email: "A@B.C" })).toBe(
			subjectKey({ format: "email", email: "a@b.c" }),
		);
	});
});

type Fetch = typeof fetch;

async function makeTransmitter(
	opts: {
		fetchImpl?: Fetch;
		resolver?: () => Promise<string[]>;
		maxAttempts?: number;
		sleep?: (ms: number) => Promise<void>;
		defaultSubjects?: "ALL" | "NONE";
		minVerificationInterval?: number;
	} = {},
) {
	const plugin = sharedSignals({
		transmitter: {
			issuer: ISS,
			signingKey: keys.privateKey,
			signingAlgorithm: "ES256",
			keyId: "k1",
			defaultSubjects: opts.defaultSubjects,
			minVerificationInterval: opts.minVerificationInterval,
			authenticate: async (request) => {
				const header = request.headers.get("authorization");
				if (header === "Bearer rx1") return { id: "https://rp.example" };
				if (header === "Bearer rx2") return { id: "https://other.example" };
				return null;
			},
			delivery: {
				mode: "inline",
				maxAttempts: opts.maxAttempts ?? 4,
				baseBackoffMs: 10,
				sleep: opts.sleep ?? (async () => undefined),
				fetchImpl: opts.fetchImpl,
				resolver: opts.resolver ?? PUBLIC_IP,
			},
		},
	});
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		plugins: [plugin],
	});
	const call = async (method: string, path: string, body?: unknown, token = "rx1") => {
		const res = await auth.plugins.handleRequest(
			new Request(`${ISS}${path}`, {
				method,
				headers: {
					"content-type": "application/json",
					...(token ? { authorization: `Bearer ${token}` } : {}),
				},
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
		);
		if (!res) throw new Error(`no route for ${method} ${path}`);
		return res;
	};
	return { plugin, auth, call };
}

const verifyForRp = (jwt: string) =>
	verifySet(jwt, { issuer: ISS, audience: "https://rp.example", key: keys.publicKey });

describe("transmitter: configuration and streams", () => {
	it("serves discovery metadata", async () => {
		const { call } = await makeTransmitter();
		const res = await call("GET", "/.well-known/ssf-configuration", undefined, "");
		expect(res.status).toBe(200);
		const doc = await res.json();
		expect(doc.issuer).toBe(ISS);
		expect(doc.delivery_methods_supported).toContain("urn:ietf:rfc:8936");
		expect(doc.configuration_endpoint).toBe(`${ISS}/ssf/stream`);
	});

	it("requires authentication and hides other receivers' streams", async () => {
		const { call } = await makeTransmitter();
		const anon = await call(
			"POST",
			"/ssf/stream",
			{ events_requested: [], delivery: { method: "urn:ietf:rfc:8936" } },
			"",
		);
		expect(anon.status).toBe(401);
		const created = await call("POST", "/ssf/stream", {
			events_requested: [RISC_SESSIONS_REVOKED, "https://example.com/unknown"],
			delivery: { method: "urn:ietf:rfc:8936" },
		});
		expect(created.status).toBe(201);
		const stream = await created.json();
		expect(stream.events_delivered).toEqual([RISC_SESSIONS_REVOKED]);
		expect(stream.delivery.endpoint_url).toBe(`${ISS}/ssf/poll/${stream.stream_id}`);
		const foreign = await call(
			"GET",
			`/ssf/stream?stream_id=${stream.stream_id}`,
			undefined,
			"rx2",
		);
		expect(foreign.status).toBe(404);
		const mine = await call("GET", `/ssf/stream?stream_id=${stream.stream_id}`);
		expect(mine.status).toBe(200);
	});

	it("supports update and delete", async () => {
		const { call } = await makeTransmitter();
		const stream = await (
			await call("POST", "/ssf/stream", {
				events_requested: [RISC_SESSIONS_REVOKED],
				delivery: { method: "urn:ietf:rfc:8936" },
			})
		).json();
		const patched = await call("PATCH", "/ssf/stream", {
			stream_id: stream.stream_id,
			events_requested: [RISC_ACCOUNT_DISABLED],
			description: "d",
		});
		expect((await patched.json()).events_delivered).toEqual([RISC_ACCOUNT_DISABLED]);
		expect((await call("DELETE", `/ssf/stream?stream_id=${stream.stream_id}`)).status).toBe(204);
		expect((await call("GET", `/ssf/stream?stream_id=${stream.stream_id}`)).status).toBe(404);
	});

	it("rejects SSRF push endpoints at configuration time", async () => {
		const priv = await makeTransmitter({ resolver: async () => ["10.0.0.5"] });
		const res = await priv.call("POST", "/ssf/stream", {
			events_requested: [RISC_SESSIONS_REVOKED],
			delivery: { method: "urn:ietf:rfc:8935", endpoint_url: "https://internal.example/hook" },
		});
		expect(res.status).toBe(400);
		const { call } = await makeTransmitter();
		for (const url of [
			"http://rp.example/hook",
			"https://localhost/hook",
			"https://169.254.169.254/latest",
			"https://user:pw@rp.example/hook",
			"https://rp.example:8443/hook",
		]) {
			const r = await call("POST", "/ssf/stream", {
				events_requested: [RISC_SESSIONS_REVOKED],
				delivery: { method: "urn:ietf:rfc:8935", endpoint_url: url },
			});
			expect(r.status, url).toBe(400);
		}
	});
});

describe("transmitter: poll delivery", () => {
	async function pollStream(h: Awaited<ReturnType<typeof makeTransmitter>>) {
		const res = await h.call("POST", "/ssf/stream", {
			events_requested: [RISC_SESSIONS_REVOKED, CAEP_SESSION_REVOKED],
			delivery: { method: "urn:ietf:rfc:8936" },
		});
		return (await res.json()) as { stream_id: string };
	}

	it("queues events, returns them, and drops them on ack", async () => {
		const h = await makeTransmitter();
		const stream = await pollStream(h);
		const a = await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		const b = await h.plugin.emit({ ...events.sessionRevoked(), subject });
		expect(a.queued).toHaveLength(1);

		const first = await (
			await h.call("POST", `/ssf/poll/${stream.stream_id}`, { maxEvents: 1 })
		).json();
		expect(Object.keys(first.sets)).toHaveLength(1);
		expect(first.moreAvailable).toBe(true);
		const [jti, jwt] = Object.entries(first.sets)[0] as [string, string];
		const verified = await verifyForRp(jwt);
		expect(verified.ok).toBe(true);
		if (verified.ok) {
			const payload = verified.value.events[RISC_SESSIONS_REVOKED];
			expect(payload?.subject).toEqual(subject);
			expect(typeof payload?.event_timestamp).toBe("number");
		}

		// Unacked SETs are served again.
		const again = await (
			await h.call("POST", `/ssf/poll/${stream.stream_id}`, { maxEvents: 10 })
		).json();
		expect(Object.keys(again.sets)).toHaveLength(2);

		const acked = await (
			await h.call("POST", `/ssf/poll/${stream.stream_id}`, { ack: [jti], maxEvents: 10 })
		).json();
		expect(Object.keys(acked.sets)).toHaveLength(1);
		expect(acked.sets[jti]).toBeUndefined();
		expect(acked.moreAvailable).toBe(false);
		expect(b.queued).toHaveLength(1);
	});

	it("honors the subject list in ALL and NONE modes", async () => {
		const all = await makeTransmitter();
		const s1 = await pollStream(all);
		await all.call("POST", "/ssf/subjects/remove", { stream_id: s1.stream_id, subject });
		await all.plugin.emit({ ...events.sessionsRevoked(), subject });
		const r1 = await (await all.call("POST", `/ssf/poll/${s1.stream_id}`, {})).json();
		expect(Object.keys(r1.sets)).toHaveLength(0);
		await all.call("POST", "/ssf/subjects/add", { stream_id: s1.stream_id, subject });
		await all.plugin.emit({ ...events.sessionsRevoked(), subject });
		const r2 = await (await all.call("POST", `/ssf/poll/${s1.stream_id}`, {})).json();
		expect(Object.keys(r2.sets)).toHaveLength(1);

		const none = await makeTransmitter({ defaultSubjects: "NONE" });
		const s2 = await pollStream(none);
		await none.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(
			Object.keys((await (await none.call("POST", `/ssf/poll/${s2.stream_id}`, {})).json()).sets),
		).toHaveLength(0);
		await none.call("POST", "/ssf/subjects/add", { stream_id: s2.stream_id, subject });
		await none.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(
			Object.keys((await (await none.call("POST", `/ssf/poll/${s2.stream_id}`, {})).json()).sets),
		).toHaveLength(1);
	});

	it("matches a complex subject through its user member", async () => {
		const h = await makeTransmitter({ defaultSubjects: "NONE" });
		const s = await pollStream(h);
		await h.call("POST", "/ssf/subjects/add", { stream_id: s.stream_id, subject });
		await h.plugin.emit({
			...events.sessionRevoked(),
			subject: { format: "complex", user: subject, session: { format: "opaque", id: "sess-1" } },
		});
		const r = await (await h.call("POST", `/ssf/poll/${s.stream_id}`, {})).json();
		expect(Object.keys(r.sets)).toHaveLength(1);
	});

	it("holds events while paused and releases them when enabled", async () => {
		const h = await makeTransmitter();
		const s = await pollStream(h);
		const paused = await h.call("POST", "/ssf/status", {
			stream_id: s.stream_id,
			status: "paused",
		});
		expect((await paused.json()).status).toBe("paused");
		await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(
			Object.keys((await (await h.call("POST", `/ssf/poll/${s.stream_id}`, {})).json()).sets),
		).toHaveLength(0);
		await h.call("POST", "/ssf/status", { stream_id: s.stream_id, status: "enabled" });
		expect(
			Object.keys((await (await h.call("POST", `/ssf/poll/${s.stream_id}`, {})).json()).sets),
		).toHaveLength(1);
		const status = await (await h.call("GET", `/ssf/status?stream_id=${s.stream_id}`)).json();
		expect(status.status).toBe("enabled");
	});

	it("delivers a verification event with the state and rate limits it", async () => {
		const h = await makeTransmitter({ minVerificationInterval: 3600 });
		const s = await pollStream(h);
		const res = await h.call("POST", "/ssf/verify", { stream_id: s.stream_id, state: "abc" });
		expect(res.status).toBe(204);
		const polled = await (await h.call("POST", `/ssf/poll/${s.stream_id}`, {})).json();
		const jwt = Object.values(polled.sets)[0] as string;
		const verified = await verifyForRp(jwt);
		expect(verified.ok && verified.value.events[SSF_VERIFICATION_EVENT]).toEqual({ state: "abc" });
		const again = await h.call("POST", "/ssf/verify", { stream_id: s.stream_id, state: "abc" });
		expect(again.status).toBe(429);
	});

	it("does not deliver events the stream did not request", async () => {
		const h = await makeTransmitter();
		const s = await pollStream(h);
		const r = await h.plugin.emit({ ...events.accountDisabled(), subject });
		expect(r.queued).toHaveLength(0);
		expect(
			Object.keys((await (await h.call("POST", `/ssf/poll/${s.stream_id}`, {})).json()).sets),
		).toHaveLength(0);
	});
});

describe("transmitter: push delivery", () => {
	const pushBody = {
		events_requested: [RISC_SESSIONS_REVOKED],
		delivery: {
			method: "urn:ietf:rfc:8935",
			endpoint_url: "https://rp.example/ssf/receive",
			authorization_header: "Bearer secret",
		},
	};

	it("POSTs the SET with the right headers", async () => {
		const seen: Array<{ url: string; headers: Headers; body: string }> = [];
		const fetchImpl = (async (url: string, init: RequestInit) => {
			seen.push({ url, headers: new Headers(init.headers), body: String(init.body) });
			return new Response(null, { status: 202 });
		}) as unknown as Fetch;
		const h = await makeTransmitter({ fetchImpl });
		await h.call("POST", "/ssf/stream", pushBody);
		await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(seen).toHaveLength(1);
		expect(seen[0]?.url).toBe("https://rp.example/ssf/receive");
		expect(seen[0]?.headers.get("content-type")).toBe("application/secevent+jwt");
		expect(seen[0]?.headers.get("authorization")).toBe("Bearer secret");
		expect((await verifyForRp(seen[0]?.body ?? "")).ok).toBe(true);
	});

	it("retries 5xx with growing backoff and then succeeds", async () => {
		const statuses = [503, 500, 202];
		let calls = 0;
		const fetchImpl = (async () =>
			new Response(null, { status: statuses[calls++] ?? 202 })) as unknown as Fetch;
		const sleeps: number[] = [];
		const h = await makeTransmitter({ fetchImpl, sleep: async (ms) => void sleeps.push(ms) });
		await h.call("POST", "/ssf/stream", pushBody);
		const { queued } = await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(calls).toBe(3);
		expect(sleeps).toHaveLength(2);
		expect((sleeps[1] ?? 0) > (sleeps[0] ?? 0)).toBe(true);
		const row = await h.plugin.transmitter?.store.getOutbox(queued[0] as string);
		expect(row?.status).toBe("delivered");
		expect(row?.attempts).toBe(3);
	});

	it("gives up after maxAttempts", async () => {
		let calls = 0;
		const fetchImpl = (async () => {
			calls += 1;
			return new Response(null, { status: 503 });
		}) as unknown as Fetch;
		const h = await makeTransmitter({ fetchImpl, maxAttempts: 3 });
		await h.call("POST", "/ssf/stream", pushBody);
		const { queued } = await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(calls).toBe(3);
		expect((await h.plugin.transmitter?.store.getOutbox(queued[0] as string))?.status).toBe(
			"failed",
		);
	});

	it("does not retry a 400 from the receiver", async () => {
		let calls = 0;
		const fetchImpl = (async () => {
			calls += 1;
			return new Response(JSON.stringify({ err: "invalid_key" }), { status: 400 });
		}) as unknown as Fetch;
		const h = await makeTransmitter({ fetchImpl });
		await h.call("POST", "/ssf/stream", pushBody);
		const { queued } = await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(calls).toBe(1);
		expect((await h.plugin.transmitter?.store.getOutbox(queued[0] as string))?.status).toBe(
			"failed",
		);
	});

	it("refuses to deliver when the host later resolves to a private address", async () => {
		let resolved = PUBLIC_IP;
		let calls = 0;
		const fetchImpl = (async () => {
			calls += 1;
			return new Response(null, { status: 202 });
		}) as unknown as Fetch;
		const h = await makeTransmitter({ fetchImpl, resolver: () => resolved() });
		await h.call("POST", "/ssf/stream", pushBody);
		resolved = async () => ["192.168.1.10"];
		const { queued } = await h.plugin.emit({ ...events.sessionsRevoked(), subject });
		expect(calls).toBe(0);
		expect((await h.plugin.transmitter?.store.getOutbox(queued[0] as string))?.status).toBe(
			"failed",
		);
	});

	it("processDue delivers a stored SET whose retry time has come", async () => {
		let calls = 0;
		const fetchImpl = (async () => {
			calls += 1;
			return new Response(null, { status: 202 });
		}) as unknown as Fetch;
		const h = await makeTransmitter({ fetchImpl });
		const created = await (await h.call("POST", "/ssf/stream", pushBody)).json();
		const tx = h.plugin.transmitter;
		await tx?.store.enqueue({
			jti: "due-1",
			streamId: created.stream_id,
			jwt: await sign({ audience: "https://rp.example", jti: "due-1" }),
			nextAttemptAt: new Date(Date.now() - 1000),
		});
		const out = await tx?.processDue();
		expect(out).toEqual({ attempted: 1, delivered: 1, failed: 0 });
		expect(calls).toBe(1);
		expect((await tx?.store.getOutbox("due-1"))?.status).toBe("delivered");
		expect((await tx?.processDue())?.attempted).toBe(0);
	});
});

describe("receiver", () => {
	const audience = "https://rp.example";
	const make = (extra: Partial<Parameters<typeof createReceiver>[0]> = {}) =>
		createReceiver({
			issuer: ISS,
			audience,
			verificationKey: keys.publicKey,
			algorithms: ["ES256"],
			...extra,
		});
	const push = (
		r: ReturnType<typeof createReceiver>,
		jwt: string,
		type = "application/secevent+jwt",
	) =>
		r.handleRequest(
			new Request("https://rp.example/ssf/receive", {
				method: "POST",
				headers: { "content-type": type },
				body: jwt,
			}),
		);

	it("accepts a valid SET with 202 and dispatches once, even on replay", async () => {
		const handler = vi.fn();
		const r = make({ handlers: { [RISC_SESSIONS_REVOKED]: handler } });
		const jwt = await sign({ jti: "replay-1", audience });
		expect((await push(r, jwt)).status).toBe(202);
		expect((await push(r, jwt)).status).toBe(202);
		expect(handler).toHaveBeenCalledTimes(1);
		expect(handler.mock.calls[0]?.[0].subject).toEqual(subject);
	});

	it("rejects tampered, wrong audience and wrong content type with RFC 8935 errors", async () => {
		const r = make();
		const jwt = await sign({ audience });
		const [h, p, s] = jwt.split(".") as [string, string, string];
		const claims = JSON.parse(Buffer.from(p, "base64url").toString());
		claims.jti = "other";
		const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
		const t = await push(r, forged);
		expect(t.status).toBe(400);
		expect((await t.json()).err).toBe("invalid_key");
		const a = await push(r, await sign({ audience: "https://someone-else" }));
		expect((await a.json()).err).toBe("invalid_audience");
		const c = await push(r, jwt, "text/plain");
		expect(c.status).toBe(400);
	});

	it("checks the Authorization header when one is configured", async () => {
		const r = make({ authorizationHeader: "Bearer s3cret" });
		const res = await push(r, await sign({ audience }));
		expect(res.status).toBe(401);
	});

	it("revokes sessions through the default handlers", async () => {
		const sessionManager = {
			revoke: vi.fn(async () => undefined),
			revokeAll: vi.fn(async () => undefined),
		};
		const r = make({ handlers: createDefaultHandlers({ sessionManager, issuer: ISS }) });
		const tokenFor = (type: string, sub: unknown, jti: string) =>
			sign({ audience, jti, events: { [type]: { subject: sub, event_timestamp: 1 } } });

		expect((await push(r, await tokenFor(RISC_SESSIONS_REVOKED, subject, "a"))).status).toBe(202);
		expect(sessionManager.revokeAll).toHaveBeenLastCalledWith("user-1");

		expect(
			(
				await push(
					r,
					await tokenFor(
						RISC_ACCOUNT_DISABLED,
						{ format: "iss_sub", iss: ISS, sub: "user-2" },
						"b",
					),
				)
			).status,
		).toBe(202);
		expect(sessionManager.revokeAll).toHaveBeenLastCalledWith("user-2");

		await push(
			r,
			await tokenFor(
				CAEP_SESSION_REVOKED,
				{ format: "complex", session: { format: "opaque", id: "sess-9" } },
				"c",
			),
		);
		expect(sessionManager.revoke).toHaveBeenCalledWith("sess-9");

		const before = sessionManager.revokeAll.mock.calls.length;
		await push(
			r,
			await tokenFor(
				RISC_ACCOUNT_DISABLED,
				{ format: "iss_sub", iss: "https://elsewhere", sub: "u" },
				"d",
			),
		);
		expect(sessionManager.revokeAll.mock.calls.length).toBe(before);
	});

	it("discovers keys from the issuer's metadata through the safe fetcher", async () => {
		const jwk = { ...(await exportJWK(keys.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
		const urls: string[] = [];
		const fetchImpl = (async (url: string) => {
			urls.push(url);
			const body = url.endsWith("/.well-known/ssf-configuration")
				? { issuer: ISS, jwks_uri: `${ISS}/jwks.json` }
				: { keys: [jwk] };
			return new Response(JSON.stringify(body), {
				headers: { "content-type": "application/json" },
			});
		}) as unknown as Fetch;
		const r = createReceiver({
			issuer: ISS,
			audience,
			algorithms: ["ES256"],
			fetchOptions: { fetchImpl, resolver: PUBLIC_IP },
		});
		expect((await push(r, await sign({ audience }))).status).toBe(202);
		expect(urls).toEqual([`${ISS}/.well-known/ssf-configuration`, `${ISS}/jwks.json`]);
	});

	it("will not discover keys from a private issuer address", async () => {
		const fetchImpl = vi.fn();
		const r = createReceiver({
			issuer: ISS,
			audience,
			algorithms: ["ES256"],
			fetchOptions: {
				fetchImpl: fetchImpl as unknown as Fetch,
				resolver: async () => ["127.0.0.1"],
			},
		});
		const res = await push(r, await sign({ audience }));
		expect(res.status).toBe(400);
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("receives polled SETs and reports ack and errors", async () => {
		const handler = vi.fn();
		const r = make({ handlers: { [RISC_SESSIONS_REVOKED]: handler } });
		const good = await sign({ audience, jti: "g" });
		const out = await r.receivePolled({ g: good, bad: "not-a-jwt" });
		expect(out.ack).toEqual(["g"]);
		expect(out.setErrs.bad?.err).toBeDefined();
	});
});

describe("plugin wiring", () => {
	it("mounts a receiver endpoint and reports verification state", async () => {
		const onVerification = vi.fn();
		const plugin = sharedSignals({
			receiver: {
				issuer: ISS,
				audience: "https://rp.example",
				verificationKey: keys.publicKey,
				algorithms: ["ES256"],
				onVerification,
			},
		});
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [plugin],
		});
		const jwt = await sign({
			audience: "https://rp.example",
			events: { [SSF_VERIFICATION_EVENT]: { state: "xyz" } },
		});
		const res = await auth.plugins.handleRequest(
			new Request("https://rp.example/ssf/receive", {
				method: "POST",
				headers: { "content-type": "application/secevent+jwt" },
				body: jwt,
			}),
		);
		expect(res?.status).toBe(202);
		expect(onVerification).toHaveBeenCalledWith("xyz");
	});

	it("emission bridges map admin bans and session revokes to events", async () => {
		const emit = vi.fn(async () => undefined);
		const bridge = createEmissionBridge({ emit, issuer: ISS });
		await bridge.onAdminAction({
			adminUserId: "a",
			action: "ban_user",
			targetUserId: "u1",
			timestamp: new Date(),
		});
		const types = emit.mock.calls.map((c) => (c[0] as { type: string }).type);
		expect(types).toEqual([RISC_ACCOUNT_DISABLED, RISC_SESSIONS_REVOKED]);
		await bridge.onSessionsRevoked([
			{ id: "s1", userId: "u1", expiresAt: new Date(), createdAt: new Date() },
		]);
		const last = emit.mock.calls.at(-1)?.[0] as { type: string; subject: unknown };
		expect(last.type).toBe(CAEP_SESSION_REVOKED);
		expect(last.subject).toEqual({
			format: "complex",
			user: { format: "iss_sub", iss: ISS, sub: "u1" },
			session: { format: "opaque", id: "s1" },
		});
	});

	it("bridges swallow emit failures", async () => {
		const bridge = createEmissionBridge({
			emit: async () => {
				throw new Error("down");
			},
			issuer: ISS,
		});
		await expect(bridge.onPasswordChanged("u1")).resolves.toBeUndefined();
	});
});
