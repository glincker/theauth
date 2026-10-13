/**
 * DPoP (RFC 9449) client helper. Edge safe: WebCrypto only, no dependencies.
 *
 * `createDPoPProver` owns an ES256 key pair and builds proofs. `createDPoPClient`
 * wraps `fetch`: it attaches the proof (and the `DPoP` authorization scheme with
 * an `ath` claim when an access token is supplied), caches the server nonce per
 * origin and retries once on a `use_dpop_nonce` challenge.
 */

export interface DPoPPublicJwk {
	kty: "EC";
	crv: "P-256";
	x: string;
	y: string;
}

export interface DPoPProofInput {
	/** HTTP method of the request the proof is for. */
	method: string;
	/** Absolute request URL. Query and fragment are dropped from `htu`. */
	url: string;
	/** Include to bind the proof to a resource request (`ath`). */
	accessToken?: string;
	/** Server-provided nonce, when one is known for the origin. */
	nonce?: string;
}

export interface DPoPProver {
	readonly publicJwk: DPoPPublicJwk;
	/** RFC 7638 SHA-256 JWK thumbprint (the `jkt` / `cnf.jkt` value). */
	thumbprint(): Promise<string>;
	createProof(input: DPoPProofInput): Promise<string>;
	/** Cached nonce for the origin of `url`, if any. */
	getNonce(url: string): string | undefined;
	setNonce(url: string, nonce: string): void;
}

export interface DPoPProverOptions {
	/** Existing ECDSA P-256 key pair. Generated (non-extractable private key) when omitted. */
	keyPair?: CryptoKeyPair;
	/** Clock in milliseconds. Defaults to `Date.now`. */
	now?: () => number;
}

export interface DPoPFetchOptions {
	/** Access token for this request. Overrides the client-level `accessToken`. */
	accessToken?: string;
}

export interface DPoPClientOptions extends DPoPProverOptions {
	/** Reuse a prover (and its nonce cache) instead of creating one. */
	prover?: DPoPProver;
	fetch?: typeof fetch;
	/** Default access token, or a getter resolved per request. */
	accessToken?: string | (() => string | undefined | Promise<string | undefined>);
}

export interface DPoPClient {
	readonly prover: DPoPProver;
	thumbprint(): Promise<string>;
	fetch(
		input: RequestInfo | URL,
		init?: RequestInit,
		options?: DPoPFetchOptions,
	): Promise<Response>;
}

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function encodeJson(value: unknown): string {
	return toBase64Url(encoder.encode(JSON.stringify(value)));
}

async function sha256Url(value: string): Promise<string> {
	return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

/** `htu` form: scheme, host and path only. Throws for a non-absolute URL. */
export function normalizeHtu(value: string): string {
	const url = new URL(value);
	return `${url.origin}${url.pathname}`;
}

function originOf(url: string): string {
	return new URL(url).origin;
}

function randomJti(): string {
	return toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}

export async function createDPoPProver(options: DPoPProverOptions = {}): Promise<DPoPProver> {
	const keyPair =
		options.keyPair ??
		(await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
			"sign",
			"verify",
		]));
	const now = options.now ?? Date.now;
	const exported = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
	if (exported.kty !== "EC" || exported.crv !== "P-256" || !exported.x || !exported.y) {
		throw new Error("DPoP key pair must be an ECDSA P-256 key pair");
	}
	const publicJwk: DPoPPublicJwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
	const nonces = new Map<string, string>();
	let thumbprint: Promise<string> | undefined;

	return {
		publicJwk,

		thumbprint() {
			thumbprint ??= sha256Url(
				JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }),
			);
			return thumbprint;
		},

		async createProof(input) {
			const claims: Record<string, unknown> = {
				htm: input.method.toUpperCase(),
				htu: normalizeHtu(input.url),
				iat: Math.floor(now() / 1000),
				jti: randomJti(),
			};
			if (input.accessToken) claims.ath = await sha256Url(input.accessToken);
			if (input.nonce) claims.nonce = input.nonce;
			const signingInput = `${encodeJson({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk })}.${encodeJson(claims)}`;
			const signature = await crypto.subtle.sign(
				{ name: "ECDSA", hash: "SHA-256" },
				keyPair.privateKey,
				encoder.encode(signingInput),
			);
			return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
		},

		getNonce(url) {
			return nonces.get(originOf(url));
		},

		setNonce(url, nonce) {
			nonces.set(originOf(url), nonce);
		},
	};
}

async function isNonceChallenge(res: Response): Promise<boolean> {
	if (res.status !== 400 && res.status !== 401) return false;
	if (!res.headers.get("DPoP-Nonce")) return false;
	if (/use_dpop_nonce/.test(res.headers.get("WWW-Authenticate") ?? "")) return true;
	if (res.status !== 400) return false;
	try {
		const body: unknown = await res.clone().json();
		return (
			typeof body === "object" &&
			body !== null &&
			(body as { error?: unknown }).error === "use_dpop_nonce"
		);
	} catch {
		return false;
	}
}

export async function createDPoPClient(options: DPoPClientOptions = {}): Promise<DPoPClient> {
	const prover = options.prover ?? (await createDPoPProver(options));
	const baseFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));

	async function resolveToken(override?: string): Promise<string | undefined> {
		if (override) return override;
		const configured = options.accessToken;
		return typeof configured === "function" ? configured() : configured;
	}

	async function send(base: Request, accessToken: string | undefined): Promise<Response> {
		const req = base.clone();
		const proof = await prover.createProof({
			method: req.method,
			url: req.url,
			accessToken,
			nonce: prover.getNonce(req.url),
		});
		req.headers.set("DPoP", proof);
		if (accessToken) req.headers.set("Authorization", `DPoP ${accessToken}`);
		const res = await baseFetch(req);
		const nonce = res.headers.get("DPoP-Nonce");
		if (nonce) prover.setNonce(req.url, nonce);
		return res;
	}

	return {
		prover,

		thumbprint: () => prover.thumbprint(),

		async fetch(input, init, fetchOptions) {
			const base = new Request(input, init);
			const accessToken = await resolveToken(fetchOptions?.accessToken);
			const first = await send(base, accessToken);
			if (!(await isNonceChallenge(first))) return first;
			return send(base, accessToken);
		},
	};
}
