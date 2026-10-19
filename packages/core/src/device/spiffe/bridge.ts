import type { AgentConfirmation } from "../../agent/confirmation.js";
import { CNF_X5T_S256 } from "../../agent/confirmation.js";
import type { AgentIdentity } from "../../types.js";
import { certBytesFromText } from "../attestation/x509.js";
import type { Device } from "../types.js";
import type { SpiffeBundleStore, SpiffeTrustDomainConfig } from "./bundle-store.js";
import { createBundleStore } from "./bundle-store.js";
import { claimedSpiffeId } from "./claimed.js";
import { verifyJwtSvid } from "./jwt-svid.js";
import type { SvidFailure } from "./x509-svid.js";
import { verifyX509Svid } from "./x509-svid.js";

export interface SpiffeBridgeConfig {
	/** Trust bundles by trust domain name, for example `{ "example.org": { endpoint: { url } } }`. */
	trustDomains: Record<string, SpiffeTrustDomainConfig>;
	/** Audience values a JWT-SVID may carry. Leave empty to refuse JWT-SVIDs. */
	audience?: string[];
	/** The device module (`theauth.device`). Without it SPIFFE ids never map to devices. */
	devices?: {
		findBySpiffeId(id: string): Promise<{ device: Device; credentialId: string } | null>;
	};
	/** Agent side. `resolve` (or the static `map`) returns the agent id for a verified SPIFFE ID. */
	agents?: {
		get(agentId: string): Promise<AgentIdentity | null>;
		rotate(
			agentId: string,
			options: { cnf: AgentConfirmation },
		): Promise<AgentIdentity & { token: string }>;
		resolve?: (spiffeId: string) => string | null | Promise<string | null>;
		map?: Record<string, string>;
	};
	/**
	 * Called once per verification outcome, success or failure, never with the certificate or token. `spiffeId` is only trusted when `verified` is true. Errors thrown here are swallowed.
	 */
	onOutcome?: (outcome: SpiffeOutcome) => void | Promise<void>;
	/** Time source in ms, for tests. */
	clock?: () => number;
	clockSkewSeconds?: number;
	/** Refuse X.509-SVIDs valid for longer than this (SPIRE issues one hour by default). Default: no limit. */
	maxX509LifetimeSeconds?: number;
	/** Longest accepted JWT-SVID expiry from now. Default 3600. */
	maxJwtTtlSeconds?: number;
	/**
	 * Return the TLS client certificate chain (PEM text or DER, leaf first) of a request. TLS ends at your proxy, so only you know it, and it must come from the verified handshake, never from a header a client can set. Used by `authenticateRequest`.
	 */
	clientCertificate?: (
		request: Request,
	) => string | Uint8Array[] | null | Promise<string | Uint8Array[] | null>;
}

export type SpiffePresentation =
	| { kind: "x509"; chain: Uint8Array[] | string }
	| { kind: "jwt"; token: string };

export type SpiffePrincipal =
	| { type: "device"; device: Device; credentialId: string }
	| { type: "agent"; agent: AgentIdentity };

/** What `onOutcome` receives. Holds no certificate body and no token. */
export interface SpiffeOutcome {
	/** `authenticate` maps the id to a device or agent, `verify` only checks the SVID. */
	purpose: "authenticate" | "verify";
	kind: "x509" | "jwt";
	ok: boolean;
	/** "ok" or the failure code. */
	code: "ok" | SpiffeAuthFailure;
	/** The id the SVID names. A failed outcome carries it unverified (read before the signature check), so treat it as a claim. */
	spiffeId?: string;
	/** True when the SVID passed verification against a trust bundle. */
	verified: boolean;
	principal?: { type: "device" | "agent"; id: string };
	/** `x5t#S256` of an X.509 leaf, when it could be read. */
	thumbprint?: string;
}

export type SpiffeAuthFailure = SvidFailure | "unknown_workload" | "principal_inactive";

export type SpiffeAuthResult =
	| {
			ok: true;
			principal: SpiffePrincipal;
			spiffeId: string;
			svid: { kind: "x509" | "jwt"; expiresAt: Date; thumbprint?: string };
			/** RFC 8705 confirmation of an X.509-SVID: `x5t#S256` of the leaf. */
			cnf?: AgentConfirmation;
	  }
	| { ok: false; code: SpiffeAuthFailure; reason: string; agentId?: string };

function chainOf(input: Uint8Array[] | string): Uint8Array[] | null {
	if (typeof input !== "string") return input;
	const blocks = input.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
	if (!blocks) return null;
	try {
		return blocks.map((b) => certBytesFromText(b));
	} catch {
		return null;
	}
}

/**
 * SPIFFE bridge: a workload presents an X.509-SVID or JWT-SVID, we verify it against configured trust
 * bundles and map the SPIFFE ID to an existing device or agent. Nothing is created on the fly: an
 * unmapped workload is refused (`unknown_workload`). Map ids with
 * `device.addCredential(id, { kind: "spiffe", spiffeId })` or `agents.map` and `agents.resolve`.
 */
export function createSpiffeBridge(config: SpiffeBridgeConfig) {
	const now = config.clock ?? Date.now;
	const store: SpiffeBundleStore = createBundleStore(config.trustDomains, now);

	async function resolveAgent(spiffeId: string): Promise<AgentIdentity | null> {
		const agents = config.agents;
		if (!agents) return null;
		const mapped =
			agents.map && Object.hasOwn(agents.map, spiffeId) ? agents.map[spiffeId] : undefined;
		const id = mapped ?? (agents.resolve ? await agents.resolve(spiffeId) : null);
		if (!id) return null;
		const agent = await agents.get(id);
		if (!agent || agent.type === "device") return null;
		return agent;
	}

	async function principalFor(
		spiffeId: string,
	): Promise<
		SpiffePrincipal | { ok: false; code: SpiffeAuthFailure; reason: string; agentId?: string }
	> {
		const device = await config.devices?.findBySpiffeId(spiffeId);
		if (device) return { type: "device", ...device };
		const agent = await resolveAgent(spiffeId);
		if (!agent) {
			return {
				ok: false,
				code: "unknown_workload",
				reason: "No device or agent is mapped to this SPIFFE ID",
			};
		}
		if (agent.status !== "active" || (agent.expiresAt && agent.expiresAt.getTime() <= now())) {
			return {
				ok: false,
				code: "principal_inactive",
				reason: "The mapped agent is not active",
				agentId: agent.id,
			};
		}
		return { type: "agent", agent };
	}

	type Verified =
		| {
				ok: true;
				spiffeId: string;
				svid: { kind: "x509" | "jwt"; expiresAt: Date; thumbprint?: string };
				cnf?: AgentConfirmation;
		  }
		| { ok: false; code: SvidFailure; reason: string };

	/** Check the SVID against the trust bundles. No principal lookup. */
	async function verifySvid(presentation: SpiffePresentation): Promise<Verified> {
		const at = new Date(now());
		if (presentation.kind === "x509") {
			const chain = chainOf(presentation.chain);
			if (!chain) return { ok: false, code: "malformed", reason: "No certificate in the chain" };
			const result = await verifyX509Svid(chain, store, {
				now: at,
				...(config.clockSkewSeconds !== undefined && { clockSkewSeconds: config.clockSkewSeconds }),
				...(config.maxX509LifetimeSeconds !== undefined && {
					maxLifetimeSeconds: config.maxX509LifetimeSeconds,
				}),
			});
			if (!result.ok) return result;
			return {
				ok: true,
				spiffeId: result.identity.spiffeId,
				svid: {
					kind: "x509",
					expiresAt: result.identity.notAfter,
					thumbprint: result.identity.thumbprint,
				},
				cnf: { [CNF_X5T_S256]: result.identity.thumbprint },
			};
		}
		const result = await verifyJwtSvid(presentation.token, store, {
			audience: config.audience ?? [],
			now: at,
			...(config.clockSkewSeconds !== undefined && { clockSkewSeconds: config.clockSkewSeconds }),
			...(config.maxJwtTtlSeconds !== undefined && { maxTtlSeconds: config.maxJwtTtlSeconds }),
		});
		if (!result.ok) return result;
		return {
			ok: true,
			spiffeId: result.identity.spiffeId,
			svid: { kind: "jwt", expiresAt: result.identity.expiresAt },
		};
	}

	async function emit(outcome: SpiffeOutcome): Promise<void> {
		if (!config.onOutcome) return;
		try {
			await config.onOutcome(outcome);
		} catch {
			// An audit sink that fails must not change the authentication result.
		}
	}

	/** Verify the SVID only (no device or agent mapping). Used to link an id and for diagnostics. */
	async function verify(
		presentation: SpiffePresentation,
	): Promise<Exclude<Verified, { ok: true }> | Extract<Verified, { ok: true }>> {
		const result = await verifySvid(presentation);
		if (result.ok) {
			await emit({
				purpose: "verify",
				kind: presentation.kind,
				ok: true,
				code: "ok",
				spiffeId: result.spiffeId,
				verified: true,
				...(result.svid.thumbprint && { thumbprint: result.svid.thumbprint }),
			});
		} else {
			await emitFailure("verify", presentation, result.code);
		}
		return result;
	}

	async function emitFailure(
		purpose: SpiffeOutcome["purpose"],
		presentation: SpiffePresentation,
		code: SpiffeAuthFailure,
	): Promise<void> {
		const claimed = await claimedSpiffeId(presentation, chainOf);
		await emit({
			purpose,
			kind: presentation.kind,
			ok: false,
			code,
			verified: false,
			...(claimed && { spiffeId: claimed.spiffeId }),
			...(claimed?.thumbprint && { thumbprint: claimed.thumbprint }),
		});
	}

	async function authenticate(presentation: SpiffePresentation): Promise<SpiffeAuthResult> {
		const result = await verifySvid(presentation);
		if (!result.ok) {
			await emitFailure("authenticate", presentation, result.code);
			return result;
		}
		const principal = await principalFor(result.spiffeId);
		if ("code" in principal) {
			await emit({
				purpose: "authenticate",
				kind: presentation.kind,
				ok: false,
				code: principal.code,
				spiffeId: result.spiffeId,
				verified: true,
				...(result.svid.thumbprint && { thumbprint: result.svid.thumbprint }),
			});
			return principal;
		}
		await emit({
			purpose: "authenticate",
			kind: presentation.kind,
			ok: true,
			code: "ok",
			spiffeId: result.spiffeId,
			verified: true,
			principal: {
				type: principal.type,
				id: principal.type === "device" ? principal.device.id : principal.agent.id,
			},
			...(result.svid.thumbprint && { thumbprint: result.svid.thumbprint }),
		});
		return {
			ok: true,
			principal,
			spiffeId: result.spiffeId,
			svid: result.svid,
			...(result.cnf && { cnf: result.cnf }),
		};
	}

	/** Read the SVID of a request: the TLS client certificate from `clientCertificate`, else `Authorization: Bearer <JWT-SVID>`. */
	async function authenticateRequest(request: Request): Promise<SpiffeAuthResult> {
		const cert = config.clientCertificate ? await config.clientCertificate(request) : null;
		if (cert) return authenticate({ kind: "x509", chain: cert });
		const match = /^Bearer\s+(\S+)$/i.exec((request.headers.get("authorization") ?? "").trim());
		if (match?.[1]) return authenticate({ kind: "jwt", token: match[1] });
		return { ok: false, code: "malformed", reason: "No SVID presented" };
	}

	/**
	 * Give an agent that proved itself with an X.509-SVID a token bound to that certificate (RFC 8705 `cnf` `x5t#S256`). This rotates the agent token, so the previous token stops working: use one agent per workload identity. Devices have no bearer token, they act through `device.authorize`. A JWT-SVID has no key to bind, so it never gets a token.
	 */
	async function issueAgentToken(
		result: Extract<SpiffeAuthResult, { ok: true }>,
	): Promise<(AgentIdentity & { token: string }) | null> {
		if (result.principal.type !== "agent" || !result.cnf || !config.agents) return null;
		return config.agents.rotate(result.principal.agent.id, { cnf: result.cnf });
	}

	return { authenticate, authenticateRequest, verify, issueAgentToken, bundles: store };
}

export type SpiffeBridge = ReturnType<typeof createSpiffeBridge>;
