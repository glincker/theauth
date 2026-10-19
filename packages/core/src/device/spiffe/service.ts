import { recordAuditEvent } from "../../audit/record.js";
import type { Database } from "../../db/database.js";
import type { SecondaryStorage } from "../../storage/types.js";
import type { AgentIdentity } from "../../types.js";
import { devicePrincipal } from "../state.js";
import type { Device } from "../types.js";
import type {
	SpiffeAuthResult,
	SpiffeBridge,
	SpiffeBridgeConfig,
	SpiffeOutcome,
	SpiffePresentation,
} from "./bridge.js";
import { createSpiffeBridge } from "./bridge.js";
import { parseSpiffeId } from "./spiffe-id.js";

/** `devices.spiffe`: the bridge settings plus the HTTP side (header source, rate limit, agent mapping). */
export interface DeviceSpiffeConfig
	extends Pick<
		SpiffeBridgeConfig,
		| "trustDomains"
		| "audience"
		| "clockSkewSeconds"
		| "maxX509LifetimeSeconds"
		| "maxJwtTtlSeconds"
		| "clientCertificate"
		| "clock"
	> {
	/** SPIFFE ID to agent id, for workloads that are agents rather than devices. */
	agentMap?: Record<string, string>;
	/** Look up the agent id of a verified SPIFFE ID. */
	resolveAgent?: (spiffeId: string) => string | null | Promise<string | null>;
	/**
	 * Read the client certificate chain from a request header your reverse proxy sets after it verified the TLS handshake (nginx `$ssl_client_escaped_cert`, or PEM). Off by default and ignored when `clientCertificate` is set. The proxy MUST overwrite or strip this header on every inbound request, otherwise a client can send any certificate, which carries no proof of key possession. Never enable it on a server that is reachable without the proxy.
	 */
	trustedProxyHeader?: string;
	/** Per client IP limit on the SPIFFE routes. Default 60 requests per 60 seconds. */
	rateLimit?: { max?: number; windowSeconds?: number };
}

interface Deps {
	db: Database;
	config: DeviceSpiffeConfig;
	storage: SecondaryStorage;
	devices: {
		findBySpiffeId(id: string): Promise<{ device: Device; credentialId: string } | null>;
		/** Device that owns a SPIFFE id credential in any state, no side effects. For audit attribution. */
		attribute(id: string): Promise<Device | null>;
	};
	agents: {
		get(agentId: string): Promise<AgentIdentity | null>;
		rotate: NonNullable<SpiffeBridgeConfig["agents"]>["rotate"];
	};
}

const MAX_HEADER_CHARS = 32_768;
const DEFAULT_MAX = 60;
const DEFAULT_WINDOW = 60;

/** Certificate chain from the operator's trusted proxy header (URL encoded or plain PEM), or null. */
function chainFromHeader(request: Request, name: string): string | null {
	const raw = request.headers.get(name);
	if (!raw || raw.length > MAX_HEADER_CHARS) return null;
	let text = raw;
	if (!text.includes("BEGIN CERTIFICATE")) {
		try {
			text = decodeURIComponent(text);
		} catch {
			return null;
		}
	}
	return text.includes("BEGIN CERTIFICATE") ? text : null;
}

export function createDeviceSpiffeService(deps: Deps) {
	const { config } = deps;
	const max = config.rateLimit?.max ?? DEFAULT_MAX;
	const windowSeconds = config.rateLimit?.windowSeconds ?? DEFAULT_WINDOW;

	/** One audit row per outcome when the outcome can be tied to a device or agent. */
	async function audit(outcome: SpiffeOutcome): Promise<void> {
		let target: { agentId: string; ownerId: string; extra: Record<string, unknown> } | null = null;
		if (outcome.principal?.type === "agent") {
			const agent = await deps.agents.get(outcome.principal.id);
			if (agent) target = { agentId: agent.id, ownerId: agent.ownerId, extra: {} };
		} else if (outcome.spiffeId) {
			const device = await deps.devices.attribute(outcome.spiffeId);
			if (device) {
				target = {
					agentId: device.agentId,
					ownerId: device.ownerId,
					extra: devicePrincipal(device.id),
				};
			}
		}
		if (!target) return;
		await recordAuditEvent(deps.db, {
			agentId: target.agentId,
			userId: target.ownerId,
			action: `device.spiffe.${outcome.purpose}`,
			resource: `spiffe:${outcome.spiffeId ?? "unknown"}`,
			result: outcome.ok ? "allowed" : "denied",
			reason: outcome.ok ? "svid verified" : outcome.code,
			parameters: {
				...target.extra,
				kind: outcome.kind,
				code: outcome.code,
				verified: outcome.verified,
				...(outcome.thumbprint && { thumbprint: outcome.thumbprint }),
			},
		}).catch(() => {});
	}

	const bridge: SpiffeBridge = createSpiffeBridge({
		trustDomains: config.trustDomains,
		...(config.audience && { audience: config.audience }),
		...(config.clockSkewSeconds !== undefined && { clockSkewSeconds: config.clockSkewSeconds }),
		...(config.maxX509LifetimeSeconds !== undefined && {
			maxX509LifetimeSeconds: config.maxX509LifetimeSeconds,
		}),
		...(config.maxJwtTtlSeconds !== undefined && { maxJwtTtlSeconds: config.maxJwtTtlSeconds }),
		...(config.clock && { clock: config.clock }),
		devices: deps.devices,
		agents: {
			get: deps.agents.get,
			rotate: deps.agents.rotate,
			...(config.agentMap && { map: config.agentMap }),
			...(config.resolveAgent && { resolve: config.resolveAgent }),
		},
		clientCertificate: async (request) => {
			if (config.clientCertificate) return config.clientCertificate(request);
			return config.trustedProxyHeader ? chainFromHeader(request, config.trustedProxyHeader) : null;
		},
		onOutcome: audit,
	});

	/** True when the caller is over the limit. A missing IP shares one bucket, so the limit still holds. */
	async function limited(ip: string | undefined): Promise<boolean> {
		try {
			const { count } = await deps.storage.incr(`spiffe:${ip ?? "unknown"}`, windowSeconds);
			return count > max;
		} catch {
			return true;
		}
	}

	/** Verify the SVID of a request (TLS or trusted header certificate, else Bearer JWT-SVID). */
	function authenticateRequest(request: Request): Promise<SpiffeAuthResult> {
		return bridge.authenticateRequest(request);
	}

	/** Only an id in a configured trust domain may be linked, so a typo or foreign id fails closed. */
	function checkLinkable(
		spiffeId: string,
	): { ok: true; id: string } | { ok: false; reason: string } {
		const id = parseSpiffeId(spiffeId);
		if (!id.ok || id.path === "") return { ok: false, reason: "Not a SPIFFE ID with a path" };
		if (!Object.hasOwn(config.trustDomains, id.trustDomain)) {
			return { ok: false, reason: "The trust domain is not configured" };
		}
		return { ok: true, id: id.id };
	}

	return {
		bridge,
		limited,
		authenticateRequest,
		checkLinkable,
		verify: (presentation: SpiffePresentation) => bridge.verify(presentation),
		authenticate: (presentation: SpiffePresentation) => bridge.authenticate(presentation),
		issueAgentToken: bridge.issueAgentToken,
	};
}

export type DeviceSpiffeService = ReturnType<typeof createDeviceSpiffeService>;
