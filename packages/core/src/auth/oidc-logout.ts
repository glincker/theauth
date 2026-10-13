/**
 * OIDC provider logout wiring.
 *
 * Connects the primitives in `federated-logout.ts` to the OIDC provider:
 *
 * - `end_session_endpoint` (RP-Initiated Logout 1.0): validates `id_token_hint`
 *   and the `post_logout_redirect_uri` allowlist, ends the provider session.
 * - A sid index (`theauth_oidc_sessions`) records which relying parties hold a
 *   provider session, so a logout or a session revoke can fan out
 *   `sendBackChannelLogout` to every registered `backchannel_logout_uri`.
 * - Fan-out is best effort and never throws, so local logout always completes.
 *
 * Opt in with `createOidcProviderModule(config, db, getClaims)` where
 * `config.logout` is set. Without it nothing here runs.
 */

import { and, desc, eq, lt } from "drizzle-orm";
import type * as jose from "jose";
import { generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { oidcLogoutClients, oidcSessions } from "../db/schema.js";
import type { DnsResolver } from "../mcp/safe-fetch.js";
import { extractToken } from "../plugin/helpers.js";
import type { Session, SessionManager } from "../session/session.js";
import { createEndSessionHandler, sendBackChannelLogout } from "./federated-logout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OidcLogoutConfig {
	/** Path of the end session endpoint under the issuer. Default `/logout`. */
	endSessionPath?: string;
	/** Where to send the user when no valid `post_logout_redirect_uri` applies. */
	defaultRedirectUri?: string;
	/**
	 * Provider session manager. When set, the end session endpoint revokes the
	 * session named by the request cookie and by the `sid` hint.
	 */
	sessionManager?: SessionManager;
	/**
	 * Extra work when a provider session ends (clear your own cookies, etc.).
	 * Runs after sessions are revoked and before the redirect.
	 */
	onEndSession?: (ctx: { sub?: string; sid?: string; clientId?: string }) => Promise<void>;
	/** How long index rows are kept, seconds. Default 30 days. */
	indexTtlSeconds?: number;
	/** Back-channel delivery timeout in ms. Default 5000. */
	backchannelTimeoutMs?: number;
	/** Fetch override for back-channel delivery. */
	fetchImpl?: typeof fetch;
	/** DNS resolver override for the private-address check. */
	resolver?: DnsResolver;
	/** Allow http and private back-channel URIs. Development only. */
	allowInsecureBackchannel?: boolean;
}

export interface ClientLogoutConfig {
	postLogoutRedirectUris: string[];
	backchannelLogoutUri?: string | null;
}

export interface FanOutResult {
	attempted: number;
	delivered: number;
	failed: number;
}

export interface OidcLogoutModule {
	/** Absolute URL advertised as `end_session_endpoint`. */
	readonly endSessionEndpoint: string;
	/** Path (under the issuer) the endpoint is mounted at. */
	readonly endSessionPath: string;
	/** RP-initiated logout endpoint. Accepts GET and POST. */
	handleEndSession(request: Request): Promise<Response>;
	setClientLogoutConfig(clientId: string, config: ClientLogoutConfig): Promise<void>;
	getClientLogoutConfig(clientId: string): Promise<ClientLogoutConfig | null>;
	deleteClientLogoutConfig(clientId: string): Promise<void>;
	/**
	 * Notify relying parties that the given provider sessions ended. Plug this
	 * into `auth.session.onRevoke` so any revoke (logout, password reset,
	 * limit eviction) fans out. Never throws.
	 */
	handleSessionsRevoked(sessions: Session[]): Promise<FanOutResult>;
	/** Fan out for a sid, or for every session of a user. Never throws. */
	fanOut(target: { sid?: string; sessionId?: string; userId?: string }): Promise<FanOutResult>;
}

/** Internal hooks the provider module passes in. */
export interface OidcLogoutDeps {
	db: Database;
	issuer: string;
	signingAlg: string;
	kid: string;
	getSigningKey: () => Promise<CryptoKey>;
	getPublicJwk: () => Promise<jose.JWK>;
	importPublicKey: (jwk: jose.JWK) => Promise<CryptoKey | Uint8Array>;
	config: OidcLogoutConfig;
}

const DEFAULT_PATH = "/logout";
const DEFAULT_INDEX_TTL = 30 * 24 * 60 * 60;

/** Derive the public `sid` for a provider session without exposing its id. */
export async function deriveSid(issuer: string, sessionId: string): Promise<string> {
	return (await sha256(`oidc-sid:${issuer}:${sessionId}`)).slice(0, 32);
}

function validateHttpsUri(uri: string, allowInsecure: boolean): boolean {
	try {
		const url = new URL(uri);
		if (url.protocol === "https:") return true;
		return allowInsecure && url.protocol === "http:";
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOidcLogoutModule(deps: OidcLogoutDeps): OidcLogoutModule {
	const { db, issuer, config } = deps;
	const path = config.endSessionPath ?? DEFAULT_PATH;
	const allowInsecure = config.allowInsecureBackchannel === true;

	// ── client logout config ────────────────────────────────────────────────

	async function getClientLogoutConfig(clientId: string): Promise<ClientLogoutConfig | null> {
		const rows = await db
			.select()
			.from(oidcLogoutClients)
			.where(eq(oidcLogoutClients.clientId, clientId));
		const row = rows[0];
		if (!row) return null;
		return {
			postLogoutRedirectUris: row.postLogoutRedirectUris,
			backchannelLogoutUri: row.backchannelLogoutUri,
		};
	}

	async function setClientLogoutConfig(clientId: string, cfg: ClientLogoutConfig): Promise<void> {
		for (const uri of cfg.postLogoutRedirectUris) {
			if (!validateHttpsUri(uri, true) || new URL(uri).hash) {
				throw new Error(`Invalid post_logout_redirect_uri: ${uri}`);
			}
		}
		const bc = cfg.backchannelLogoutUri ?? null;
		if (bc !== null && !validateHttpsUri(bc, allowInsecure)) {
			throw new Error("backchannel_logout_uri must be an https URL");
		}
		await db.delete(oidcLogoutClients).where(eq(oidcLogoutClients.clientId, clientId));
		await db.insert(oidcLogoutClients).values({
			clientId,
			postLogoutRedirectUris: cfg.postLogoutRedirectUris,
			backchannelLogoutUri: bc,
			updatedAt: new Date(),
		});
	}

	async function deleteClientLogoutConfig(clientId: string): Promise<void> {
		await db.delete(oidcLogoutClients).where(eq(oidcLogoutClients.clientId, clientId));
	}

	// ── fan-out ─────────────────────────────────────────────────────────────

	async function fanOut(target: {
		sid?: string;
		sessionId?: string;
		userId?: string;
	}): Promise<FanOutResult> {
		const result: FanOutResult = { attempted: 0, delivered: 0, failed: 0 };
		try {
			const condition = target.sid
				? eq(oidcSessions.sid, target.sid)
				: target.sessionId
					? eq(oidcSessions.sessionId, target.sessionId)
					: target.userId
						? eq(oidcSessions.userId, target.userId)
						: null;
			if (!condition) return result;

			const rows = await db.select().from(oidcSessions).where(condition);
			if (rows.length === 0) return result;

			// Claim the rows first so concurrent or repeated fan-outs do not double send.
			await db.delete(oidcSessions).where(condition);

			const key = await deps.getSigningKey();
			// One token per (sid, client, user), however many authorizations were indexed.
			const seen = new Set<string>();
			const unique = rows.filter((row) => {
				const k = `${row.sid}\u0000${row.clientId}\u0000${row.userId}`;
				if (seen.has(k)) return false;
				seen.add(k);
				return true;
			});
			await Promise.all(
				unique.map(async (row) => {
					const client = await getClientLogoutConfig(row.clientId);
					if (!client?.backchannelLogoutUri) return;
					result.attempted += 1;
					const sent = await sendBackChannelLogout({
						issuer,
						clientId: row.clientId,
						backchannelLogoutUri: client.backchannelLogoutUri,
						sub: row.userId,
						sid: row.sid,
						signingKey: key,
						alg: deps.signingAlg,
						kid: deps.kid,
						...(config.backchannelTimeoutMs !== undefined && {
							timeoutMs: config.backchannelTimeoutMs,
						}),
						...(config.fetchImpl && { fetchImpl: config.fetchImpl }),
						...(config.resolver && { resolver: config.resolver }),
						...(allowInsecure && { allowInsecure: true }),
					});
					if (sent.success) result.delivered += 1;
					else result.failed += 1;
				}),
			);
		} catch {
			// Fan-out must never block local logout.
		}
		return result;
	}

	async function handleSessionsRevoked(revoked: Session[]): Promise<FanOutResult> {
		const total: FanOutResult = { attempted: 0, delivered: 0, failed: 0 };
		for (const session of revoked) {
			const one = await fanOut({ sessionId: session.id });
			total.attempted += one.attempted;
			total.delivered += one.delivered;
			total.failed += one.failed;
		}
		return total;
	}

	// ── end session endpoint ────────────────────────────────────────────────

	async function endProviderSession(ctx: {
		request: Request;
		sub?: string;
		sid?: string;
		clientId?: string;
	}): Promise<void> {
		const sessionIds = new Set<string>();
		const sm = config.sessionManager;

		if (sm) {
			const token = extractToken(ctx.request);
			if (token) {
				const session = await sm.validate(token);
				// A hint for another user must not end this browser's session.
				if (session && (!ctx.sub || session.userId === ctx.sub)) sessionIds.add(session.id);
			}
			if (ctx.sid) {
				const rows = await db.select().from(oidcSessions).where(eq(oidcSessions.sid, ctx.sid));
				for (const row of rows) if (row.sessionId) sessionIds.add(row.sessionId);
			}
		}

		// Notify relying parties first so a failing revoke cannot skip fan-out.
		if (ctx.sid) {
			await fanOut({ sid: ctx.sid });
		} else {
			for (const id of sessionIds) await fanOut({ sessionId: id });
			if (sessionIds.size === 0 && ctx.sub) await fanOut({ userId: ctx.sub });
		}

		if (sm) {
			for (const id of sessionIds) {
				try {
					await sm.revoke(id);
				} catch {
					// Keep going: the remaining sessions and the redirect still apply.
				}
			}
		}
		if (config.onEndSession) {
			await config.onEndSession({ sub: ctx.sub, sid: ctx.sid, clientId: ctx.clientId });
		}
	}

	const handler = createEndSessionHandler({
		issuer,
		verificationKey: async () => deps.importPublicKey(await deps.getPublicJwk()),
		algorithms: [deps.signingAlg],
		getClient: async (clientId) => {
			const cfg = await getClientLogoutConfig(clientId);
			return cfg ? { postLogoutRedirectUris: cfg.postLogoutRedirectUris } : null;
		},
		endSession: endProviderSession,
		...(config.defaultRedirectUri && { defaultRedirectUri: config.defaultRedirectUri }),
	});

	return {
		endSessionEndpoint: `${issuer}${path}`,
		endSessionPath: path,
		handleEndSession: (request) => handler.handleRequest(request),
		setClientLogoutConfig,
		getClientLogoutConfig,
		deleteClientLogoutConfig,
		handleSessionsRevoked,
		fanOut,
	};
}

// ---------------------------------------------------------------------------
// sid index helpers used by the provider
// ---------------------------------------------------------------------------

export interface OidcSidIndex {
	/** Record an authorization for a client; returns the sid used. */
	record(input: {
		userId: string;
		clientId: string;
		codeHash: string;
		sessionId?: string;
	}): Promise<string>;
	/** Sid linked to an authorization code (consumed at token exchange). */
	forCode(codeHash: string): Promise<string | null>;
	/** Most recent sid for a user and client (refresh grant). */
	latest(userId: string, clientId: string): Promise<string | null>;
}

export function createOidcSidIndex(
	db: Database,
	issuer: string,
	ttlSeconds?: number,
): OidcSidIndex {
	const ttl = (ttlSeconds ?? DEFAULT_INDEX_TTL) * 1000;

	return {
		async record({ userId, clientId, codeHash, sessionId }) {
			try {
				await db.delete(oidcSessions).where(lt(oidcSessions.createdAt, new Date(Date.now() - ttl)));
			} catch {
				// Pruning is opportunistic.
			}
			const sid = sessionId ? await deriveSid(issuer, sessionId) : generateId().replace(/-/g, "");
			await db.insert(oidcSessions).values({
				id: generateId(),
				sid,
				sessionId: sessionId ?? null,
				userId,
				clientId,
				codeHash,
				createdAt: new Date(),
			});
			return sid;
		},
		async forCode(codeHash) {
			const rows = await db
				.select({ sid: oidcSessions.sid })
				.from(oidcSessions)
				.where(eq(oidcSessions.codeHash, codeHash));
			return rows[0]?.sid ?? null;
		},
		async latest(userId, clientId) {
			const rows = await db
				.select({ sid: oidcSessions.sid })
				.from(oidcSessions)
				.where(and(eq(oidcSessions.userId, userId), eq(oidcSessions.clientId, clientId)))
				.orderBy(desc(oidcSessions.createdAt))
				.limit(1);
			return rows[0]?.sid ?? null;
		},
	};
}
