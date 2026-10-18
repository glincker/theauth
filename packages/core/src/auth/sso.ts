/**
 * SAML 2.0 and OIDC enterprise SSO. Connections link to organizations and route by email domain.
 * Security hardening: namespace-aware XML parsing, XXE blocking, SAML condition checks, InResponseTo replay tracking, signature digest checks, OIDC nonce and at_hash checks, state expiry, rate limiting and audit logging.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   sso: {
 *     saml: [{ id: 'okta', name: 'Okta', entryPoint: '...', issuer: '...', cert: '...', callbackUrl: '...' }],
 *   },
 * });
 *
 * // Get SAML auth URL (redirect user to this)
 * const url = await theauth.sso.getSamlAuthUrl(connectionId);
 * ```
 */

import { and, eq } from "drizzle-orm";
import { generateId, sha256Raw, toHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { ssoConnections } from "../db/schema.js";
import { createOidcFlow } from "./sso-oidc.js";
import { RateLimiter } from "./sso-rate-limit.js";
import { createSsoRouteHandler } from "./sso-routes.js";
import { buildSamlAuthnRequest, parseSamlResponse } from "./sso-saml.js";
import { encodeState, validateStateToken } from "./sso-state.js";
import type {
	OidcProvider,
	SamlProvider,
	SsoAuditEvent,
	SsoConfig,
	SsoConnection,
	SsoModule,
} from "./sso-types.js";
import { rowToConnection, SSO_ERROR, SsoError } from "./sso-types.js";

export function createSsoModule(config: SsoConfig, db: Database): SsoModule {
	const samlProviders = new Map<string, SamlProvider>((config.saml ?? []).map((p) => [p.id, p]));
	const oidcProviders = new Map<string, OidcProvider>((config.oidc ?? []).map((p) => [p.id, p]));
	const stateTtlSeconds = config.stateTtlSeconds ?? 300;
	const rateLimiter = new RateLimiter(
		config.rateLimitMax ?? 10,
		config.rateLimitWindowSeconds ?? 60,
	);
	const auditLog = config.onAuditEvent ?? (() => {});

	const pruneInterval = setInterval(() => rateLimiter.prune(), 5 * 60 * 1000);
	// Allow the process to exit without waiting for this timer
	if (typeof pruneInterval === "object" && "unref" in pruneInterval) {
		pruneInterval.unref();
	}

	function emitAudit(event: Omit<SsoAuditEvent, "timestamp">): void {
		auditLog({ ...event, timestamp: new Date() });
	}

	async function createConnection(input: {
		orgId: string;
		providerId: string;
		type: "saml" | "oidc";
		domain: string;
	}): Promise<SsoConnection> {
		const id = `sso_${generateId().replace(/-/g, "")}`;
		const now = new Date();

		await db.insert(ssoConnections).values({
			id,
			orgId: input.orgId,
			providerId: input.providerId,
			type: input.type,
			domain: input.domain.toLowerCase(),
			enabled: 1,
			createdAt: now,
		});

		emitAudit({
			type: "sso_connection_created",
			connectionId: id,
			providerId: input.providerId,
			metadata: { orgId: input.orgId, domain: input.domain.toLowerCase() },
		});

		return {
			id,
			orgId: input.orgId,
			providerId: input.providerId,
			type: input.type,
			domain: input.domain.toLowerCase(),
			enabled: true,
			createdAt: now,
		};
	}

	async function getConnectionByDomain(domain: string): Promise<SsoConnection | null> {
		const rows = await db
			.select()
			.from(ssoConnections)
			.where(and(eq(ssoConnections.domain, domain.toLowerCase()), eq(ssoConnections.enabled, 1)));
		const row = rows[0];
		if (!row) return null;
		return rowToConnection(row);
	}

	async function listConnections(orgId: string): Promise<SsoConnection[]> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.orgId, orgId));
		return rows.map(rowToConnection);
	}

	async function removeConnection(connectionId: string): Promise<void> {
		await db.delete(ssoConnections).where(eq(ssoConnections.id, connectionId));
		emitAudit({
			type: "sso_connection_removed",
			connectionId,
		});
	}

	async function getSamlAuthUrl(connectionId: string, relayState?: string): Promise<string> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);
		if (conn.type !== "saml") {
			throw new SsoError(
				SSO_ERROR.CONNECTION_TYPE_MISMATCH,
				`Connection "${connectionId}" is not a SAML connection`,
			);
		}

		const provider = samlProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`SAML provider "${conn.providerId}" not configured`,
			);

		const { encoded } = await buildSamlAuthnRequest(provider);
		const url = new URL(provider.entryPoint);
		url.searchParams.set("SAMLRequest", encoded);
		if (relayState) url.searchParams.set("RelayState", relayState);

		return url.toString();
	}

	async function handleSamlResponse(
		connectionId: string,
		samlResponse: string,
		expectedRequestId?: string,
	): Promise<{ user: { id: string; email: string; name?: string }; orgId: string }> {
		emitAudit({ type: "sso_login_attempt", connectionId, metadata: { protocol: "saml" } });

		if (!rateLimiter.check(`saml:${connectionId}`)) {
			emitAudit({ type: "sso_login_failure", connectionId, error: "Rate limited" });
			throw new SsoError(
				SSO_ERROR.RATE_LIMITED,
				"Too many SSO login attempts. Please try again later.",
			);
		}

		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);

		const provider = samlProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`SAML provider "${conn.providerId}" not configured`,
			);

		try {
			const { email, name } = await parseSamlResponse(samlResponse, provider, expectedRequestId);

			const userIdHash = await sha256Raw(`${conn.providerId}:${email}`);
			const userId = `saml_${toHex(userIdHash).slice(0, 32)}`;

			emitAudit({
				type: "sso_login_success",
				connectionId,
				providerId: conn.providerId,
				email,
			});

			return {
				user: { id: userId, email, name },
				orgId: conn.orgId,
			};
		} catch (err) {
			emitAudit({
				type: "sso_login_failure",
				connectionId,
				providerId: conn.providerId,
				error: err instanceof Error ? err.message : "Unknown error",
			});
			throw err;
		}
	}

	async function generateState(): Promise<string> {
		return encodeState(stateTtlSeconds);
	}

	async function validateState(state: string): Promise<boolean> {
		return validateStateToken(state);
	}

	const { getOidcAuthUrl, handleOidcCallback } = createOidcFlow({
		db,
		oidcProviders,
		rateLimiter,
		emitAudit,
	});
	const handleRequest = createSsoRouteHandler({
		createConnection,
		listConnections,
		removeConnection,
		getSamlAuthUrl,
		handleSamlResponse,
		getOidcAuthUrl,
		handleOidcCallback,
	});

	return {
		createConnection,
		getConnectionByDomain,
		listConnections,
		removeConnection,
		getSamlAuthUrl,
		handleSamlResponse,
		getOidcAuthUrl,
		handleOidcCallback,
		handleRequest,
		generateState,
		validateState,
	};
}

export { verifySamlSignature } from "./sso-saml.js";
export type { XmlNode } from "./sso-types.js";
export {
	checkXxe,
	findAllElements,
	findElement,
	getElementText,
	getSamlAttributeValue,
	parseXml,
	stripXmlComments,
} from "./sso-xml.js";
export type { OidcProvider, SamlProvider, SsoAuditEvent, SsoConfig, SsoConnection, SsoModule };
export { encodeState, SSO_ERROR, SsoError, validateStateToken };
